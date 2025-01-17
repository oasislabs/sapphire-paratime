// SPDX-License-Identifier: Apache-2.0

import { decode as cborDecode, encode as cborEncode } from 'cborg';
import deoxysii from '@oasisprotocol/deoxysii';
import { sha512_256 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { randomBytes } from '@noble/hashes/utils';

import {
  BoxKeyPair,
  boxKeyPairFromSecretKey,
  crypto_box_SECRETKEYBYTES,
  naclScalarMult,
} from './munacl.js';

import { BytesLike, isBytesLike, getBytes, hexlify } from './ethersutils.js';

/**
 * Some Ethereum libraries are picky about hex encoding vs Uint8Array
 *
 * The ethers BytesLike type can be either, if the request came as a hex encoded
 * string we should return hex encoded string, if request came as Uint8Array we
 * should return one.
 *
 * Notably hardhat-ignition doesn't work well with Uint8Array responses
 *
 * @param example Some example data, where we should return the same type
 * @param output Output data
 * @returns Output data, as either hex encoded 0x-prefixed string, or Uint8Array
 */
function asBytesLike(example: BytesLike, output: BytesLike): BytesLike {
  if (!isBytesLike(example) || !isBytesLike(output)) {
    throw new Error('Not byteslike data!');
  }
  if (typeof example === 'string') {
    if (typeof output === 'string') {
      return output;
    }
    return hexlify(output);
  }
  if (typeof output === 'string') {
    return hexlify(output);
  }
  return output;
}

export enum CipherKind {
  X25519DeoxysII = 1,
}

export type InnerEnvelope = {
  body: Uint8Array;
};

export type Envelope = {
  format: CipherKind;
  body: {
    pk: Uint8Array;
    nonce: Uint8Array;
    data: Uint8Array;
    epoch?: number;
  };
};

export type AeadEnvelope = { nonce: Uint8Array; data: Uint8Array };

export type CallResult = {
  ok?: string | Uint8Array | AeadEnvelope;
  fail?: CallFailure;
  unknown?: AeadEnvelope;
};

export type CallFailure = { module: string; code: number; message?: string };

function formatFailure(fail: CallFailure): string {
  if (fail.message) return fail.message;
  return `Call failed in module '${fail.module}' with code '${fail.code}'`;
}

export abstract class Cipher {
  public abstract kind: CipherKind;
  public abstract publicKey: Uint8Array;
  public abstract ephemeralKey: Uint8Array;
  public abstract epoch?: number;

  public abstract encrypt(
    plaintext: Uint8Array,
    nonce?: Uint8Array,
  ): {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
  };

  public abstract decrypt(
    nonce: Uint8Array,
    ciphertext: Uint8Array,
  ): Uint8Array;

  /** Encrypts the plaintext and encodes it for sending. */
  public encryptCall(
    calldata?: BytesLike | null,
    nonce?: Uint8Array,
  ): BytesLike {
    // Txs without data are just balance transfers, and all data in those is public.
    if (calldata === undefined || calldata === null || calldata.length === 0)
      return '';

    if (!isBytesLike(calldata)) {
      throw new Error('Attempted to sign tx having non-byteslike data.');
    }

    const innerEnvelope = cborEncode({ body: getBytes(calldata) });

    let ciphertext: Uint8Array;
    ({ ciphertext, nonce } = this.encrypt(innerEnvelope, nonce));

    const envelope: Envelope = {
      format: this.kind,
      body: {
        pk: this.publicKey,
        nonce,
        data: ciphertext,
        epoch: this.epoch,
      },
    };

    return asBytesLike(calldata, cborEncode(envelope));
  }

  public decryptCall(envelopeBytes: BytesLike): BytesLike {
    const envelope = cborDecode(getBytes(envelopeBytes));
    if (!isEnvelopeFormatOk(envelope)) {
      throw new EnvelopeError('Unexpected non-envelope!');
    }
    const result = this.decrypt(envelope.body.nonce, envelope.body.data);
    const inner = cborDecode(result) as InnerEnvelope;
    return asBytesLike(envelopeBytes, inner.body);
  }

  public encryptResult(
    ok?: Uint8Array,
    innerFail?: string,
    outerFail?: string,
  ): Uint8Array {
    if (ok || innerFail) {
      if ((ok && innerFail) || outerFail) {
        throw new EnvelopeError('Conflicting result envelope', {
          ok,
          innerFail,
          outerFail,
        });
      }

      // Inner envelope is encrypted
      const inner = cborEncode(innerFail ? { fail: innerFail } : { ok });
      const { nonce, ciphertext: data } = this.encrypt(inner);

      // Outer envelope is plaintext
      const envelope = cborEncode({
        ok: { nonce, data } as AeadEnvelope,
      });
      return envelope;
    }
    if (outerFail) {
      // Outer failures are returned in plaintext
      return cborEncode({ fail: outerFail });
    }
    throw new EnvelopeError('Cannot encrypt result with no data or failures!', {
      ok,
      innerFail,
      outerFail,
    });
  }

  /** Decrypts the data contained within a hex-encoded serialized envelope. */
  public decryptResult(callResult: BytesLike): BytesLike {
    const envelope = cborDecode(getBytes(callResult));
    if (envelope.fail) {
      throw new EnvelopeError(formatFailure(envelope.fail), envelope.fail);
    }

    // Unencrypted results will have `ok` as bytes, not a struct
    if (
      envelope.ok &&
      (typeof envelope.ok === 'string' || envelope.ok instanceof Uint8Array)
    ) {
      throw new EnvelopeError('Received unencrypted envelope', envelope);
    }

    // Encrypted result will have `ok` as a CBOR encoded struct
    const { nonce, data } = (envelope.ok as AeadEnvelope) ?? envelope.unknown;
    const inner = cborDecode(this.decrypt(nonce, data));

    if (inner.ok) {
      return asBytesLike(callResult, getBytes(inner.ok));
    }

    if (inner.fail) {
      throw new EnvelopeError(formatFailure(inner.fail), inner.fail);
    }

    throw new EnvelopeError(
      `Unexpected inner call result: ${JSON.stringify(inner)}`,
      inner,
    );
  }
}

/**
 * A {@link Cipher} that derives a shared secret using X25519 and then uses DeoxysII for encrypting using that secret.
 *
 * This is the default cipher.
 */
export class X25519DeoxysII extends Cipher {
  public override readonly kind = CipherKind.X25519DeoxysII;
  public override readonly publicKey: Uint8Array;
  public override readonly ephemeralKey: Uint8Array;
  public override readonly epoch: number | undefined;

  private cipher: deoxysii.AEAD;
  public secretKey: Uint8Array; // Stored for curious users.

  /** Creates a new cipher using an ephemeral keypair stored in memory. */
  static ephemeral(peerPublicKey: BytesLike, epoch?: number): X25519DeoxysII {
    const keypair = boxKeyPairFromSecretKey(
      randomBytes(crypto_box_SECRETKEYBYTES),
    );
    return new X25519DeoxysII(keypair, getBytes(peerPublicKey), epoch);
  }

  static fromSecretKey(
    secretKey: BytesLike,
    peerPublicKey: BytesLike,
    epoch?: number,
  ): X25519DeoxysII {
    const keypair = boxKeyPairFromSecretKey(getBytes(secretKey));
    return new X25519DeoxysII(keypair, getBytes(peerPublicKey), epoch);
  }

  public constructor(
    keypair: BoxKeyPair,
    peerPublicKey: Uint8Array,
    epoch?: number,
  ) {
    super();

    this.publicKey = keypair.publicKey;
    this.ephemeralKey = keypair.secretKey;
    this.epoch = epoch;

    // Derive a shared secret using X25519 (followed by hashing to remove ECDH bias).
    const keyBytes = hmac
      .create(
        sha512_256,
        new TextEncoder().encode('MRAE_Box_Deoxys-II-256-128'),
      )
      .update(naclScalarMult(keypair.secretKey, peerPublicKey))
      .digest().buffer;

    this.secretKey = new Uint8Array(keyBytes);
    this.cipher = new deoxysii.AEAD(new Uint8Array(this.secretKey)); // deoxysii owns the input
  }

  public encrypt(
    plaintext: Uint8Array,
    nonce: Uint8Array = randomBytes(deoxysii.NonceSize),
  ): {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
  } {
    const ciphertext = this.cipher.encrypt(nonce, plaintext);
    return { nonce, ciphertext };
  }

  public decrypt(nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    return this.cipher.decrypt(nonce, ciphertext);
  }
}

// -----------------------------------------------------------------------------
// Determine if the CBOR encoded calldata is a signed query or an evelope

export class EnvelopeError extends Error {
  public constructor(message: string, public readonly response?: unknown) {
    super(message);
  }
}

function isEnvelopeFormatOk(envelope: any): envelope is Envelope {
  const { format, body } = envelope;

  if (!body || !format) {
    throw new EnvelopeError('No body or format specified', envelope);
  }

  if (format !== CipherKind.X25519DeoxysII) {
    throw new EnvelopeError('Not encrypted format', envelope);
  }

  if (isBytesLike(body))
    throw new EnvelopeError('Requires struct body', envelope);

  if (!isBytesLike(body.data))
    throw new EnvelopeError('No body data', envelope);

  return true;
}

export function isCalldataEnveloped(calldata?: BytesLike): boolean {
  if (calldata === undefined) {
    return false;
  }
  try {
    const envelope = cborDecode(getBytes(calldata));

    if (!isEnvelopeFormatOk(envelope)) {
      throw new EnvelopeError(
        'Bogus Sapphire enveloped data found in transaction!',
      );
    }
    return true;
  } catch (e: any) {
    if (e instanceof EnvelopeError) throw e;
  }
  return false;
}
