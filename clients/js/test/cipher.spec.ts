// SPDX-License-Identifier: Apache-2.0

import nacl from 'tweetnacl';
import { hexlify, getBytes } from 'ethers';
import {
  isCalldataEnveloped,
  X25519DeoxysII,
} from '@oasisprotocol/sapphire-paratime';

describe('X25519DeoxysII', () => {
  it('key derivation', () => {
    // These test vectors are taken from `ts-web`.
    const secretKey = getBytes(
      '0xc07b151fbc1e7a11dff926111188f8d872f62eba0396da97c0a24adb75161750',
    );
    const keypair = nacl.box.keyPair.fromSecretKey(secretKey);
    const cipher = new X25519DeoxysII(keypair, keypair.publicKey);
    expect(hexlify(cipher.publicKey)).toEqual(
      '0x3046db3fa70ce605457dc47c48837ebd8bd0a26abfde5994d033e1ced68e2576',
    );
    expect(hexlify(cipher['secretKey'])).toEqual(
      '0xe69ac21066a8c2284e8fdc690e579af4513547b9b31dd144792c1904b45cf586',
    );

    const alsoCipher = X25519DeoxysII.fromSecretKey(
      secretKey,
      keypair.publicKey,
    );
    expect(alsoCipher.publicKey).toEqual(cipher.publicKey);
  });

  it('envelope roundtrip call', () => {
    const cipher = X25519DeoxysII.ephemeral(nacl.box.keyPair().publicKey);
    for (let i = 1; i < 512; i += 30) {
      const expected = nacl.randomBytes(i);
      const encrypted = cipher.encryptCall(expected);
      expect(isCalldataEnveloped(encrypted)).toStrictEqual(true);
      const decoded = cipher.decryptCall(encrypted);
      expect(hexlify(decoded)).toEqual(hexlify(expected));
    }
  });

  it('envelope roundtrip result', () => {
    const cipher = X25519DeoxysII.ephemeral(nacl.box.keyPair().publicKey);
    for (let i = 1; i < 512; i += 30) {
      const ok = nacl.randomBytes(i);
      const encrypted = cipher.encryptResult(ok);
      const decrypted = cipher.decryptResult(encrypted);
      expect(hexlify(decrypted)).toEqual(hexlify(ok));
    }
  });
});
