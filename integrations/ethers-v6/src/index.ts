// SPDX-License-Identifier: Apache-2.0

import type {
	ContractRunner,
	EthersError,
	Provider,
	Signer,
	TransactionLike,
	TransactionRequest,
} from "ethers";

import { AbstractSigner, type JsonRpcApiProvider, hexlify } from "ethers";

import type {
	Cipher,
	EIP1193_RequestArguments,
	EIP1193_RequestFn,
	EIP2696_EthereumProvider,
	SapphireWrapConfig,
	SapphireWrapOptions,
} from "@oasisprotocol/sapphire-paratime";

import {
	detectSapphireSnap,
	fillOptions,
	isCalldataEnveloped,
	makeTaggedProxyObject,
	notifySapphireSnap,
} from "@oasisprotocol/sapphire-paratime";

export { NETWORKS } from "@oasisprotocol/sapphire-paratime";

// ----------------------------------------------------------------------------

function isEthersJsonRpcApiProvider(
	p: ContractRunner,
): p is JsonRpcApiProvider {
	return "send" in p && typeof p.send === "function";
}

function hasRequestFunction(
	p: ContractRunner | EIP2696_EthereumProvider,
): p is EIP2696_EthereumProvider {
	return "request" in p && typeof p.request === "function";
}

/// Get a JsonRpcApiProvider compatible provider from a ContractRunner
function getProviderFromContractRunner(
	r: ContractRunner,
): JsonRpcApiProvider | undefined {
	if (isEthersJsonRpcApiProvider(r)) {
		return r;
	}
	if (r.provider && isEthersJsonRpcApiProvider(r.provider)) {
		return r.provider;
	}
	return;
}

/**
 * Get a EIP-1193 compatible request() function from a ContractRunner
 * @param r Runner or other compatible provider
 * @returns `undefined` if there is no attached provider
 */
function makeEthereumRequestFnFromProvider(
	r: ContractRunner,
): EIP1193_RequestFn | undefined {
	if (hasRequestFunction(r)) {
		return r.request;
	}

	const p = getProviderFromContractRunner(r);
	if (!p) return;

	return async (request: EIP1193_RequestArguments): Promise<unknown> => {
		const { method, params } = request;
		return p.send(method, params ?? []);
	};
}

// ----------------------------------------------------------------------------

const SAPPHIRE_WRAPPED_ETHERS_SIGNER = "#SAPPHIRE_WRAPPED_ETHERS_SIGNER";

function isWrappedSigner<P extends Signer>(
	p: P,
): p is P & EIP2696_EthereumProvider {
	return SAPPHIRE_WRAPPED_ETHERS_SIGNER in p;
}

export class SignerHasNoProviderError extends Error {}

function hookEthersSend<
	C extends Signer["sendTransaction"] | Signer["signTransaction"],
>(
	send: C,
	options: SapphireWrapOptions,
	request: EIP1193_RequestFn,
	provider: EIP2696_EthereumProvider | undefined,
): C {
	return (async (tx: TransactionRequest) => {
		if (tx.data) {
			const cipher = await options.fetcher.cipher({ request });
			tx.data = hexlify(cipher.encryptCall(tx.data));
			if (provider) {
				const snapId = options.enableSapphireSnap
					? await detectSapphireSnap(provider)
					: undefined;

				if (snapId !== undefined && tx.data !== undefined) {
					notifySapphireSnap(snapId, cipher, tx.data, options, provider);
				}
			}
		}
		return send(tx);
	}) as C;
}

export function wrapEthersSigner<P extends Signer>(
	upstream: P,
	options?: SapphireWrapConfig,
): P & EIP2696_EthereumProvider {
	if (isWrappedSigner(upstream)) {
		return upstream;
	}

	const filled_options = fillOptions(options);

	let signer: Signer;
	let provider: (Provider & EIP2696_EthereumProvider) | undefined;
	if (upstream.provider) {
		provider = wrapEthersProvider(upstream.provider, filled_options);
		try {
			signer = upstream.connect(provider);
		} catch (e: unknown) {
			if ((e as EthersError).code !== "UNSUPPORTED_OPERATION") throw e;
			signer = upstream;
		}
	} else {
		signer = upstream;
	}

	// The signer must have been connected to a provider
	const request = makeEthereumRequestFnFromProvider(signer);
	if (!request) {
		throw new SignerHasNoProviderError(
			"Signer must be connected to a provider!",
		);
	}

	return makeTaggedProxyObject(
		signer,
		SAPPHIRE_WRAPPED_ETHERS_SIGNER,
		filled_options,
		{
			sendTransaction: hookEthersSend(
				signer.sendTransaction.bind(signer),
				filled_options,
				request,
				provider,
			),
			signTransaction: hookEthersSend(
				signer.signTransaction.bind(signer),
				filled_options,
				request,
				provider,
			),
			call: hookEthersCall(signer, "call", filled_options, request),
			estimateGas: hookEthersCall(
				signer,
				"estimateGas",
				filled_options,
				request,
			),
			connect(provider: Provider) {
				const wp = signer.connect(provider);
				return wrapEthersSigner(wp, filled_options);
			},
			request,
		},
	) as P & EIP2696_EthereumProvider;
}

// ----------------------------------------------------------------------------

const SAPPHIRE_WRAPPED_ETHERS_PROVIDER = "#SAPPHIRE_WRAPPED_ETHERS_PROVIDER";

function isWrappedProvider<P extends Provider>(
	p: P,
): p is P & EIP2696_EthereumProvider {
	return SAPPHIRE_WRAPPED_ETHERS_PROVIDER in p;
}

export class ContractRunnerHasNoProviderError extends Error {}

export function wrapEthersProvider<P extends Provider>(
	provider: P,
	options?: SapphireWrapConfig,
): P & EIP2696_EthereumProvider {
	// Already wrapped, so don't wrap it again.
	if (isWrappedProvider(provider)) {
		return provider;
	}

	const request = makeEthereumRequestFnFromProvider(provider);
	if (!request) {
		throw new Error("Couldn't make request function!");
	}

	const filled_options = fillOptions(options);

	return makeTaggedProxyObject(
		provider,
		SAPPHIRE_WRAPPED_ETHERS_PROVIDER,
		filled_options,
		{
			// Calls can be unsigned, but must be enveloped.
			call: hookEthersCall(provider, "call", filled_options, request),
			estimateGas: hookEthersCall(
				provider,
				"estimateGas",
				filled_options,
				request,
			),
			request,
			// TODO: wrap `getSigner()`
		},
	) as P & EIP2696_EthereumProvider;
}

function isEthersSigner(upstream: object): upstream is Signer {
	return upstream instanceof AbstractSigner;
}

async function sendUnsignedCall(
	fn: ContractRunner["call"] | ContractRunner["estimateGas"],
	call: TransactionRequest,
	is_already_enveloped: boolean,
	cipher: Cipher,
) {
	let call_data = call.data ?? undefined;
	if (!is_already_enveloped) {
		call_data = hexlify(cipher.encryptCall(call.data));
	}
	return await fn?.({
		...call,
		data: call_data ? hexlify(call_data) : "0x",
	});
}

function hookEthersCall(
	runner: ContractRunner,
	method: "call" | "estimateGas",
	options: SapphireWrapOptions,
	request: EIP1193_RequestFn,
) {
	return async (call: TransactionLike<string>) => {
		const cipher = await options.fetcher.cipher({ request });

		// If the calldata is already enveloped, don't wrap it in another envelope
		const is_already_enveloped = isCalldataEnveloped(call.data ?? undefined);

		const f = runner[method];
		if (!f) {
			throw new Error(`${method} not found in runner!`);
		}

		const res = await sendUnsignedCall(
			f.bind(runner),
			isEthersSigner(runner) ? await runner.populateCall(call) : call,
			is_already_enveloped,
			cipher,
		);

		// NOTE: if it's already enveloped, caller will decrypt it (not us)
		if (!is_already_enveloped && res && typeof res === "string") {
			return cipher.decryptResult(res);
		}
		return res;
	};
}
