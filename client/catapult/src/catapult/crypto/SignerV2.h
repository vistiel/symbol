/**
*** Copyright (c) 2016-2019, Jaguar0625, gimre, BloodyRookie, Tech Bureau, Corp.
*** Copyright (c) 2020-present, Jaguar0625, gimre, BloodyRookie.
*** All rights reserved.
***
*** This file is part of Catapult.
***
*** Catapult is free software: you can redistribute it and/or modify
*** it under the terms of the GNU Lesser General Public License as published by
*** the Free Software Foundation, either version 3 of the License, or
*** (at your option) any later version.
***
*** Catapult is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*** GNU Lesser General Public License for more details.
***
*** You should have received a copy of the GNU Lesser General Public License
*** along with Catapult. If not, see <http://www.gnu.org/licenses/>.
**/

#pragma once
#include "CryptoProvider.h"
#include "CryptoProviderRegistry.h"
#include <vector>

namespace catapult { namespace crypto {

	/// V2 signing/verification that works with variable-length keys and signatures
	/// via the CryptoProviderRegistry. Unlike V1 Sign()/Verify() which are hardcoded
	/// to Ed25519 with fixed-size Key (32B) and Signature (64B), these functions
	/// accept CryptoBuffer-based variable-length inputs.
	///
	/// These are the V2 counterparts to V1's Sign()/Verify() in Signer.h.
	/// V1 functions are NOT modified — they continue to work for Ed25519 only.

	/// Signs \a buffers using the private key in \a privateKey and public key in \a publicKey,
	/// using the signature provider for \a scheme from \a registry.
	/// The resulting signature is placed in \a signature (resized to the scheme's signature size).
	inline void SignV2(
			const CryptoProviderRegistry& registry,
			CryptoScheme scheme,
			const SecureCryptoBuffer& privateKey,
			const CryptoBuffer& publicKey,
			const std::vector<RawBuffer>& buffers,
			CryptoBuffer& signature) {
		const auto& provider = registry.signatureProvider(scheme);
		provider.sign(privateKey, publicKey, buffers, signature);
	}

	/// Signs a single \a dataBuffer using the given scheme and keys.
	inline void SignV2(
			const CryptoProviderRegistry& registry,
			CryptoScheme scheme,
			const SecureCryptoBuffer& privateKey,
			const CryptoBuffer& publicKey,
			const RawBuffer& dataBuffer,
			CryptoBuffer& signature) {
		SignV2(registry, scheme, privateKey, publicKey, std::vector<RawBuffer>{ dataBuffer }, signature);
	}

	/// Verifies that \a signature of \a buffers is valid using \a publicKey
	/// for the given \a scheme from \a registry.
	/// Returns \c true if the signature is valid.
	inline bool VerifyV2(
			const CryptoProviderRegistry& registry,
			CryptoScheme scheme,
			const CryptoBuffer& publicKey,
			const std::vector<RawBuffer>& buffers,
			const CryptoBuffer& signature) {
		const auto& provider = registry.signatureProvider(scheme);
		return provider.verify(publicKey, buffers, signature);
	}

	/// Verifies that \a signature of a single \a dataBuffer is valid.
	inline bool VerifyV2(
			const CryptoProviderRegistry& registry,
			CryptoScheme scheme,
			const CryptoBuffer& publicKey,
			const RawBuffer& dataBuffer,
			const CryptoBuffer& signature) {
		return VerifyV2(registry, scheme, publicKey, std::vector<RawBuffer>{ dataBuffer }, signature);
	}

	/// V2 signature input for batch verification support.
	struct SignatureInputV2 {
		/// Cryptographic scheme.
		CryptoScheme Scheme;

		/// Public key (variable-length).
		CryptoBuffer PublicKey;

		/// Buffers to verify.
		std::vector<RawBuffer> Buffers;

		/// Signature (variable-length).
		CryptoBuffer Signature;
	};

	/// Verifies all \a count V2 signature inputs pointed to by \a pInputs
	/// using providers from \a registry.
	/// Returns a pair of (individual results, aggregate result).
	///
	/// NOTE: Unlike V1 VerifyMulti which uses Ed25519 batch verification
	/// (multi-scalar multiplication), V2 verification is done individually
	/// per signature since PQC schemes don't support batch math.
	/// Future optimization: batch Ed25519 inputs separately.
	inline std::pair<std::vector<bool>, bool> VerifyMultiV2(
			const CryptoProviderRegistry& registry,
			const SignatureInputV2* pInputs,
			size_t count) {
		std::vector<bool> results(count);
		bool allValid = true;

		for (size_t i = 0; i < count; ++i) {
			const auto& input = pInputs[i];
			results[i] = VerifyV2(registry, input.Scheme, input.PublicKey, input.Buffers, input.Signature);
			if (!results[i])
				allValid = false;
		}

		return { std::move(results), allValid };
	}

	/// Short-circuit version: stops on first failure.
	inline bool VerifyMultiV2ShortCircuit(
			const CryptoProviderRegistry& registry,
			const SignatureInputV2* pInputs,
			size_t count) {
		for (size_t i = 0; i < count; ++i) {
			const auto& input = pInputs[i];
			if (!VerifyV2(registry, input.Scheme, input.PublicKey, input.Buffers, input.Signature))
				return false;
		}
		return true;
	}

	/// Generates a new key pair for the given \a scheme.
	/// Returns (privateKey, publicKey).
	inline std::pair<SecureCryptoBuffer, CryptoBuffer> GenerateKeyPairV2(
			const CryptoProviderRegistry& registry,
			CryptoScheme scheme) {
		const auto& provider = registry.signatureProvider(scheme);
		SecureCryptoBuffer privateKey;
		provider.generatePrivateKey(privateKey);

		CryptoBuffer publicKey;
		provider.extractPublicKey(privateKey, publicKey);

		return { std::move(privateKey), std::move(publicKey) };
	}
}}
