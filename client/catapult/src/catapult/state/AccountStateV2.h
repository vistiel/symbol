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
#include "AccountState.h"
#include "catapult/crypto/CryptoProvider.h"
#include <optional>

namespace catapult { namespace state {

	/// V2 extension fields for AccountState to support variable-length public keys.
	///
	/// Design decisions:
	/// 1. We do NOT modify the existing AccountState struct — V1 code continues to use
	///    `accountState.PublicKey` (32B) for Ed25519 accounts unchanged.
	/// 2. For PQC accounts (ML-DSA-65, future schemes), the V2 extension stores the
	///    full variable-length public key and crypto scheme.
	/// 3. The V2 extension is stored as an optional companion alongside AccountState
	///    in the cache — only PQC accounts have this overhead.
	///
	/// Relationship to V1 AccountState.PublicKey:
	/// - Ed25519 accounts: PublicKey contains the full 32B key. No V2 extension needed.
	/// - ML-DSA-65 accounts: PublicKey contains SHA3-256(fullKey)[0..31] as a lookup hash.
	///   The V2 extension stores the full 1952B key and CryptoScheme.
	///
	/// This approach means:
	/// - The secondary Key→Address lookup table still works (32B Key hash as lookup key)
	/// - Patricia tree and cache serialization are backward-compatible for Ed25519
	/// - PQC accounts have additional storage for the full public key

	struct AccountStateV2Extension {
	public:
		/// Creates a V2 extension with the given \a cryptoScheme and \a fullPublicKey.
		AccountStateV2Extension(crypto::CryptoScheme cryptoScheme, const crypto::CryptoBuffer& fullPublicKey)
				: CryptoScheme(cryptoScheme)
				, FullPublicKey(fullPublicKey)
		{}

		/// Creates a V2 extension with the given \a cryptoScheme and key data.
		AccountStateV2Extension(crypto::CryptoScheme cryptoScheme, const uint8_t* pKeyData, size_t keySize)
				: CryptoScheme(cryptoScheme)
				, FullPublicKey(pKeyData, keySize)
		{}

	public:
		/// Cryptographic scheme used by this account.
		crypto::CryptoScheme CryptoScheme;

		/// Full public key (variable-length).
		/// For Ed25519 (32B), this is the same as AccountState::PublicKey.
		/// For ML-DSA-65 (1952B), this is the full FIPS 204 public key.
		crypto::CryptoBuffer FullPublicKey;
	};

	/// Returns \c true if the account uses PQC (non-Ed25519) cryptography.
	inline bool IsPqcAccount(const AccountStateV2Extension& ext) {
		return crypto::CryptoScheme::Ed25519 != ext.CryptoScheme;
	}

	/// Computes the 32-byte lookup key (for cache secondary index) from a variable-length public key.
	/// For Ed25519 keys (32B), returns the key directly.
	/// For larger keys, returns SHA3-256(key).
	Key ComputePublicKeyHash(const crypto::CryptoBuffer& fullPublicKey, crypto::CryptoScheme scheme);

	/// V2 account state serialization format version.
	constexpr uint16_t AccountState_V2_Format_Version = 2;

	/// Serializes a V2 extension to a byte buffer.
	/// Format: [CryptoScheme(1)] [KeySize(4)] [FullPublicKey(KeySize)]
	inline std::vector<uint8_t> SerializeV2Extension(const AccountStateV2Extension& ext) {
		std::vector<uint8_t> buffer(1 + 4 + ext.FullPublicKey.size());
		buffer[0] = static_cast<uint8_t>(ext.CryptoScheme);
		auto keySize = static_cast<uint32_t>(ext.FullPublicKey.size());
		std::memcpy(buffer.data() + 1, &keySize, 4);
		std::memcpy(buffer.data() + 5, ext.FullPublicKey.data(), ext.FullPublicKey.size());
		return buffer;
	}

	/// Deserializes a V2 extension from a byte buffer.
	/// Returns nullopt if the buffer is too small or malformed.
	inline std::optional<AccountStateV2Extension> DeserializeV2Extension(const uint8_t* pData, size_t dataSize) {
		if (dataSize < 5)
			return std::nullopt;

		auto scheme = static_cast<crypto::CryptoScheme>(pData[0]);
		uint32_t keySize = 0;
		std::memcpy(&keySize, pData + 1, 4);

		if (dataSize < 5 + keySize)
			return std::nullopt;

		// Sanity check: reject unreasonably large keys (>64KB)
		if (keySize > 65536)
			return std::nullopt;

		return AccountStateV2Extension(scheme, pData + 5, keySize);
	}
}}
