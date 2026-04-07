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

namespace catapult { namespace crypto {

	/// ML-DSA-65 (Dilithium3) signature provider using liboqs.
	/// This is a NIST FIPS 204 post-quantum digital signature scheme.
	class MlDsa65SignatureProvider final : public SignatureProvider {
	public:
		/// ML-DSA-65 key and signature sizes (from FIPS 204).
		static constexpr size_t Public_Key_Size = 1952;
		static constexpr size_t Oqs_Secret_Key_Size = 4032;
		/// Private key stores sk(4032) || pk(1952) — mirrors libsodium Ed25519 convention.
		/// This allows extractPublicKey to retrieve the embedded public key.
		static constexpr size_t Private_Key_Size = Oqs_Secret_Key_Size + Public_Key_Size;
		static constexpr size_t Signature_Size = 3309;

	public:
		CryptoScheme scheme() const override;
		const std::string& name() const override;
		size_t publicKeySize() const override;
		size_t privateKeySize() const override;
		size_t signatureSize() const override;

	public:
		void extractPublicKey(const SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const override;

		void sign(
				const SecureCryptoBuffer& privateKey,
				const CryptoBuffer& publicKey,
				const std::vector<RawBuffer>& buffers,
				CryptoBuffer& signature) const override;

		bool verify(
				const CryptoBuffer& publicKey,
				const std::vector<RawBuffer>& buffers,
				const CryptoBuffer& signature) const override;

		void generatePrivateKey(SecureCryptoBuffer& privateKey) const override;

	public:
		/// Generates a new ML-DSA-65 key pair (both private and public).
		/// \note Unlike Ed25519, the public key cannot be cheaply derived from the private key,
		///       so key generation produces both at once.
		void generateKeyPair(SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const;
	};
}}
