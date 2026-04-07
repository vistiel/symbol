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

	/// Ed25519 signature provider — wraps existing donna-based implementation behind CryptoProvider interface.
	class Ed25519SignatureProvider final : public SignatureProvider {
	public:
		/// Ed25519 key and signature sizes.
		static constexpr size_t Public_Key_Size = 32;
		static constexpr size_t Private_Key_Size = 32;
		static constexpr size_t Signature_Size = 64;

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
	};
}}
