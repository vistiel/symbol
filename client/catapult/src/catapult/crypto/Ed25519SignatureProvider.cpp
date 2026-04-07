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

#include "Ed25519SignatureProvider.h"
#include "KeyPair.h"
#include "Signer.h"
#include "catapult/exceptions.h"
#include <numeric>
#include <random>

namespace catapult { namespace crypto {

	namespace {
		const std::string Scheme_Name = "Ed25519";
	}

	CryptoScheme Ed25519SignatureProvider::scheme() const {
		return CryptoScheme::Ed25519;
	}

	const std::string& Ed25519SignatureProvider::name() const {
		return Scheme_Name;
	}

	size_t Ed25519SignatureProvider::publicKeySize() const {
		return Public_Key_Size;
	}

	size_t Ed25519SignatureProvider::privateKeySize() const {
		return Private_Key_Size;
	}

	size_t Ed25519SignatureProvider::signatureSize() const {
		return Signature_Size;
	}

	void Ed25519SignatureProvider::extractPublicKey(const SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const {
		if (Private_Key_Size != privateKey.size())
			CATAPULT_THROW_INVALID_ARGUMENT_1("invalid private key size for Ed25519", privateKey.size());

		// Bridge to existing PrivateKey/KeyPair types
		auto existingPrivateKey = PrivateKey::FromBuffer(RawBuffer{ privateKey.data(), privateKey.size() });
		auto keyPair = KeyPair::FromPrivate(std::move(existingPrivateKey));

		publicKey = CryptoBuffer(keyPair.publicKey().data(), Public_Key_Size);
	}

	void Ed25519SignatureProvider::sign(
			const SecureCryptoBuffer& privateKey,
			const CryptoBuffer& publicKey,
			const std::vector<RawBuffer>& buffers,
			CryptoBuffer& signature) const {
		if (Private_Key_Size != privateKey.size())
			CATAPULT_THROW_INVALID_ARGUMENT_1("invalid private key size for Ed25519 sign", privateKey.size());

		if (Public_Key_Size != publicKey.size())
			CATAPULT_THROW_INVALID_ARGUMENT_1("invalid public key size for Ed25519 sign", publicKey.size());

		// Bridge to existing KeyPair
		auto existingPrivateKey = PrivateKey::FromBuffer(RawBuffer{ privateKey.data(), privateKey.size() });
		auto keyPair = KeyPair::FromPrivate(std::move(existingPrivateKey));

		// Call existing signer — bridge vector to single-buffer sign
		// Note: The existing Sign() accepts initializer_list<const RawBuffer>, not vector.
		// For the bridge, we concatenate and use the single-buffer overload.
		auto totalSize = std::accumulate(buffers.begin(), buffers.end(), size_t(0),
				[](size_t sum, const auto& buf) { return sum + buf.Size; });
		std::vector<uint8_t> concatenated(totalSize);
		size_t offset = 0;
		for (const auto& buffer : buffers) {
			if (buffer.Size > 0) {
				std::memcpy(concatenated.data() + offset, buffer.pData, buffer.Size);
				offset += buffer.Size;
			}
		}

		catapult::Signature existingSignature;
		crypto::Sign(keyPair, RawBuffer{ concatenated.data(), concatenated.size() }, existingSignature);

		signature = CryptoBuffer(existingSignature.data(), Signature_Size);
	}

	bool Ed25519SignatureProvider::verify(
			const CryptoBuffer& publicKey,
			const std::vector<RawBuffer>& buffers,
			const CryptoBuffer& signature) const {
		if (Public_Key_Size != publicKey.size())
			return false;

		if (Signature_Size != signature.size())
			return false;

		// Bridge to existing Key/Signature types
		Key existingKey;
		std::memcpy(existingKey.data(), publicKey.data(), Public_Key_Size);

		catapult::Signature existingSignature;
		std::memcpy(existingSignature.data(), signature.data(), Signature_Size);

		return crypto::Verify(existingKey, buffers, existingSignature);
	}

	void Ed25519SignatureProvider::generatePrivateKey(SecureCryptoBuffer& privateKey) const {
		privateKey = SecureCryptoBuffer(Private_Key_Size);

		std::random_device rd;
		auto* pData = privateKey.data();
		for (size_t i = 0; i < Private_Key_Size; ++i)
			pData[i] = static_cast<uint8_t>(rd());
	}
}}
