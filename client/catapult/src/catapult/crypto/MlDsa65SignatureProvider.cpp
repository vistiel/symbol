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

#include "MlDsa65SignatureProvider.h"
#include "SecureZero.h"
#include "catapult/exceptions.h"
#include <oqs/oqs.h>
#include <numeric>

namespace catapult { namespace crypto {

	namespace {
		const std::string Scheme_Name = "ML-DSA-65";

		std::vector<uint8_t> ConcatenateBuffers(const std::vector<RawBuffer>& buffers) {
			auto totalSize = std::accumulate(buffers.begin(), buffers.end(), size_t(0),
					[](size_t sum, const auto& buf) { return sum + buf.Size; });

			std::vector<uint8_t> result(totalSize);
			size_t offset = 0;
			for (const auto& buffer : buffers) {
				if (buffer.Size > 0) {
					std::memcpy(result.data() + offset, buffer.pData, buffer.Size);
					offset += buffer.Size;
				}
			}
			return result;
		}
	}

	CryptoScheme MlDsa65SignatureProvider::scheme() const {
		return CryptoScheme::Ml_Dsa_65;
	}

	const std::string& MlDsa65SignatureProvider::name() const {
		return Scheme_Name;
	}

	size_t MlDsa65SignatureProvider::publicKeySize() const {
		return Public_Key_Size;
	}

	size_t MlDsa65SignatureProvider::privateKeySize() const {
		return Private_Key_Size;
	}

	size_t MlDsa65SignatureProvider::signatureSize() const {
		return Signature_Size;
	}

	void MlDsa65SignatureProvider::extractPublicKey(const SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const {
		// ML-DSA does not support cheap public key extraction from private key.
		// The public key is embedded in the latter portion of the private key in the liboqs representation.
		// For now, we extract it from the stored key pair (the public key is the last 1952 bytes of the secret key).
		if (Private_Key_Size != privateKey.size())
			CATAPULT_THROW_INVALID_ARGUMENT_1("invalid private key size for ML-DSA-65", privateKey.size());

		// In liboqs ML-DSA-65 secret key format, the public key is stored at the end
		publicKey = CryptoBuffer(privateKey.data() + Private_Key_Size - Public_Key_Size, Public_Key_Size);
	}

	void MlDsa65SignatureProvider::sign(
			const SecureCryptoBuffer& privateKey,
			const CryptoBuffer& publicKey,
			const std::vector<RawBuffer>& buffers,
			CryptoBuffer& signature) const {
		if (Private_Key_Size != privateKey.size())
			CATAPULT_THROW_INVALID_ARGUMENT_1("invalid private key size for ML-DSA-65 sign", privateKey.size());

		// ML-DSA signs a single message, so concatenate all buffers
		auto message = ConcatenateBuffers(buffers);

		signature.resize(Signature_Size);
		size_t signatureLen = 0;

		auto result = OQS_SIG_ml_dsa_65_sign(
				signature.data(),
				&signatureLen,
				message.data(),
				message.size(),
				privateKey.data());

		if (OQS_SUCCESS != result)
			CATAPULT_THROW_RUNTIME_ERROR("ML-DSA-65 signing failed");

		// Update signature size (ML-DSA signatures may be slightly variable)
		signature.resize(signatureLen);
	}

	bool MlDsa65SignatureProvider::verify(
			const CryptoBuffer& publicKey,
			const std::vector<RawBuffer>& buffers,
			const CryptoBuffer& signature) const {
		if (Public_Key_Size != publicKey.size())
			return false;

		if (signature.empty() || signature.size() > Signature_Size)
			return false;

		auto message = ConcatenateBuffers(buffers);

		auto result = OQS_SIG_ml_dsa_65_verify(
				message.data(),
				message.size(),
				signature.data(),
				signature.size(),
				publicKey.data());

		return OQS_SUCCESS == result;
	}

	void MlDsa65SignatureProvider::generatePrivateKey(SecureCryptoBuffer& privateKey) const {
		// For ML-DSA, we must generate a full key pair
		CryptoBuffer publicKey;
		generateKeyPair(privateKey, publicKey);
	}

	void MlDsa65SignatureProvider::generateKeyPair(SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const {
		publicKey = CryptoBuffer(Public_Key_Size);
		privateKey = SecureCryptoBuffer(Private_Key_Size);

		auto result = OQS_SIG_ml_dsa_65_keypair(publicKey.data(), privateKey.data());
		if (OQS_SUCCESS != result) {
			SecureZero(privateKey.data(), privateKey.size());
			CATAPULT_THROW_RUNTIME_ERROR("ML-DSA-65 key pair generation failed");
		}
	}
}}
