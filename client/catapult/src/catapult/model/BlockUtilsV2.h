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
#include "EntityHeaderV2.h"
#include "EntityHasherV2.h"
#include "catapult/crypto/SignerV2.h"

namespace catapult { namespace model {

	/// V2 block signing/verification utilities that work with variable-length
	/// signatures and keys via the CryptoProviderRegistry.
	///
	/// These are the V2 counterparts to SignBlockHeader()/VerifyBlockHeaderSignature()
	/// in BlockUtils.h. V1 functions are NOT modified.
	namespace BlockUtilsV2 {

		/// Signs a V2 block buffer using the given scheme and keys.
		///
		/// \a pBlockBuffer points to a complete V2 block serialized via EntityHeaderV2Writer.
		/// \a blockSize is the total size of the buffer.
		/// \a footerSize is the size of the block footer to exclude from signing.
		/// The computed signature is written back into the buffer at the Signature offset.
		inline void SignBlockHeader(
				const crypto::CryptoProviderRegistry& registry,
				crypto::CryptoScheme scheme,
				const crypto::SecureCryptoBuffer& privateKey,
				const crypto::CryptoBuffer& publicKey,
				uint8_t* pBlockBuffer,
				size_t blockSize,
				size_t footerSize) {
			EntityHeaderV2Reader reader(pBlockBuffer, blockSize);
			auto hdrSize = reader.headerSize();

			// Data to sign = everything after Header_Size, excluding footer
			if (blockSize <= hdrSize + footerSize)
				throw std::invalid_argument("block buffer too small for signing");

			RawBuffer dataBuffer = { pBlockBuffer + hdrSize, blockSize - hdrSize - footerSize };

			crypto::CryptoBuffer signature;
			crypto::SignV2(registry, scheme, privateKey, publicKey, dataBuffer, signature);

			// Write signature back into the buffer
			auto sigOffset = EntityHeaderV2Layout::SignatureOffset();
			if (signature.size() != reader.fieldSizes().signatureSize)
				throw std::runtime_error("signature size mismatch after signing");

			std::memcpy(pBlockBuffer + sigOffset, signature.data(), signature.size());
		}

		/// Verifies the signature of a V2 block buffer.
		///
		/// \a footerSize is the size of the block footer to exclude from verification.
		/// Returns \c true if the signature is valid.
		inline bool VerifyBlockHeaderSignature(
				const crypto::CryptoProviderRegistry& registry,
				const uint8_t* pBlockBuffer,
				size_t blockSize,
				size_t footerSize) {
			EntityHeaderV2Reader reader(pBlockBuffer, blockSize);
			auto hdrSize = reader.headerSize();

			if (blockSize <= hdrSize + footerSize)
				return false;

			RawBuffer dataBuffer = { pBlockBuffer + hdrSize, blockSize - hdrSize - footerSize };

			auto sigBuf = reader.signature();
			auto keyBuf = reader.signerPublicKey();

			crypto::CryptoBuffer publicKey(keyBuf.pData, keyBuf.Size);
			crypto::CryptoBuffer signature(sigBuf.pData, sigBuf.Size);

			return crypto::VerifyV2(registry, reader.cryptoScheme(), publicKey, dataBuffer, signature);
		}

		/// Signs a V2 transaction buffer using the given scheme and keys.
		///
		/// The computed signature is written back into the buffer.
		inline void SignTransaction(
				const crypto::CryptoProviderRegistry& registry,
				crypto::CryptoScheme scheme,
				const crypto::SecureCryptoBuffer& privateKey,
				const crypto::CryptoBuffer& publicKey,
				uint8_t* pTxBuffer,
				size_t txSize) {
			EntityHeaderV2Reader reader(pTxBuffer, txSize);
			auto dataBuffer = reader.dataBuffer();

			crypto::CryptoBuffer signature;
			crypto::SignV2(registry, scheme, privateKey, publicKey, dataBuffer, signature);

			auto sigOffset = EntityHeaderV2Layout::SignatureOffset();
			std::memcpy(pTxBuffer + sigOffset, signature.data(), signature.size());
		}

		/// Verifies the signature of a V2 transaction buffer.
		/// Returns \c true if the signature is valid.
		inline bool VerifyTransactionSignature(
				const crypto::CryptoProviderRegistry& registry,
				const uint8_t* pTxBuffer,
				size_t txSize) {
			EntityHeaderV2Reader reader(pTxBuffer, txSize);

			auto sigBuf = reader.signature();
			auto keyBuf = reader.signerPublicKey();
			auto dataBuffer = reader.dataBuffer();

			crypto::CryptoBuffer publicKey(keyBuf.pData, keyBuf.Size);
			crypto::CryptoBuffer signature(sigBuf.pData, sigBuf.Size);

			return crypto::VerifyV2(registry, reader.cryptoScheme(), publicKey, dataBuffer, signature);
		}

		/// Signs a V2 transaction buffer with replay protection
		/// (GenerationHashSeed prepended to the data).
		inline void SignTransactionWithReplayProtection(
				const crypto::CryptoProviderRegistry& registry,
				crypto::CryptoScheme scheme,
				const crypto::SecureCryptoBuffer& privateKey,
				const crypto::CryptoBuffer& publicKey,
				const GenerationHashSeed& generationHashSeed,
				uint8_t* pTxBuffer,
				size_t txSize) {
			EntityHeaderV2Reader reader(pTxBuffer, txSize);
			auto dataBuffer = reader.dataBuffer();

			std::vector<RawBuffer> buffers;
			buffers.push_back(generationHashSeed);
			if (dataBuffer.Size > 0)
				buffers.push_back(dataBuffer);

			crypto::CryptoBuffer signature;
			crypto::SignV2(registry, scheme, privateKey, publicKey, buffers, signature);

			auto sigOffset = EntityHeaderV2Layout::SignatureOffset();
			std::memcpy(pTxBuffer + sigOffset, signature.data(), signature.size());
		}

		/// Verifies a V2 transaction signature with replay protection.
		inline bool VerifyTransactionSignatureWithReplayProtection(
				const crypto::CryptoProviderRegistry& registry,
				const uint8_t* pTxBuffer,
				size_t txSize,
				const GenerationHashSeed& generationHashSeed) {
			EntityHeaderV2Reader reader(pTxBuffer, txSize);

			auto sigBuf = reader.signature();
			auto keyBuf = reader.signerPublicKey();
			auto dataBuffer = reader.dataBuffer();

			crypto::CryptoBuffer publicKey(keyBuf.pData, keyBuf.Size);
			crypto::CryptoBuffer signature(sigBuf.pData, sigBuf.Size);

			std::vector<RawBuffer> buffers;
			buffers.push_back(generationHashSeed);
			if (dataBuffer.Size > 0)
				buffers.push_back(dataBuffer);

			return crypto::VerifyV2(registry, reader.cryptoScheme(), publicKey, buffers, signature);
		}
	}
}}
