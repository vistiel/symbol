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
#include "VerifiableEntity.h"
#include "EmbeddedTransaction.h"
#include "Cosignature.h"
#include <vector>

namespace catapult { namespace model {

	/// Utilities for serializing and converting between V1 and V2 entity formats.
	namespace EntitySerializerV2 {

		// region V1 → V2 conversion

		/// Converts a V1 VerifiableEntity to V2 wire format.
		/// The resulting buffer uses CryptoSchemeId = Ed25519 (0x00)
		/// and is binary-compatible with V1.
		inline std::vector<uint8_t> ConvertV1ToV2(const VerifiableEntity& entity) {
			// V1 Ed25519 entities are already binary-compatible with V2 (SchemeId = 0x00).
			// Just copy the raw bytes.
			auto totalSize = entity.Size;
			std::vector<uint8_t> buffer(totalSize);
			std::memcpy(buffer.data(), &entity, totalSize);
			return buffer;
		}

		/// Converts a V1 EmbeddedTransaction to V2 wire format.
		inline std::vector<uint8_t> ConvertEmbeddedV1ToV2(const EmbeddedTransaction& transaction) {
			auto totalSize = transaction.Size;
			std::vector<uint8_t> buffer(totalSize);
			std::memcpy(buffer.data(), &transaction, totalSize);
			return buffer;
		}

		/// Converts a V1 Cosignature to V2 wire format.
		/// V2 cosignature layout: Version(8) + SchemeId(1) + Reserved(7) + Key(32) + Sig(64) = 112 bytes
		/// V1 cosignature layout: Version(8) + Key(32) + Sig(64) = 104 bytes
		/// Note: V2 adds 8 bytes (SchemeId + padding) between Version and Key.
		inline std::vector<uint8_t> ConvertCosignatureV1ToV2(const Cosignature& cosignature) {
			auto v2Size = EntityHeaderV2Layout::CosignatureSize(crypto::CryptoScheme::Ed25519);
			std::vector<uint8_t> buffer(v2Size, 0);

			// Version (8 bytes)
			std::memcpy(buffer.data(), &cosignature.Version, sizeof(cosignature.Version));

			// CryptoSchemeId (1 byte) at offset 8
			buffer[CosignatureV2Reader::CryptoSchemeId_Offset] = static_cast<uint8_t>(crypto::CryptoScheme::Ed25519);

			// SignerPublicKey at offset 16
			std::memcpy(buffer.data() + CosignatureV2Reader::Variable_Fields_Offset,
				cosignature.SignerPublicKey.data(), Key::Size);

			// Signature at offset 16 + 32 = 48
			std::memcpy(buffer.data() + CosignatureV2Reader::Variable_Fields_Offset + Key::Size,
				cosignature.Signature.data(), Signature::Size);

			return buffer;
		}

		// endregion

		// region V2 → V1 conversion (Ed25519 only)

		/// Checks if a V2 buffer represents an Ed25519 entity (convertible to V1).
		inline bool IsEd25519V2(const uint8_t* pData, size_t dataSize) {
			if (dataSize < EntityHeaderV2Layout::Variable_Fields_Offset)
				return false;
			return pData[EntityHeaderV2Layout::CryptoSchemeId_Offset] == static_cast<uint8_t>(crypto::CryptoScheme::Ed25519);
		}

		// endregion

		// region V2 entity creation

		/// Creates a V2 transaction buffer with the given parameters.
		/// Returns a buffer containing the complete V2 transaction header,
		/// ready for payload data to be appended after entityBodyEndOffset().
		inline EntityHeaderV2Writer CreateTransactionV2(
				crypto::CryptoScheme scheme,
				uint32_t totalSize,
				uint8_t version,
				NetworkIdentifier network,
				EntityType type) {
			EntityHeaderV2Writer writer(totalSize, scheme);
			writer.setVersion(version);
			writer.setNetwork(network);
			writer.setType(type);
			return writer;
		}

		/// Creates a V2 transaction buffer with additional MaxFee and Deadline fields.
		/// Returns a writer positioned after the header.
		inline EntityHeaderV2Writer CreateFullTransactionV2(
				crypto::CryptoScheme scheme,
				uint32_t totalSize,
				uint8_t version,
				NetworkIdentifier network,
				EntityType type,
				uint64_t maxFee,
				uint64_t deadline) {
			auto writer = CreateTransactionV2(scheme, totalSize, version, network, type);

			// MaxFee immediately follows the entity body (after Type field)
			auto feeOffset = writer.entityBodyEndOffset();
			writer.writeAt(feeOffset, reinterpret_cast<const uint8_t*>(&maxFee), sizeof(maxFee));

			// Deadline follows MaxFee
			auto deadlineOffset = feeOffset + sizeof(maxFee);
			writer.writeAt(deadlineOffset, reinterpret_cast<const uint8_t*>(&deadline), sizeof(deadline));

			return writer;
		}

		// endregion

		// region V2 signing support

		/// Returns the data buffer to be signed/verified for a V2 entity.
		/// This is everything after Header_Size to the end of the entity.
		inline RawBuffer GetSignableDataBuffer(const EntityHeaderV2Reader& reader) {
			return reader.dataBuffer();
		}

		/// Returns the data buffer to be signed/verified for a V2 entity,
		/// excluding the block footer of \a footerSize bytes.
		inline RawBuffer GetSignableDataBufferWithFooter(const EntityHeaderV2Reader& reader, size_t footerSize) {
			auto hdrSize = reader.headerSize();
			auto entitySize = reader.size();
			if (entitySize <= hdrSize + footerSize)
				return { nullptr, 0 };
			return { reader.data() + hdrSize, entitySize - hdrSize - footerSize };
		}

		// endregion

		// region V2 entity iteration

		/// Iterates over variable-sized V2 cosignatures in a buffer.
		/// Calls \a callback for each cosignature found.
		/// Returns the number of cosignatures processed.
		template<typename TCallback>
		size_t ForEachCosignatureV2(const uint8_t* pData, size_t dataSize, TCallback callback) {
			size_t offset = 0;
			size_t count = 0;

			while (offset < dataSize) {
				auto remaining = dataSize - offset;
				if (remaining < CosignatureV2Reader::Variable_Fields_Offset)
					break;

				CosignatureV2Reader reader(pData + offset, remaining);
				callback(reader);

				offset += reader.totalSize();
				++count;
			}

			return count;
		}

		// endregion

		// region V2 entity hashing support

		/// Computes the hash input components for a V2 entity.
		/// Symbol's entity hash = SHA3-256(Signature || SignerPublicKey || DataBuffer).
		/// For V2, the Signature and Key are variable-length.
		struct V2HashComponents {
			RawBuffer signature;
			RawBuffer signerPublicKey;
			RawBuffer dataBuffer;
		};

		/// Extracts hash components from a V2 entity reader.
		inline V2HashComponents GetV2HashComponents(const EntityHeaderV2Reader& reader) {
			return {
				reader.signature(),
				reader.signerPublicKey(),
				reader.dataBuffer()
			};
		}

		// endregion
	}
}}
