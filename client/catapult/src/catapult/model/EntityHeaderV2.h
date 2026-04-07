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
#include "EntityType.h"
#include "NetworkIdentifier.h"
#include "catapult/crypto/CryptoProvider.h"
#include "catapult/types.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace catapult { namespace model {

	// region V2 Wire Format Layout
	//
	// The V2 entity header replaces V1's fixed-size Signature (64B) and Key (32B)
	// with variable-length fields whose sizes are determined by a CryptoSchemeId byte.
	//
	// V2 VerifiableEntity Wire Format:
	//   Offset     Size          Field
	//   0x00       4 (uint32)    Size
	//   0x04       1 (uint8)     CryptoSchemeId (0x00=Ed25519, 0x01=ML-DSA-65)
	//   0x05       3             Reserved1 (padding for 8-byte alignment)
	//   0x08       S             Signature (size determined by CryptoSchemeId)
	//   0x08+S     K             SignerPublicKey (size determined by CryptoSchemeId)
	//   0x08+S+K   4 (uint32)    Reserved2
	//   0x0C+S+K   1 (uint8)     Version
	//   0x0D+S+K   1 (uint8)     Network (NetworkIdentifier)
	//   0x0E+S+K   2 (uint16)    Type (EntityType)
	//
	// Header_Size (bytes to skip for signing) = 8 + S + K + 4 = 12 + S + K
	//
	// For Ed25519 (S=64, K=32):  Header_Size = 108 (same as V1!)
	// For ML-DSA-65 (S=3309, K=1952): Header_Size = 5273
	//
	// IMPORTANT: When CryptoSchemeId = 0x00 and remaining Reserved bytes = 0,
	// the V2 format is BINARY COMPATIBLE with V1 (Reserved1 was always 0x00000000).
	//
	// V2 EmbeddedTransaction Wire Format (no signature):
	//   Offset     Size          Field
	//   0x00       4 (uint32)    Size
	//   0x04       1 (uint8)     CryptoSchemeId
	//   0x05       3             Reserved1
	//   0x08       K             SignerPublicKey (size determined by CryptoSchemeId)
	//   0x08+K     4 (uint32)    Reserved2
	//   0x0C+K     1 (uint8)     Version
	//   0x0D+K     1 (uint8)     Network (NetworkIdentifier)
	//   0x0E+K     2 (uint16)    Type (EntityType)
	//
	// EmbeddedHeader_Size = 8 + K + 4 = 12 + K
	// For Ed25519 (K=32):   EmbeddedHeader_Size = 44 (same as V1!)
	// For ML-DSA-65 (K=1952): EmbeddedHeader_Size = 1964
	//
	// V2 Cosignature Wire Format:
	//   [8 bytes]  Version (uint64)
	//   [1 byte]   CryptoSchemeId
	//   [7 bytes]  Reserved (padding for 8-byte alignment)
	//   [K bytes]  SignerPublicKey
	//   [S bytes]  Signature
	// endregion

	/// Cryptographic field sizes for a given scheme.
	struct CryptoFieldSizes {
		size_t signatureSize;
		size_t publicKeySize;
	};

	/// Returns the field sizes for the given \a scheme.
	inline CryptoFieldSizes GetCryptoFieldSizes(crypto::CryptoScheme scheme) {
		switch (scheme) {
		case crypto::CryptoScheme::Ed25519:
			return { 64, 32 };
		case crypto::CryptoScheme::Ml_Dsa_65:
			return { 3309, 1952 };
		default:
			throw std::invalid_argument("unknown crypto scheme");
		}
	}

	// region EntityHeaderV2Layout — offset calculations

	/// Namespace for V2 entity header wire format offset and size calculations.
	namespace EntityHeaderV2Layout {
		/// Offset of CryptoSchemeId field.
		constexpr size_t CryptoSchemeId_Offset = 4;

		/// Start of variable-length fields (after Size + SchemeId + Reserved).
		constexpr size_t Variable_Fields_Offset = 8;

		/// Offset of the Signature field.
		inline constexpr size_t SignatureOffset() {
			return Variable_Fields_Offset;
		}

		/// Offset of the SignerPublicKey field.
		inline size_t SignerPublicKeyOffset(size_t signatureSize) {
			return Variable_Fields_Offset + signatureSize;
		}

		/// Offset of Reserved2 (padding after SignerPublicKey).
		inline size_t Reserved2Offset(size_t signatureSize, size_t publicKeySize) {
			return Variable_Fields_Offset + signatureSize + publicKeySize;
		}

		/// Offset of the Version field.
		inline size_t VersionOffset(size_t signatureSize, size_t publicKeySize) {
			return Reserved2Offset(signatureSize, publicKeySize) + sizeof(uint32_t);
		}

		/// Offset of the Network field.
		inline size_t NetworkOffset(size_t signatureSize, size_t publicKeySize) {
			return VersionOffset(signatureSize, publicKeySize) + sizeof(uint8_t);
		}

		/// Offset of the Type field.
		inline size_t TypeOffset(size_t signatureSize, size_t publicKeySize) {
			return NetworkOffset(signatureSize, publicKeySize) + sizeof(uint8_t);
		}

		/// Header_Size: bytes to skip when signing (Size + SchemeId+Pad + Sig + Key + Reserved2).
		inline size_t HeaderSize(size_t signatureSize, size_t publicKeySize) {
			return Variable_Fields_Offset + signatureSize + publicKeySize + sizeof(uint32_t);
		}

		/// Total bytes through and including the Type field (EntityBody end).
		inline size_t EntityBodyEndOffset(size_t signatureSize, size_t publicKeySize) {
			return TypeOffset(signatureSize, publicKeySize) + sizeof(uint16_t);
		}

		/// Header_Size for a given crypto scheme.
		inline size_t HeaderSize(crypto::CryptoScheme scheme) {
			auto sizes = GetCryptoFieldSizes(scheme);
			return HeaderSize(sizes.signatureSize, sizes.publicKeySize);
		}

		/// Offset for EmbeddedTransaction V2: SignerPublicKey starts right after the prefix.
		inline constexpr size_t EmbeddedSignerPublicKeyOffset() {
			return Variable_Fields_Offset;
		}

		/// EmbeddedHeader_Size for V2.
		inline size_t EmbeddedHeaderSize(size_t publicKeySize) {
			return Variable_Fields_Offset + publicKeySize + sizeof(uint32_t);
		}

		/// EmbeddedHeader_Size for a given scheme.
		inline size_t EmbeddedHeaderSize(crypto::CryptoScheme scheme) {
			auto sizes = GetCryptoFieldSizes(scheme);
			return EmbeddedHeaderSize(sizes.publicKeySize);
		}

		/// V2 Cosignature size for a given scheme.
		inline size_t CosignatureSize(size_t signatureSize, size_t publicKeySize) {
			// Version(8) + SchemeId(1) + Reserved(7) + Key(K) + Signature(S)
			return 16 + publicKeySize + signatureSize;
		}

		inline size_t CosignatureSize(crypto::CryptoScheme scheme) {
			auto sizes = GetCryptoFieldSizes(scheme);
			return CosignatureSize(sizes.signatureSize, sizes.publicKeySize);
		}

		// Pre-computed sizes for Ed25519 (for compile-time use and V1 compatibility checks).
		namespace Ed25519 {
			constexpr size_t Signature_Size = 64;
			constexpr size_t Public_Key_Size = 32;
			constexpr size_t Header_Size = 8 + 64 + 32 + 4;  // = 108 (matches V1!)
			constexpr size_t Embedded_Header_Size = 8 + 32 + 4;  // = 44 (matches V1!)
			constexpr size_t Cosignature_Size = 16 + 32 + 64;  // = 112
		}

		// Pre-computed sizes for ML-DSA-65.
		namespace MlDsa65 {
			constexpr size_t Signature_Size = 3309;
			constexpr size_t Public_Key_Size = 1952;
			constexpr size_t Header_Size = 8 + 3309 + 1952 + 4;  // = 5273
			constexpr size_t Embedded_Header_Size = 8 + 1952 + 4;  // = 1964
			constexpr size_t Cosignature_Size = 16 + 1952 + 3309;  // = 5277
		}
	}

	// endregion

	// region EntityHeaderV2Reader — read-only buffer accessor

	/// Read-only accessor for a V2 entity header in a byte buffer.
	///
	/// Unlike V1's #pragma pack(1) structs, this class does not assume
	/// a fixed struct layout. Instead, it reads fields at runtime-determined
	/// offsets based on the CryptoSchemeId embedded in the buffer.
	class EntityHeaderV2Reader {
	public:
		/// Creates a reader over \a pData of \a dataSize bytes.
		/// \note The reader does NOT take ownership of the buffer.
		EntityHeaderV2Reader(const uint8_t* pData, size_t dataSize)
				: m_pData(pData)
				, m_dataSize(dataSize) {
			if (dataSize < EntityHeaderV2Layout::Variable_Fields_Offset)
				throw std::out_of_range("buffer too small for V2 entity header prefix");

			m_scheme = static_cast<crypto::CryptoScheme>(m_pData[EntityHeaderV2Layout::CryptoSchemeId_Offset]);
			m_fieldSizes = GetCryptoFieldSizes(m_scheme);

			auto minSize = EntityHeaderV2Layout::EntityBodyEndOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			if (dataSize < minSize)
				throw std::out_of_range("buffer too small for V2 entity header with scheme");
		}

	public:
		// --- Fixed fields ---

		/// Total entity size (first 4 bytes).
		uint32_t size() const {
			uint32_t value;
			std::memcpy(&value, m_pData, sizeof(value));
			return value;
		}

		/// Crypto scheme identifier.
		crypto::CryptoScheme cryptoScheme() const {
			return m_scheme;
		}

		/// Field sizes for this entity's crypto scheme.
		const CryptoFieldSizes& fieldSizes() const {
			return m_fieldSizes;
		}

		/// Header_Size (bytes to skip for signing).
		size_t headerSize() const {
			return EntityHeaderV2Layout::HeaderSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
		}

		// --- Variable-length fields ---

		/// Signature as a raw buffer view.
		RawBuffer signature() const {
			return { m_pData + EntityHeaderV2Layout::SignatureOffset(), m_fieldSizes.signatureSize };
		}

		/// Signer public key as a raw buffer view.
		RawBuffer signerPublicKey() const {
			auto offset = EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize);
			return { m_pData + offset, m_fieldSizes.publicKeySize };
		}

		// --- Body fields ---

		/// Entity version.
		uint8_t version() const {
			return m_pData[EntityHeaderV2Layout::VersionOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)];
		}

		/// Entity network identifier.
		NetworkIdentifier network() const {
			auto offset = EntityHeaderV2Layout::NetworkOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			return static_cast<NetworkIdentifier>(m_pData[offset]);
		}

		/// Entity type.
		EntityType type() const {
			auto offset = EntityHeaderV2Layout::TypeOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			uint16_t value;
			std::memcpy(&value, m_pData + offset, sizeof(value));
			return static_cast<EntityType>(value);
		}

		// --- Data buffer (signable portion) ---

		/// Returns the data buffer that should be signed/verified
		/// (everything after Header_Size to the end of the entity).
		RawBuffer dataBuffer() const {
			auto hdrSize = headerSize();
			auto entitySize = size();
			if (entitySize <= hdrSize)
				return { nullptr, 0 };
			return { m_pData + hdrSize, entitySize - hdrSize };
		}

		/// Returns the underlying raw buffer.
		const uint8_t* data() const { return m_pData; }

		/// Returns the total data size.
		size_t dataSize() const { return m_dataSize; }

	private:
		const uint8_t* m_pData;
		size_t m_dataSize;
		crypto::CryptoScheme m_scheme;
		CryptoFieldSizes m_fieldSizes;
	};

	// endregion

	// region EntityHeaderV2Writer — mutable buffer builder

	/// Mutable buffer builder for V2 entity headers.
	///
	/// Allocates an internal buffer and provides methods to write
	/// header fields at the correct offsets for the given crypto scheme.
	class EntityHeaderV2Writer {
	public:
		/// Creates a writer for an entity of \a totalSize bytes using \a scheme.
		EntityHeaderV2Writer(uint32_t totalSize, crypto::CryptoScheme scheme)
				: m_buffer(totalSize, 0)
				, m_scheme(scheme)
				, m_fieldSizes(GetCryptoFieldSizes(scheme)) {
			// Write Size field.
			std::memcpy(m_buffer.data(), &totalSize, sizeof(totalSize));

			// Write CryptoSchemeId.
			m_buffer[EntityHeaderV2Layout::CryptoSchemeId_Offset] = static_cast<uint8_t>(scheme);
		}

	public:
		/// Sets the signature.
		void setSignature(const uint8_t* pSignature, size_t signatureSize) {
			if (signatureSize != m_fieldSizes.signatureSize)
				throw std::invalid_argument("signature size mismatch");
			std::memcpy(m_buffer.data() + EntityHeaderV2Layout::SignatureOffset(), pSignature, signatureSize);
		}

		/// Sets the signer public key.
		void setSignerPublicKey(const uint8_t* pKey, size_t keySize) {
			if (keySize != m_fieldSizes.publicKeySize)
				throw std::invalid_argument("public key size mismatch");
			auto offset = EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize);
			std::memcpy(m_buffer.data() + offset, pKey, keySize);
		}

		/// Sets the entity version.
		void setVersion(uint8_t version) {
			auto offset = EntityHeaderV2Layout::VersionOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			m_buffer[offset] = version;
		}

		/// Sets the network identifier.
		void setNetwork(NetworkIdentifier network) {
			auto offset = EntityHeaderV2Layout::NetworkOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			m_buffer[offset] = static_cast<uint8_t>(network);
		}

		/// Sets the entity type.
		void setType(EntityType type) {
			auto offset = EntityHeaderV2Layout::TypeOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			auto rawType = static_cast<uint16_t>(type);
			std::memcpy(m_buffer.data() + offset, &rawType, sizeof(rawType));
		}

		/// Writes arbitrary data at \a offset.
		void writeAt(size_t offset, const uint8_t* pData, size_t dataSize) {
			if (offset + dataSize > m_buffer.size())
				throw std::out_of_range("write exceeds buffer bounds");
			std::memcpy(m_buffer.data() + offset, pData, dataSize);
		}

		/// Returns the header size for this entity's scheme.
		size_t headerSize() const {
			return EntityHeaderV2Layout::HeaderSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
		}

		/// Returns the entity body end offset (after Type field).
		size_t entityBodyEndOffset() const {
			return EntityHeaderV2Layout::EntityBodyEndOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
		}

		/// Releases ownership of the internal buffer.
		std::vector<uint8_t> release() { return std::move(m_buffer); }

		/// Returns a const pointer to the buffer.
		const uint8_t* data() const { return m_buffer.data(); }

		/// Returns a mutable pointer to the buffer.
		uint8_t* data() { return m_buffer.data(); }

		/// Returns the buffer size.
		size_t size() const { return m_buffer.size(); }

	private:
		std::vector<uint8_t> m_buffer;
		crypto::CryptoScheme m_scheme;
		CryptoFieldSizes m_fieldSizes;
	};

	// endregion

	// region EmbeddedEntityHeaderV2Reader — read-only accessor for embedded transactions

	/// Read-only accessor for a V2 embedded transaction header.
	class EmbeddedEntityHeaderV2Reader {
	public:
		EmbeddedEntityHeaderV2Reader(const uint8_t* pData, size_t dataSize)
				: m_pData(pData)
				, m_dataSize(dataSize) {
			if (dataSize < EntityHeaderV2Layout::Variable_Fields_Offset)
				throw std::out_of_range("buffer too small for V2 embedded header prefix");

			m_scheme = static_cast<crypto::CryptoScheme>(m_pData[EntityHeaderV2Layout::CryptoSchemeId_Offset]);
			m_fieldSizes = GetCryptoFieldSizes(m_scheme);

			auto keyOffset = EntityHeaderV2Layout::EmbeddedSignerPublicKeyOffset();
			auto bodyEnd = keyOffset + m_fieldSizes.publicKeySize + sizeof(uint32_t) + 4; // +Reserved2+Version+Network+Type
			if (dataSize < bodyEnd)
				throw std::out_of_range("buffer too small for V2 embedded header with scheme");
		}

	public:
		uint32_t size() const {
			uint32_t value;
			std::memcpy(&value, m_pData, sizeof(value));
			return value;
		}

		crypto::CryptoScheme cryptoScheme() const { return m_scheme; }

		size_t embeddedHeaderSize() const {
			return EntityHeaderV2Layout::EmbeddedHeaderSize(m_fieldSizes.publicKeySize);
		}

		RawBuffer signerPublicKey() const {
			return { m_pData + EntityHeaderV2Layout::EmbeddedSignerPublicKeyOffset(), m_fieldSizes.publicKeySize };
		}

		uint8_t version() const {
			auto offset = EntityHeaderV2Layout::EmbeddedSignerPublicKeyOffset()
				+ m_fieldSizes.publicKeySize + sizeof(uint32_t);
			return m_pData[offset];
		}

		NetworkIdentifier network() const {
			auto offset = EntityHeaderV2Layout::EmbeddedSignerPublicKeyOffset()
				+ m_fieldSizes.publicKeySize + sizeof(uint32_t) + 1;
			return static_cast<NetworkIdentifier>(m_pData[offset]);
		}

		EntityType type() const {
			auto offset = EntityHeaderV2Layout::EmbeddedSignerPublicKeyOffset()
				+ m_fieldSizes.publicKeySize + sizeof(uint32_t) + 2;
			uint16_t value;
			std::memcpy(&value, m_pData + offset, sizeof(value));
			return static_cast<EntityType>(value);
		}

		RawBuffer dataBuffer() const {
			auto hdrSize = embeddedHeaderSize();
			auto entitySize = size();
			if (entitySize <= hdrSize)
				return { nullptr, 0 };
			return { m_pData + hdrSize, entitySize - hdrSize };
		}

		const uint8_t* data() const { return m_pData; }
		size_t dataSize() const { return m_dataSize; }

	private:
		const uint8_t* m_pData;
		size_t m_dataSize;
		crypto::CryptoScheme m_scheme;
		CryptoFieldSizes m_fieldSizes;
	};

	// endregion

	// region CosignatureV2Reader — read-only accessor for V2 cosignatures

	/// Read-only accessor for a V2 cosignature in a byte buffer.
	class CosignatureV2Reader {
	public:
		/// Offset constants for fixed-position fields within a cosignature.
		static constexpr size_t Version_Offset = 0;
		static constexpr size_t CryptoSchemeId_Offset = 8;
		static constexpr size_t Reserved_Offset = 9;
		static constexpr size_t Variable_Fields_Offset = 16;  // After Version(8) + SchemeId(1) + Reserved(7)

	public:
		CosignatureV2Reader(const uint8_t* pData, size_t dataSize)
				: m_pData(pData)
				, m_dataSize(dataSize) {
			if (dataSize < Variable_Fields_Offset)
				throw std::out_of_range("buffer too small for V2 cosignature prefix");

			m_scheme = static_cast<crypto::CryptoScheme>(m_pData[CryptoSchemeId_Offset]);
			m_fieldSizes = GetCryptoFieldSizes(m_scheme);

			auto expectedSize = EntityHeaderV2Layout::CosignatureSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			if (dataSize < expectedSize)
				throw std::out_of_range("buffer too small for V2 cosignature with scheme");
		}

	public:
		uint64_t version() const {
			uint64_t value;
			std::memcpy(&value, m_pData + Version_Offset, sizeof(value));
			return value;
		}

		crypto::CryptoScheme cryptoScheme() const { return m_scheme; }

		RawBuffer signerPublicKey() const {
			return { m_pData + Variable_Fields_Offset, m_fieldSizes.publicKeySize };
		}

		RawBuffer signature() const {
			return { m_pData + Variable_Fields_Offset + m_fieldSizes.publicKeySize, m_fieldSizes.signatureSize };
		}

		size_t totalSize() const {
			return EntityHeaderV2Layout::CosignatureSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
		}

	private:
		const uint8_t* m_pData;
		size_t m_dataSize;
		crypto::CryptoScheme m_scheme;
		CryptoFieldSizes m_fieldSizes;
	};

	// endregion
}}
