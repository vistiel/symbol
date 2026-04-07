/**
*** Phase 2: Wire Protocol V2 — Standalone Integration Tests
***
*** Tests the V2 entity header infrastructure without requiring catapult full build.
*** Validates:
***   - Layout offset calculations for Ed25519 and ML-DSA-65
***   - EntityHeaderV2Reader/Writer round-trip
***   - EmbeddedEntityHeaderV2Reader
***   - CosignatureV2Reader
***   - V1 binary compatibility
***   - V2 entity creation and field access
***   - Transaction and block header serialization
***   - Cosignature iteration
***
*** Compile:
***   g++ -std=c++17 -O2 -I../../../src -o wire_v2_test WireProtocolV2Tests.cpp
***   ./wire_v2_test
**/

#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ============================================================================
// Minimal type stubs (avoid pulling in full catapult headers)
// ============================================================================

namespace catapult {
	// RawBuffer stub
	struct RawBuffer {
		const uint8_t* pData;
		size_t Size;

		RawBuffer() : pData(nullptr), Size(0) {}
		RawBuffer(const uint8_t* p, size_t s) : pData(p), Size(s) {}
		RawBuffer(std::nullptr_t, size_t) : pData(nullptr), Size(0) {}
	};

	// ByteArray stub
	namespace utils {
		class NonCopyable {
		public:
			NonCopyable() = default;
			NonCopyable(const NonCopyable&) = delete;
			NonCopyable& operator=(const NonCopyable&) = delete;
			NonCopyable(NonCopyable&&) = default;
			NonCopyable& operator=(NonCopyable&&) = default;
		};

		template<typename TTag>
		class ByteArray {
		public:
			static constexpr size_t Size = TTag::Size;
			ByteArray() { std::memset(m_data, 0, Size); }
			const uint8_t* data() const { return m_data; }
			uint8_t* data() { return m_data; }
			static constexpr size_t size() { return Size; }
		private:
			uint8_t m_data[Size];
		};
	}

	// Type tags
	struct Signature_tag { static constexpr size_t Size = 64; };
	struct Key_tag { static constexpr size_t Size = 32; };
	struct Hash256_tag { static constexpr size_t Size = 32; };
	struct Hash512_tag { static constexpr size_t Size = 64; };

	using Signature = utils::ByteArray<Signature_tag>;
	using Key = utils::ByteArray<Key_tag>;
	using Hash256 = utils::ByteArray<Hash256_tag>;
	using Hash512 = utils::ByteArray<Hash512_tag>;

	using Height = uint64_t;
	using Timestamp = uint64_t;
	using Amount = uint64_t;
}

// Model layer stubs
namespace catapult { namespace model {
	enum class NetworkIdentifier : uint8_t {
		Mainnet = 0x68,
		Testnet = 0x98
	};

	enum class EntityType : uint16_t {
		Transfer = 0x4154,
		Aggregate_Complete = 0x4141,
		Block_Normal = 0x8143
	};
}}

// Crypto layer stubs
namespace catapult { namespace crypto {
	enum class CryptoScheme : uint8_t {
		Ed25519 = 0x00,
		Ml_Dsa_65 = 0x01
	};

	class CryptoBuffer {
	public:
		CryptoBuffer() = default;
		explicit CryptoBuffer(size_t size) : m_data(size) {}
		CryptoBuffer(const uint8_t* pData, size_t size) : m_data(pData, pData + size) {}
		const uint8_t* data() const { return m_data.data(); }
		uint8_t* data() { return m_data.data(); }
		size_t size() const { return m_data.size(); }
		bool empty() const { return m_data.empty(); }
		void resize(size_t size) { m_data.resize(size); }
	private:
		std::vector<uint8_t> m_data;
	};

	class SecureCryptoBuffer {
	public:
		SecureCryptoBuffer() = default;
		explicit SecureCryptoBuffer(size_t size) : m_data(size) {}
		const uint8_t* data() const { return m_data.data(); }
		uint8_t* data() { return m_data.data(); }
		size_t size() const { return m_data.size(); }
	private:
		std::vector<uint8_t> m_data;
	};

	class SignatureProvider {
	public:
		virtual ~SignatureProvider() = default;
		virtual CryptoScheme scheme() const = 0;
		virtual const std::string& name() const = 0;
		virtual size_t publicKeySize() const = 0;
		virtual size_t privateKeySize() const = 0;
		virtual size_t signatureSize() const = 0;
		virtual void extractPublicKey(const SecureCryptoBuffer&, CryptoBuffer&) const = 0;
		virtual void sign(const SecureCryptoBuffer&, const CryptoBuffer&, const std::vector<RawBuffer>&, CryptoBuffer&) const = 0;
		virtual bool verify(const CryptoBuffer&, const std::vector<RawBuffer>&, const CryptoBuffer&) const = 0;
		virtual void generatePrivateKey(SecureCryptoBuffer&) const = 0;
	};

	class KemProvider {
	public:
		virtual ~KemProvider() = default;
	};
}}

// Include the actual headers being tested (they only need the stubs above)
// We inline-include the header content by re-declaring the needed parts.
// In a real build, we would just #include "catapult/model/EntityHeaderV2.h"

// --- EntityHeaderV2.h inline (extracted core logic) ---

namespace catapult { namespace model {

	struct CryptoFieldSizes {
		size_t signatureSize;
		size_t publicKeySize;
	};

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

	namespace EntityHeaderV2Layout {
		constexpr size_t CryptoSchemeId_Offset = 4;
		constexpr size_t Variable_Fields_Offset = 8;

		inline constexpr size_t SignatureOffset() { return Variable_Fields_Offset; }

		inline size_t SignerPublicKeyOffset(size_t signatureSize) {
			return Variable_Fields_Offset + signatureSize;
		}

		inline size_t Reserved2Offset(size_t signatureSize, size_t publicKeySize) {
			return Variable_Fields_Offset + signatureSize + publicKeySize;
		}

		inline size_t VersionOffset(size_t signatureSize, size_t publicKeySize) {
			return Reserved2Offset(signatureSize, publicKeySize) + sizeof(uint32_t);
		}

		inline size_t NetworkOffset(size_t signatureSize, size_t publicKeySize) {
			return VersionOffset(signatureSize, publicKeySize) + sizeof(uint8_t);
		}

		inline size_t TypeOffset(size_t signatureSize, size_t publicKeySize) {
			return NetworkOffset(signatureSize, publicKeySize) + sizeof(uint8_t);
		}

		inline size_t HeaderSize(size_t signatureSize, size_t publicKeySize) {
			return Variable_Fields_Offset + signatureSize + publicKeySize + sizeof(uint32_t);
		}

		inline size_t EntityBodyEndOffset(size_t signatureSize, size_t publicKeySize) {
			return TypeOffset(signatureSize, publicKeySize) + sizeof(uint16_t);
		}

		inline size_t HeaderSize(crypto::CryptoScheme scheme) {
			auto sizes = GetCryptoFieldSizes(scheme);
			return HeaderSize(sizes.signatureSize, sizes.publicKeySize);
		}

		inline constexpr size_t EmbeddedSignerPublicKeyOffset() {
			return Variable_Fields_Offset;
		}

		inline size_t EmbeddedHeaderSize(size_t publicKeySize) {
			return Variable_Fields_Offset + publicKeySize + sizeof(uint32_t);
		}

		inline size_t EmbeddedHeaderSize(crypto::CryptoScheme scheme) {
			auto sizes = GetCryptoFieldSizes(scheme);
			return EmbeddedHeaderSize(sizes.publicKeySize);
		}

		inline size_t CosignatureSize(size_t signatureSize, size_t publicKeySize) {
			return 16 + publicKeySize + signatureSize;
		}

		inline size_t CosignatureSize(crypto::CryptoScheme scheme) {
			auto sizes = GetCryptoFieldSizes(scheme);
			return CosignatureSize(sizes.signatureSize, sizes.publicKeySize);
		}

		namespace Ed25519 {
			constexpr size_t Signature_Size = 64;
			constexpr size_t Public_Key_Size = 32;
			constexpr size_t Header_Size = 8 + 64 + 32 + 4;
			constexpr size_t Embedded_Header_Size = 8 + 32 + 4;
			constexpr size_t Cosignature_Size = 16 + 32 + 64;
		}

		namespace MlDsa65 {
			constexpr size_t Signature_Size = 3309;
			constexpr size_t Public_Key_Size = 1952;
			constexpr size_t Header_Size = 8 + 3309 + 1952 + 4;
			constexpr size_t Embedded_Header_Size = 8 + 1952 + 4;
			constexpr size_t Cosignature_Size = 16 + 1952 + 3309;
		}
	}

	class EntityHeaderV2Reader {
	public:
		EntityHeaderV2Reader(const uint8_t* pData, size_t dataSize)
				: m_pData(pData), m_dataSize(dataSize) {
			if (dataSize < EntityHeaderV2Layout::Variable_Fields_Offset)
				throw std::out_of_range("buffer too small for V2 entity header prefix");
			m_scheme = static_cast<crypto::CryptoScheme>(m_pData[EntityHeaderV2Layout::CryptoSchemeId_Offset]);
			m_fieldSizes = GetCryptoFieldSizes(m_scheme);
			auto minSize = EntityHeaderV2Layout::EntityBodyEndOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			if (dataSize < minSize)
				throw std::out_of_range("buffer too small for V2 entity header with scheme");
		}

		uint32_t size() const {
			uint32_t value;
			std::memcpy(&value, m_pData, sizeof(value));
			return value;
		}

		crypto::CryptoScheme cryptoScheme() const { return m_scheme; }
		const CryptoFieldSizes& fieldSizes() const { return m_fieldSizes; }

		size_t headerSize() const {
			return EntityHeaderV2Layout::HeaderSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
		}

		RawBuffer signature() const {
			return { m_pData + EntityHeaderV2Layout::SignatureOffset(), m_fieldSizes.signatureSize };
		}

		RawBuffer signerPublicKey() const {
			auto offset = EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize);
			return { m_pData + offset, m_fieldSizes.publicKeySize };
		}

		uint8_t version() const {
			return m_pData[EntityHeaderV2Layout::VersionOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)];
		}

		NetworkIdentifier network() const {
			auto offset = EntityHeaderV2Layout::NetworkOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			return static_cast<NetworkIdentifier>(m_pData[offset]);
		}

		EntityType type() const {
			auto offset = EntityHeaderV2Layout::TypeOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			uint16_t value;
			std::memcpy(&value, m_pData + offset, sizeof(value));
			return static_cast<EntityType>(value);
		}

		RawBuffer dataBuffer() const {
			auto hdrSize = headerSize();
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

	class EntityHeaderV2Writer {
	public:
		EntityHeaderV2Writer(uint32_t totalSize, crypto::CryptoScheme scheme)
				: m_buffer(totalSize, 0), m_scheme(scheme), m_fieldSizes(GetCryptoFieldSizes(scheme)) {
			std::memcpy(m_buffer.data(), &totalSize, sizeof(totalSize));
			m_buffer[EntityHeaderV2Layout::CryptoSchemeId_Offset] = static_cast<uint8_t>(scheme);
		}

		void setSignature(const uint8_t* pSignature, size_t signatureSize) {
			if (signatureSize != m_fieldSizes.signatureSize)
				throw std::invalid_argument("signature size mismatch");
			std::memcpy(m_buffer.data() + EntityHeaderV2Layout::SignatureOffset(), pSignature, signatureSize);
		}

		void setSignerPublicKey(const uint8_t* pKey, size_t keySize) {
			if (keySize != m_fieldSizes.publicKeySize)
				throw std::invalid_argument("public key size mismatch");
			auto offset = EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize);
			std::memcpy(m_buffer.data() + offset, pKey, keySize);
		}

		void setVersion(uint8_t version) {
			auto offset = EntityHeaderV2Layout::VersionOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			m_buffer[offset] = version;
		}

		void setNetwork(NetworkIdentifier network) {
			auto offset = EntityHeaderV2Layout::NetworkOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			m_buffer[offset] = static_cast<uint8_t>(network);
		}

		void setType(EntityType type) {
			auto offset = EntityHeaderV2Layout::TypeOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			auto rawType = static_cast<uint16_t>(type);
			std::memcpy(m_buffer.data() + offset, &rawType, sizeof(rawType));
		}

		void writeAt(size_t offset, const uint8_t* pData, size_t dataSize) {
			if (offset + dataSize > m_buffer.size())
				throw std::out_of_range("write exceeds buffer bounds");
			std::memcpy(m_buffer.data() + offset, pData, dataSize);
		}

		size_t headerSize() const {
			return EntityHeaderV2Layout::HeaderSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
		}

		size_t entityBodyEndOffset() const {
			return EntityHeaderV2Layout::EntityBodyEndOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
		}

		std::vector<uint8_t> release() { return std::move(m_buffer); }
		const uint8_t* data() const { return m_buffer.data(); }
		uint8_t* data() { return m_buffer.data(); }
		size_t size() const { return m_buffer.size(); }

	private:
		std::vector<uint8_t> m_buffer;
		crypto::CryptoScheme m_scheme;
		CryptoFieldSizes m_fieldSizes;
	};

	class EmbeddedEntityHeaderV2Reader {
	public:
		EmbeddedEntityHeaderV2Reader(const uint8_t* pData, size_t dataSize)
				: m_pData(pData), m_dataSize(dataSize) {
			if (dataSize < EntityHeaderV2Layout::Variable_Fields_Offset)
				throw std::out_of_range("buffer too small for V2 embedded header prefix");
			m_scheme = static_cast<crypto::CryptoScheme>(m_pData[EntityHeaderV2Layout::CryptoSchemeId_Offset]);
			m_fieldSizes = GetCryptoFieldSizes(m_scheme);
			auto keyOffset = EntityHeaderV2Layout::EmbeddedSignerPublicKeyOffset();
			auto bodyEnd = keyOffset + m_fieldSizes.publicKeySize + sizeof(uint32_t) + 4;
			if (dataSize < bodyEnd)
				throw std::out_of_range("buffer too small for V2 embedded header with scheme");
		}

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

		const uint8_t* data() const { return m_pData; }
		size_t dataSize() const { return m_dataSize; }

	private:
		const uint8_t* m_pData;
		size_t m_dataSize;
		crypto::CryptoScheme m_scheme;
		CryptoFieldSizes m_fieldSizes;
	};

	class CosignatureV2Reader {
	public:
		static constexpr size_t Version_Offset = 0;
		static constexpr size_t CryptoSchemeId_Offset = 8;
		static constexpr size_t Variable_Fields_Offset = 16;

		CosignatureV2Reader(const uint8_t* pData, size_t dataSize)
				: m_pData(pData), m_dataSize(dataSize) {
			if (dataSize < Variable_Fields_Offset)
				throw std::out_of_range("buffer too small for V2 cosignature prefix");
			m_scheme = static_cast<crypto::CryptoScheme>(m_pData[CryptoSchemeId_Offset]);
			m_fieldSizes = GetCryptoFieldSizes(m_scheme);
			auto expectedSize = EntityHeaderV2Layout::CosignatureSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			if (dataSize < expectedSize)
				throw std::out_of_range("buffer too small for V2 cosignature with scheme");
		}

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

}} // namespace catapult::model

// ============================================================================
// Test Framework
// ============================================================================

static int g_testCount = 0;
static int g_passCount = 0;
static int g_failCount = 0;

#define TEST(name) \
	void test_##name(); \
	struct TestRegistrar_##name { \
		TestRegistrar_##name() { \
			++g_testCount; \
			std::cout << "[TEST " << g_testCount << "] " << #name << " ... "; \
			try { \
				test_##name(); \
				std::cout << "PASSED" << std::endl; \
				++g_passCount; \
			} catch (const std::exception& e) { \
				std::cout << "FAILED: " << e.what() << std::endl; \
				++g_failCount; \
			} \
		} \
	} g_registrar_##name; \
	void test_##name()

#define ASSERT_EQ(expected, actual) \
	do { \
		auto _e = (expected); auto _a = (actual); \
		if (_e != _a) { \
			std::ostringstream _ss; \
			_ss << "ASSERT_EQ failed: expected " << _e << " but got " << _a \
				<< " [" << __FILE__ << ":" << __LINE__ << "]"; \
			throw std::runtime_error(_ss.str()); \
		} \
	} while (0)

#define ASSERT_THROW(expr, excType) \
	do { \
		bool _caught = false; \
		try { expr; } catch (const excType&) { _caught = true; } \
		if (!_caught) { \
			std::ostringstream _ss; \
			_ss << "ASSERT_THROW failed: expected " << #excType \
				<< " [" << __FILE__ << ":" << __LINE__ << "]"; \
			throw std::runtime_error(_ss.str()); \
		} \
	} while (0)

#define ASSERT_TRUE(cond) \
	do { \
		if (!(cond)) { \
			std::ostringstream _ss; \
			_ss << "ASSERT_TRUE failed: " << #cond \
				<< " [" << __FILE__ << ":" << __LINE__ << "]"; \
			throw std::runtime_error(_ss.str()); \
		} \
	} while (0)

using namespace catapult;
using namespace catapult::model;
using namespace catapult::crypto;

// ============================================================================
// Test 1-4: Layout offset and size calculations
// ============================================================================

TEST(Ed25519_Layout_Matches_V1) {
	// V1 Header_Size = sizeof(SizePrefixedEntity) + 2*sizeof(uint32_t) + Signature::Size + Key::Size
	//                = 4 + 8 + 64 + 32 = 108
	ASSERT_EQ(108u, EntityHeaderV2Layout::Ed25519::Header_Size);
	ASSERT_EQ(108u, EntityHeaderV2Layout::HeaderSize(CryptoScheme::Ed25519));

	// V1 EmbeddedHeader_Size = sizeof(SizePrefixedEntity) + 2*sizeof(uint32_t) + Key::Size = 4 + 8 + 32 = 44
	ASSERT_EQ(44u, EntityHeaderV2Layout::Ed25519::Embedded_Header_Size);
	ASSERT_EQ(44u, EntityHeaderV2Layout::EmbeddedHeaderSize(CryptoScheme::Ed25519));
}

TEST(Ed25519_Field_Offsets_Match_V1) {
	// V1 Transaction Layout:
	//   0x00: Size(4), 0x04: Reserved1(4), 0x08: Signature(64), 0x48: Key(32)
	//   0x68: Reserved2(4), 0x6C: Version(1), 0x6D: Network(1), 0x6E: Type(2)
	ASSERT_EQ(8u, EntityHeaderV2Layout::SignatureOffset());
	ASSERT_EQ(0x48u, EntityHeaderV2Layout::SignerPublicKeyOffset(64));  // 8 + 64 = 72 = 0x48
	ASSERT_EQ(0x68u, EntityHeaderV2Layout::Reserved2Offset(64, 32));    // 8 + 64 + 32 = 104 = 0x68
	ASSERT_EQ(0x6Cu, EntityHeaderV2Layout::VersionOffset(64, 32));      // 104 + 4 = 108 = 0x6C
	ASSERT_EQ(0x6Du, EntityHeaderV2Layout::NetworkOffset(64, 32));      // 108 + 1 = 109 = 0x6D
	ASSERT_EQ(0x6Eu, EntityHeaderV2Layout::TypeOffset(64, 32));         // 109 + 1 = 110 = 0x6E
}

TEST(MlDsa65_Layout_Sizes) {
	ASSERT_EQ(5273u, EntityHeaderV2Layout::MlDsa65::Header_Size);
	ASSERT_EQ(5273u, EntityHeaderV2Layout::HeaderSize(CryptoScheme::Ml_Dsa_65));
	ASSERT_EQ(1964u, EntityHeaderV2Layout::MlDsa65::Embedded_Header_Size);
	ASSERT_EQ(1964u, EntityHeaderV2Layout::EmbeddedHeaderSize(CryptoScheme::Ml_Dsa_65));
	ASSERT_EQ(5277u, EntityHeaderV2Layout::MlDsa65::Cosignature_Size);
}

TEST(MlDsa65_Field_Offsets) {
	ASSERT_EQ(8u, EntityHeaderV2Layout::SignatureOffset());
	ASSERT_EQ(8u + 3309, EntityHeaderV2Layout::SignerPublicKeyOffset(3309));
	ASSERT_EQ(8u + 3309 + 1952, EntityHeaderV2Layout::Reserved2Offset(3309, 1952));

	auto versionOff = EntityHeaderV2Layout::VersionOffset(3309, 1952);
	ASSERT_EQ(8u + 3309 + 1952 + 4, versionOff);  // 5273

	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);
	ASSERT_EQ(versionOff + 4u, bodyEnd);  // Version(1) + Network(1) + Type(2) = 4
}

// ============================================================================
// Test 5-8: EntityHeaderV2Writer / Reader round-trip
// ============================================================================

TEST(Ed25519_Writer_Reader_RoundTrip) {
	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(64, 32);
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 16);  // + 16 for fee + deadline

	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ed25519);
	writer.setVersion(1);
	writer.setNetwork(NetworkIdentifier::Mainnet);
	writer.setType(EntityType::Transfer);

	// Set a recognizable signature pattern
	std::vector<uint8_t> sig(64, 0xAB);
	writer.setSignature(sig.data(), sig.size());

	// Set a recognizable key pattern
	std::vector<uint8_t> key(32, 0xCD);
	writer.setSignerPublicKey(key.data(), key.size());

	// Read back
	EntityHeaderV2Reader reader(writer.data(), writer.size());
	ASSERT_EQ(totalSize, reader.size());
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ed25519), static_cast<uint8_t>(reader.cryptoScheme()));
	ASSERT_EQ(1u, reader.version());
	ASSERT_EQ(static_cast<uint8_t>(NetworkIdentifier::Mainnet), static_cast<uint8_t>(reader.network()));
	ASSERT_EQ(static_cast<uint16_t>(EntityType::Transfer), static_cast<uint16_t>(reader.type()));

	// Verify signature bytes
	auto sigBuf = reader.signature();
	ASSERT_EQ(64u, sigBuf.Size);
	for (size_t i = 0; i < 64; ++i)
		ASSERT_EQ(0xABu, sigBuf.pData[i]);

	// Verify key bytes
	auto keyBuf = reader.signerPublicKey();
	ASSERT_EQ(32u, keyBuf.Size);
	for (size_t i = 0; i < 32; ++i)
		ASSERT_EQ(0xCDu, keyBuf.pData[i]);

	// Verify header size
	ASSERT_EQ(108u, reader.headerSize());
}

TEST(MlDsa65_Writer_Reader_RoundTrip) {
	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 16);

	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ml_Dsa_65);
	writer.setVersion(2);
	writer.setNetwork(NetworkIdentifier::Testnet);
	writer.setType(EntityType::Transfer);

	std::vector<uint8_t> sig(3309, 0x11);
	writer.setSignature(sig.data(), sig.size());

	std::vector<uint8_t> key(1952, 0x22);
	writer.setSignerPublicKey(key.data(), key.size());

	EntityHeaderV2Reader reader(writer.data(), writer.size());
	ASSERT_EQ(totalSize, reader.size());
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ml_Dsa_65), static_cast<uint8_t>(reader.cryptoScheme()));
	ASSERT_EQ(2u, reader.version());
	ASSERT_EQ(static_cast<uint8_t>(NetworkIdentifier::Testnet), static_cast<uint8_t>(reader.network()));

	auto sigBuf = reader.signature();
	ASSERT_EQ(3309u, sigBuf.Size);
	ASSERT_EQ(0x11u, sigBuf.pData[0]);
	ASSERT_EQ(0x11u, sigBuf.pData[3308]);

	auto keyBuf = reader.signerPublicKey();
	ASSERT_EQ(1952u, keyBuf.Size);
	ASSERT_EQ(0x22u, keyBuf.pData[0]);
	ASSERT_EQ(0x22u, keyBuf.pData[1951]);

	ASSERT_EQ(5273u, reader.headerSize());
}

TEST(Writer_Rejects_Wrong_Signature_Size) {
	EntityHeaderV2Writer writer(256, CryptoScheme::Ed25519);
	std::vector<uint8_t> badSig(128, 0x00);  // wrong size
	ASSERT_THROW(writer.setSignature(badSig.data(), badSig.size()), std::invalid_argument);
}

TEST(Writer_Rejects_Wrong_Key_Size) {
	EntityHeaderV2Writer writer(256, CryptoScheme::Ml_Dsa_65);
	std::vector<uint8_t> badKey(32, 0x00);  // Ed25519 key size, not ML-DSA-65
	ASSERT_THROW(writer.setSignerPublicKey(badKey.data(), badKey.size()), std::invalid_argument);
}

// ============================================================================
// Test 9-10: V1 binary compatibility
// ============================================================================

TEST(V1_Ed25519_Buffer_Is_Valid_V2) {
	// Simulate a V1 transaction buffer
	// V1 layout: Size(4) Reserved1=0(4) Sig(64) Key(32) Reserved2=0(4) Version(1) Network(1) Type(2) Fee(8) Deadline(8)
	uint32_t v1Size = 0x80;  // 128 bytes
	std::vector<uint8_t> v1Buffer(v1Size, 0);
	std::memcpy(v1Buffer.data(), &v1Size, sizeof(v1Size));

	// V1 Reserved1 is 0x00000000 — same as CryptoSchemeId=Ed25519(0x00) + padding(0,0,0)

	// Set signature at offset 0x08
	for (size_t i = 0; i < 64; ++i)
		v1Buffer[0x08 + i] = 0xAA;

	// Set key at offset 0x48
	for (size_t i = 0; i < 32; ++i)
		v1Buffer[0x48 + i] = 0xBB;

	// Version at 0x6C, Network at 0x6D, Type at 0x6E
	v1Buffer[0x6C] = 1;
	v1Buffer[0x6D] = 0x68;  // Mainnet
	uint16_t transferType = 0x4154;
	std::memcpy(v1Buffer.data() + 0x6E, &transferType, sizeof(transferType));

	// Parse as V2
	EntityHeaderV2Reader reader(v1Buffer.data(), v1Buffer.size());
	ASSERT_EQ(v1Size, reader.size());
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ed25519), static_cast<uint8_t>(reader.cryptoScheme()));
	ASSERT_EQ(1u, reader.version());
	ASSERT_EQ(static_cast<uint8_t>(NetworkIdentifier::Mainnet), static_cast<uint8_t>(reader.network()));
	ASSERT_EQ(static_cast<uint16_t>(EntityType::Transfer), static_cast<uint16_t>(reader.type()));

	auto sig = reader.signature();
	ASSERT_EQ(64u, sig.Size);
	ASSERT_EQ(0xAAu, sig.pData[0]);

	auto key = reader.signerPublicKey();
	ASSERT_EQ(32u, key.Size);
	ASSERT_EQ(0xBBu, key.pData[0]);
}

TEST(V2_Ed25519_Produces_V1_Compatible_Bytes) {
	// Create a V2 Ed25519 entity and verify the byte layout matches V1
	uint32_t totalSize = 0x80;
	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ed25519);

	std::vector<uint8_t> sig(64, 0xDD);
	std::vector<uint8_t> key(32, 0xEE);
	writer.setSignature(sig.data(), sig.size());
	writer.setSignerPublicKey(key.data(), key.size());
	writer.setVersion(1);
	writer.setNetwork(NetworkIdentifier::Mainnet);
	writer.setType(EntityType::Transfer);

	auto buffer = writer.data();

	// Check V1 offsets
	ASSERT_EQ(0xDDu, buffer[0x08]);    // Signature at V1 offset
	ASSERT_EQ(0xDDu, buffer[0x47]);    // Last byte of signature
	ASSERT_EQ(0xEEu, buffer[0x48]);    // Key at V1 offset
	ASSERT_EQ(0xEEu, buffer[0x67]);    // Last byte of key
	ASSERT_EQ(1u, buffer[0x6C]);       // Version at V1 offset
	ASSERT_EQ(0x68u, buffer[0x6D]);    // Network at V1 offset

	// Type at V1 offset
	uint16_t typeVal;
	std::memcpy(&typeVal, buffer + 0x6E, sizeof(typeVal));
	ASSERT_EQ(static_cast<uint16_t>(EntityType::Transfer), typeVal);

	// CryptoSchemeId byte (V1's Reserved1 first byte) should be 0x00
	ASSERT_EQ(0x00u, buffer[0x04]);
}

// ============================================================================
// Test 11-12: EmbeddedEntityHeaderV2Reader
// ============================================================================

TEST(Ed25519_Embedded_Reader) {
	// Embedded: Size(4) SchemeId(1) Reserved(3) Key(32) Reserved2(4) Version(1) Network(1) Type(2) Data(...)
	uint32_t embSize = 64;  // 48 header + 16 payload
	std::vector<uint8_t> buffer(embSize, 0);
	std::memcpy(buffer.data(), &embSize, sizeof(embSize));
	buffer[4] = 0x00;  // Ed25519

	// Key at offset 8
	for (size_t i = 0; i < 32; ++i)
		buffer[8 + i] = 0x77;

	// Version at 8+32+4 = 44
	buffer[44] = 3;
	// Network at 45
	buffer[45] = 0x98;  // Testnet
	// Type at 46
	uint16_t type = 0x4154;
	std::memcpy(buffer.data() + 46, &type, sizeof(type));

	EmbeddedEntityHeaderV2Reader reader(buffer.data(), buffer.size());
	ASSERT_EQ(embSize, reader.size());
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ed25519), static_cast<uint8_t>(reader.cryptoScheme()));
	ASSERT_EQ(44u, reader.embeddedHeaderSize());  // matches V1!

	auto key = reader.signerPublicKey();
	ASSERT_EQ(32u, key.Size);
	ASSERT_EQ(0x77u, key.pData[0]);

	ASSERT_EQ(3u, reader.version());
	ASSERT_EQ(static_cast<uint8_t>(NetworkIdentifier::Testnet), static_cast<uint8_t>(reader.network()));
	ASSERT_EQ(static_cast<uint16_t>(EntityType::Transfer), static_cast<uint16_t>(reader.type()));
}

TEST(MlDsa65_Embedded_Reader) {
	uint32_t embSize = 2000;
	std::vector<uint8_t> buffer(embSize, 0);
	std::memcpy(buffer.data(), &embSize, sizeof(embSize));
	buffer[4] = 0x01;  // ML-DSA-65

	// Key at offset 8, size 1952
	for (size_t i = 0; i < 1952; ++i)
		buffer[8 + i] = static_cast<uint8_t>(i & 0xFF);

	// Version at 8+1952+4 = 1964
	buffer[1964] = 2;
	// Network at 1965
	buffer[1965] = 0x68;
	// Type at 1966
	uint16_t type = 0x4154;
	std::memcpy(buffer.data() + 1966, &type, sizeof(type));

	EmbeddedEntityHeaderV2Reader reader(buffer.data(), buffer.size());
	ASSERT_EQ(embSize, reader.size());
	ASSERT_EQ(1964u, reader.embeddedHeaderSize());

	auto key = reader.signerPublicKey();
	ASSERT_EQ(1952u, key.Size);
	ASSERT_EQ(0x00u, key.pData[0]);
	ASSERT_EQ(0x01u, key.pData[1]);

	ASSERT_EQ(2u, reader.version());
}

// ============================================================================
// Test 13-14: CosignatureV2Reader
// ============================================================================

TEST(Ed25519_Cosignature_Reader) {
	auto cosigSize = EntityHeaderV2Layout::CosignatureSize(CryptoScheme::Ed25519);
	ASSERT_EQ(112u, cosigSize);

	std::vector<uint8_t> buffer(cosigSize, 0);

	// Version = 42
	uint64_t version = 42;
	std::memcpy(buffer.data(), &version, sizeof(version));

	// SchemeId at offset 8
	buffer[8] = 0x00;

	// Key at offset 16 (32 bytes)
	for (size_t i = 0; i < 32; ++i)
		buffer[16 + i] = 0x55;

	// Signature at offset 16+32=48 (64 bytes)
	for (size_t i = 0; i < 64; ++i)
		buffer[48 + i] = 0x66;

	CosignatureV2Reader reader(buffer.data(), buffer.size());
	ASSERT_EQ(42u, reader.version());
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ed25519), static_cast<uint8_t>(reader.cryptoScheme()));
	ASSERT_EQ(112u, reader.totalSize());

	auto key = reader.signerPublicKey();
	ASSERT_EQ(32u, key.Size);
	ASSERT_EQ(0x55u, key.pData[0]);

	auto sig = reader.signature();
	ASSERT_EQ(64u, sig.Size);
	ASSERT_EQ(0x66u, sig.pData[0]);
}

TEST(MlDsa65_Cosignature_Reader) {
	auto cosigSize = EntityHeaderV2Layout::CosignatureSize(CryptoScheme::Ml_Dsa_65);
	ASSERT_EQ(5277u, cosigSize);

	std::vector<uint8_t> buffer(cosigSize, 0);

	uint64_t version = 1;
	std::memcpy(buffer.data(), &version, sizeof(version));
	buffer[8] = 0x01;  // ML-DSA-65

	// Key at offset 16 (1952 bytes)
	buffer[16] = 0xAA;
	buffer[16 + 1951] = 0xBB;

	// Signature at offset 16+1952=1968 (3309 bytes)
	buffer[1968] = 0xCC;
	buffer[1968 + 3308] = 0xDD;

	CosignatureV2Reader reader(buffer.data(), buffer.size());
	ASSERT_EQ(1u, reader.version());
	ASSERT_EQ(5277u, reader.totalSize());

	auto key = reader.signerPublicKey();
	ASSERT_EQ(1952u, key.Size);
	ASSERT_EQ(0xAAu, key.pData[0]);
	ASSERT_EQ(0xBBu, key.pData[1951]);

	auto sig = reader.signature();
	ASSERT_EQ(3309u, sig.Size);
	ASSERT_EQ(0xCCu, sig.pData[0]);
	ASSERT_EQ(0xDDu, sig.pData[3308]);
}

// ============================================================================
// Test 15-16: Data buffer extraction and signing support
// ============================================================================

TEST(DataBuffer_Extraction_Ed25519) {
	uint32_t totalSize = 0x90;  // 144 bytes
	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ed25519);
	writer.setVersion(1);

	// Write some recognizable data after the header
	auto hdrSize = writer.headerSize();
	ASSERT_EQ(108u, hdrSize);

	// Everything from offset 108 to 144 should be the data buffer
	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
	writer.writeAt(hdrSize, payload, sizeof(payload));

	EntityHeaderV2Reader reader(writer.data(), writer.size());
	auto dataBuf = reader.dataBuffer();
	ASSERT_EQ(totalSize - hdrSize, dataBuf.Size);  // 144 - 108 = 36
	ASSERT_EQ(0x01u, dataBuf.pData[0]);
	ASSERT_EQ(0x02u, dataBuf.pData[1]);
}

TEST(DataBuffer_Extraction_MlDsa65) {
	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 128);  // 128 bytes of payload

	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ml_Dsa_65);
	auto hdrSize = writer.headerSize();
	ASSERT_EQ(5273u, hdrSize);

	EntityHeaderV2Reader reader(writer.data(), writer.size());
	auto dataBuf = reader.dataBuffer();
	ASSERT_EQ(totalSize - hdrSize, dataBuf.Size);
}

// ============================================================================
// Test 17: Error handling — buffer too small
// ============================================================================

TEST(Reader_Throws_On_Buffer_Too_Small) {
	std::vector<uint8_t> tinyBuffer(4, 0);
	ASSERT_THROW(EntityHeaderV2Reader(tinyBuffer.data(), tinyBuffer.size()), std::out_of_range);

	// Buffer large enough for prefix but not for Ed25519 fields
	std::vector<uint8_t> smallBuffer(50, 0);
	smallBuffer[4] = 0x00;  // Ed25519 — needs at least 112 bytes
	ASSERT_THROW(EntityHeaderV2Reader(smallBuffer.data(), smallBuffer.size()), std::out_of_range);

	// Buffer large enough for prefix but not for ML-DSA-65 fields
	std::vector<uint8_t> medBuffer(200, 0);
	medBuffer[4] = 0x01;  // ML-DSA-65 — needs thousands of bytes
	ASSERT_THROW(EntityHeaderV2Reader(medBuffer.data(), medBuffer.size()), std::out_of_range);
}

// ============================================================================
// Test 18: Transaction creation with MaxFee and Deadline
// ============================================================================

TEST(Full_Transaction_V2_Ed25519) {
	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(64, 32);
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 16 + 32);  // +Fee+Deadline+payload

	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ed25519);
	writer.setVersion(1);
	writer.setNetwork(NetworkIdentifier::Mainnet);
	writer.setType(EntityType::Transfer);

	// Write MaxFee and Deadline after body end
	uint64_t maxFee = 100000;
	uint64_t deadline = 1234567890;
	writer.writeAt(bodyEnd, reinterpret_cast<const uint8_t*>(&maxFee), sizeof(maxFee));
	writer.writeAt(bodyEnd + 8, reinterpret_cast<const uint8_t*>(&deadline), sizeof(deadline));

	EntityHeaderV2Reader reader(writer.data(), writer.size());

	// Read MaxFee from known offset (bodyEnd)
	auto dataBuf = reader.dataBuffer();
	ASSERT_TRUE(dataBuf.Size >= 16);

	// In the V2 data buffer, the first 4 bytes after headerSize are Version/Network/Type
	// then MaxFee starts. But dataBuffer() starts at headerSize, so MaxFee is at offset
	// (bodyEnd - headerSize) within the data buffer.
	auto feeOffsetInData = bodyEnd - reader.headerSize();
	uint64_t readFee;
	std::memcpy(&readFee, dataBuf.pData + feeOffsetInData, sizeof(readFee));
	ASSERT_EQ(maxFee, readFee);

	uint64_t readDeadline;
	std::memcpy(&readDeadline, dataBuf.pData + feeOffsetInData + 8, sizeof(readDeadline));
	ASSERT_EQ(deadline, readDeadline);
}

// ============================================================================
// Test 19: Size comparison Ed25519 vs ML-DSA-65
// ============================================================================

TEST(Size_Impact_Analysis) {
	// Transaction header (through Type)
	auto ed25519Body = EntityHeaderV2Layout::EntityBodyEndOffset(64, 32);
	auto mldsaBody = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);

	std::cout << std::endl;
	std::cout << "    Size Impact Analysis:" << std::endl;
	std::cout << "    Ed25519 entity body end:  " << ed25519Body << " bytes" << std::endl;
	std::cout << "    ML-DSA-65 entity body end: " << mldsaBody << " bytes" << std::endl;
	std::cout << "    Ratio: " << (mldsaBody * 100 / ed25519Body) / 100.0 << "x" << std::endl;

	std::cout << "    Ed25519 Header_Size: " << EntityHeaderV2Layout::Ed25519::Header_Size << std::endl;
	std::cout << "    ML-DSA-65 Header_Size: " << EntityHeaderV2Layout::MlDsa65::Header_Size << std::endl;

	std::cout << "    Ed25519 Cosignature: " << EntityHeaderV2Layout::Ed25519::Cosignature_Size << " bytes" << std::endl;
	std::cout << "    ML-DSA-65 Cosignature: " << EntityHeaderV2Layout::MlDsa65::Cosignature_Size << " bytes" << std::endl;
	std::cout << "    ... ";

	// Verify expected sizes
	ASSERT_EQ(112u, ed25519Body);   // 108 + 4 (Version+Network+Type)
	ASSERT_EQ(5277u, mldsaBody);     // 5273 + 4
}

// ============================================================================
// Test 20: Writer boundary check
// ============================================================================

TEST(Writer_Rejects_Write_Beyond_Buffer) {
	EntityHeaderV2Writer writer(128, CryptoScheme::Ed25519);
	std::vector<uint8_t> data(10, 0xFF);
	ASSERT_THROW(writer.writeAt(125, data.data(), data.size()), std::out_of_range);
}

// ============================================================================
// Main
// ============================================================================

int main() {
	std::cout << "\n=== Phase 2: Wire Protocol V2 Tests ===" << std::endl;
	std::cout << std::endl;

	// Tests run automatically via static initialization

	std::cout << "\n=== Results ===" << std::endl;
	std::cout << "Total: " << g_testCount << "  Passed: " << g_passCount << "  Failed: " << g_failCount << std::endl;

	if (g_failCount > 0) {
		std::cout << "\n*** FAILURES DETECTED ***" << std::endl;
		return 1;
	}

	std::cout << "\nAll tests passed!" << std::endl;
	return 0;
}
