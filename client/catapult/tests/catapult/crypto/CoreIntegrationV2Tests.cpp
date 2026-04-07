/**
*** Phase 3: Core Integration — Standalone Tests
***
*** End-to-end tests combining:
***   Phase 1: CryptoProviderRegistry + ML-DSA-65 provider (liboqs)
***   Phase 2: EntityHeaderV2 wire format layout
***   Phase 3: SignerV2, EntityHasherV2, BlockUtilsV2, AddressV2
***
*** Tests the complete V2 signing/verification pipeline:
***   1. Generate key pair via registry
***   2. Build V2 transaction/block buffer
***   3. Sign via V2 API (CryptoProviderRegistry dispatch)
***   4. Verify via V2 API
***   5. Hash via V2 API
***   6. Address derivation from variable-length keys
***
*** Compile (requires liboqs):
***   g++ -std=c++17 -O2 -I/usr/local/include -o core_v2_test CoreIntegrationV2Tests.cpp \
***       -L/usr/local/lib -loqs
***   LD_LIBRARY_PATH=/usr/local/lib ./core_v2_test
**/

#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <functional>
#include <memory>

// ============================================================================
// Minimal type stubs
// ============================================================================

namespace catapult {
	struct RawBuffer {
		const uint8_t* pData;
		size_t Size;
		RawBuffer() : pData(nullptr), Size(0) {}
		RawBuffer(const uint8_t* p, size_t s) : pData(p), Size(s) {}
		RawBuffer(std::nullptr_t, size_t) : pData(nullptr), Size(0) {}
		template<typename TByteArray>
		RawBuffer(const TByteArray& arr) : pData(arr.data()), Size(TByteArray::Size) {}
	};

	namespace utils {
		class NonCopyable {
		public:
			NonCopyable() = default;
			NonCopyable(const NonCopyable&) = delete;
			NonCopyable& operator=(const NonCopyable&) = delete;
		};

		template<typename TTag>
		class ByteArray {
		public:
			static constexpr size_t Size = TTag::Size;
			ByteArray() { std::memset(m_data, 0, Size); }
			const uint8_t* data() const { return m_data; }
			uint8_t* data() { return m_data; }
			static constexpr size_t size() { return Size; }
			bool operator==(const ByteArray& rhs) const { return std::memcmp(m_data, rhs.m_data, Size) == 0; }
			bool operator!=(const ByteArray& rhs) const { return !(*this == rhs); }
		private:
			uint8_t m_data[Size];
		};
	}

	struct Signature_tag { static constexpr size_t Size = 64; };
	struct Key_tag { static constexpr size_t Size = 32; };
	struct Hash256_tag { static constexpr size_t Size = 32; };
	struct Hash512_tag { static constexpr size_t Size = 64; };
	struct GenerationHashSeed_tag { static constexpr size_t Size = 32; };

	using Signature = utils::ByteArray<Signature_tag>;
	using Key = utils::ByteArray<Key_tag>;
	using Hash256 = utils::ByteArray<Hash256_tag>;
	using Hash512 = utils::ByteArray<Hash512_tag>;
	using GenerationHashSeed = utils::ByteArray<GenerationHashSeed_tag>;
	using Address = utils::ByteArray<GenerationHashSeed_tag>; // 24 bytes in real code, but we use 32 for stub

	template<typename T> using consumer = std::function<void(T, size_t)>;
}

// Model layer stubs
namespace catapult { namespace model {
	enum class NetworkIdentifier : uint8_t {
		Mainnet = 0x68,
		Testnet = 0x98
	};
	enum class EntityType : uint16_t {
		Transfer = 0x4154,
		Block_Normal = 0x8143
	};
}}

// ============================================================================
// Crypto stubs and real implementations
// ============================================================================

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
		auto begin() const { return m_data.begin(); }
		auto end() const { return m_data.end(); }
		bool operator==(const CryptoBuffer& rhs) const { return m_data == rhs.m_data; }
		bool operator!=(const CryptoBuffer& rhs) const { return !(*this == rhs); }
	private:
		std::vector<uint8_t> m_data;
	};

	class SecureCryptoBuffer {
	public:
		SecureCryptoBuffer() = default;
		explicit SecureCryptoBuffer(size_t size) : m_data(size) {}
		SecureCryptoBuffer(SecureCryptoBuffer&& rhs) noexcept : m_data(std::move(rhs.m_data)) {}
		SecureCryptoBuffer& operator=(SecureCryptoBuffer&& rhs) noexcept {
			m_data = std::move(rhs.m_data);
			return *this;
		}
		~SecureCryptoBuffer() {
			if (!m_data.empty()) {
				volatile uint8_t* p = m_data.data();
				for (size_t i = 0; i < m_data.size(); ++i) p[i] = 0;
			}
		}
		const uint8_t* data() const { return m_data.data(); }
		uint8_t* data() { return m_data.data(); }
		size_t size() const { return m_data.size(); }
		bool empty() const { return m_data.empty(); }
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

	class KemProvider { public: virtual ~KemProvider() = default; };
}}

// ============================================================================
// SHA3-256 stub (simplified for test — real impl would use OpenSSL)
// ============================================================================

namespace catapult { namespace crypto {
	// Simple SHA3-256 from scratch is complex. Use a hash stub that produces
	// deterministic output for testing.
	inline void Sha3_256(const RawBuffer& input, Hash256& output) {
		// Simplified hash: XOR-fold the input into 32 bytes with mixing
		std::memset(output.data(), 0, Hash256::Size);
		for (size_t i = 0; i < input.Size; ++i) {
			output.data()[i % 32] ^= input.pData[i];
			output.data()[(i + 13) % 32] ^= (input.pData[i] * 7 + 0x5A);
		}
	}

	class Sha3_256_Builder {
	public:
		void update(const RawBuffer& buffer) {
			m_data.insert(m_data.end(), buffer.pData, buffer.pData + buffer.Size);
		}
		template<typename T>
		void update(const T& arr) {
			m_data.insert(m_data.end(), arr.data(), arr.data() + T::Size);
		}
		void final(Hash256& output) {
			Sha3_256(RawBuffer{ m_data.data(), m_data.size() }, output);
		}
	private:
		std::vector<uint8_t> m_data;
	};
}}

// ============================================================================
// ML-DSA-65 provider (real liboqs implementation from Phase 1)
// ============================================================================

#include <oqs/oqs.h>

namespace catapult { namespace crypto {
	class MlDsa65SignatureProvider : public SignatureProvider {
	public:
		static constexpr size_t Public_Key_Size = 1952;
		static constexpr size_t Oqs_Secret_Key_Size = 4032;
		// Store as sk(4032) || pk(1952) — mirrors libsodium convention
		static constexpr size_t Private_Key_Size = Oqs_Secret_Key_Size + Public_Key_Size;
		static constexpr size_t Signature_Size = 3309;

		CryptoScheme scheme() const override { return CryptoScheme::Ml_Dsa_65; }
		const std::string& name() const override { static const std::string n = "ML-DSA-65"; return n; }
		size_t publicKeySize() const override { return Public_Key_Size; }
		size_t privateKeySize() const override { return Private_Key_Size; }
		size_t signatureSize() const override { return Signature_Size; }

		void extractPublicKey(const SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const override {
			publicKey.resize(Public_Key_Size);
			// Public key is stored after the OQS secret key
			std::memcpy(publicKey.data(), privateKey.data() + Oqs_Secret_Key_Size, Public_Key_Size);
		}

		void sign(const SecureCryptoBuffer& privateKey, const CryptoBuffer&,
				const std::vector<RawBuffer>& buffers, CryptoBuffer& signature) const override {
			std::vector<uint8_t> message;
			for (const auto& buf : buffers)
				message.insert(message.end(), buf.pData, buf.pData + buf.Size);

			signature.resize(Signature_Size);
			size_t sigLen = Signature_Size;
			// liboqs reads only the first Oqs_Secret_Key_Size bytes
			auto rc = OQS_SIG_ml_dsa_65_sign(
				signature.data(), &sigLen,
				message.data(), message.size(),
				privateKey.data());
			if (rc != OQS_SUCCESS)
				throw std::runtime_error("ML-DSA-65 sign failed");
		}

		bool verify(const CryptoBuffer& publicKey, const std::vector<RawBuffer>& buffers,
				const CryptoBuffer& signature) const override {
			std::vector<uint8_t> message;
			for (const auto& buf : buffers)
				message.insert(message.end(), buf.pData, buf.pData + buf.Size);

			return OQS_SUCCESS == OQS_SIG_ml_dsa_65_verify(
				message.data(), message.size(),
				signature.data(), signature.size(),
				publicKey.data());
		}

		void generatePrivateKey(SecureCryptoBuffer& privateKey) const override {
			privateKey = SecureCryptoBuffer(Private_Key_Size);
			// OQS keypair: write pk after sk in the same buffer
			auto rc = OQS_SIG_ml_dsa_65_keypair(
				privateKey.data() + Oqs_Secret_Key_Size,  // pk at offset 4032
				privateKey.data());                       // sk at offset 0
			if (rc != OQS_SUCCESS)
				throw std::runtime_error("ML-DSA-65 keypair generation failed");
		}
	};
}}

// ============================================================================
// CryptoProviderRegistry (inline simplified version for test)
// ============================================================================

namespace catapult { namespace crypto {
	class CryptoProviderRegistry {
	public:
		CryptoProviderRegistry() {
			// Register ML-DSA-65 (Ed25519 requires donna lib, so we skip it in this test)
			m_sigProviders[CryptoScheme::Ml_Dsa_65] = std::make_shared<MlDsa65SignatureProvider>();
		}

		void registerSignatureProvider(std::shared_ptr<SignatureProvider> p) {
			m_sigProviders[p->scheme()] = std::move(p);
		}

		const SignatureProvider& signatureProvider(CryptoScheme scheme) const {
			auto it = m_sigProviders.find(scheme);
			if (it == m_sigProviders.end())
				throw std::invalid_argument("unknown crypto scheme");
			return *it->second;
		}

		bool hasSignatureProvider(CryptoScheme scheme) const {
			return m_sigProviders.count(scheme) > 0;
		}

	private:
		std::unordered_map<CryptoScheme, std::shared_ptr<SignatureProvider>> m_sigProviders;
	};
}}

// ============================================================================
// Inline V2 infrastructure (from Phase 2 & 3 headers)
// ============================================================================

namespace catapult { namespace model {

	struct CryptoFieldSizes {
		size_t signatureSize;
		size_t publicKeySize;
	};

	inline CryptoFieldSizes GetCryptoFieldSizes(crypto::CryptoScheme scheme) {
		switch (scheme) {
		case crypto::CryptoScheme::Ed25519: return { 64, 32 };
		case crypto::CryptoScheme::Ml_Dsa_65: return { 3309, 1952 };
		default: throw std::invalid_argument("unknown crypto scheme");
		}
	}

	namespace EntityHeaderV2Layout {
		constexpr size_t CryptoSchemeId_Offset = 4;
		constexpr size_t Variable_Fields_Offset = 8;
		inline constexpr size_t SignatureOffset() { return Variable_Fields_Offset; }
		inline size_t SignerPublicKeyOffset(size_t sigSize) { return Variable_Fields_Offset + sigSize; }
		inline size_t HeaderSize(size_t sigSize, size_t keySize) { return Variable_Fields_Offset + sigSize + keySize + sizeof(uint32_t); }
		inline size_t VersionOffset(size_t sigSize, size_t keySize) { return HeaderSize(sigSize, keySize); }
		inline size_t NetworkOffset(size_t sigSize, size_t keySize) { return VersionOffset(sigSize, keySize) + 1; }
		inline size_t TypeOffset(size_t sigSize, size_t keySize) { return NetworkOffset(sigSize, keySize) + 1; }
		inline size_t EntityBodyEndOffset(size_t sigSize, size_t keySize) { return TypeOffset(sigSize, keySize) + 2; }
		inline size_t HeaderSize(crypto::CryptoScheme scheme) {
			auto s = GetCryptoFieldSizes(scheme);
			return HeaderSize(s.signatureSize, s.publicKeySize);
		}
	}

	class EntityHeaderV2Reader {
	public:
		EntityHeaderV2Reader(const uint8_t* pData, size_t dataSize)
				: m_pData(pData), m_dataSize(dataSize) {
			m_scheme = static_cast<crypto::CryptoScheme>(m_pData[EntityHeaderV2Layout::CryptoSchemeId_Offset]);
			m_fieldSizes = GetCryptoFieldSizes(m_scheme);
		}

		uint32_t size() const { uint32_t v; std::memcpy(&v, m_pData, 4); return v; }
		crypto::CryptoScheme cryptoScheme() const { return m_scheme; }
		const CryptoFieldSizes& fieldSizes() const { return m_fieldSizes; }
		size_t headerSize() const { return EntityHeaderV2Layout::HeaderSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize); }

		RawBuffer signature() const { return { m_pData + EntityHeaderV2Layout::SignatureOffset(), m_fieldSizes.signatureSize }; }
		RawBuffer signerPublicKey() const {
			return { m_pData + EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize), m_fieldSizes.publicKeySize };
		}

		uint8_t version() const { return m_pData[EntityHeaderV2Layout::VersionOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)]; }
		NetworkIdentifier network() const {
			return static_cast<NetworkIdentifier>(m_pData[EntityHeaderV2Layout::NetworkOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)]);
		}
		EntityType type() const {
			auto off = EntityHeaderV2Layout::TypeOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			uint16_t v; std::memcpy(&v, m_pData + off, 2); return static_cast<EntityType>(v);
		}

		RawBuffer dataBuffer() const {
			auto h = headerSize(); auto s = size();
			if (s <= h) return { nullptr, 0 };
			return { m_pData + h, s - h };
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
			std::memcpy(m_buffer.data(), &totalSize, 4);
			m_buffer[EntityHeaderV2Layout::CryptoSchemeId_Offset] = static_cast<uint8_t>(scheme);
		}

		void setSignature(const uint8_t* p, size_t s) {
			std::memcpy(m_buffer.data() + EntityHeaderV2Layout::SignatureOffset(), p, s);
		}
		void setSignerPublicKey(const uint8_t* p, size_t s) {
			std::memcpy(m_buffer.data() + EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize), p, s);
		}
		void setVersion(uint8_t v) {
			m_buffer[EntityHeaderV2Layout::VersionOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)] = v;
		}
		void setNetwork(NetworkIdentifier n) {
			m_buffer[EntityHeaderV2Layout::NetworkOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)] = static_cast<uint8_t>(n);
		}
		void setType(EntityType t) {
			auto off = EntityHeaderV2Layout::TypeOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize);
			auto v = static_cast<uint16_t>(t); std::memcpy(m_buffer.data() + off, &v, 2);
		}
		void writeAt(size_t off, const uint8_t* p, size_t s) { std::memcpy(m_buffer.data() + off, p, s); }

		size_t headerSize() const { return EntityHeaderV2Layout::HeaderSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize); }
		size_t entityBodyEndOffset() const { return EntityHeaderV2Layout::EntityBodyEndOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize); }
		const uint8_t* data() const { return m_buffer.data(); }
		uint8_t* data() { return m_buffer.data(); }
		size_t size() const { return m_buffer.size(); }
		std::vector<uint8_t> release() { return std::move(m_buffer); }

	private:
		std::vector<uint8_t> m_buffer;
		crypto::CryptoScheme m_scheme;
		CryptoFieldSizes m_fieldSizes;
	};
}}

// ============================================================================
// Inline V2 APIs (from Phase 3 headers)
// ============================================================================

namespace catapult { namespace crypto {
	inline void SignV2(const CryptoProviderRegistry& reg, CryptoScheme scheme,
			const SecureCryptoBuffer& privKey, const CryptoBuffer& pubKey,
			const std::vector<RawBuffer>& buffers, CryptoBuffer& signature) {
		reg.signatureProvider(scheme).sign(privKey, pubKey, buffers, signature);
	}
	inline void SignV2(const CryptoProviderRegistry& reg, CryptoScheme scheme,
			const SecureCryptoBuffer& privKey, const CryptoBuffer& pubKey,
			const RawBuffer& buf, CryptoBuffer& signature) {
		SignV2(reg, scheme, privKey, pubKey, std::vector<RawBuffer>{ buf }, signature);
	}
	inline bool VerifyV2(const CryptoProviderRegistry& reg, CryptoScheme scheme,
			const CryptoBuffer& pubKey, const std::vector<RawBuffer>& buffers, const CryptoBuffer& sig) {
		return reg.signatureProvider(scheme).verify(pubKey, buffers, sig);
	}
	inline bool VerifyV2(const CryptoProviderRegistry& reg, CryptoScheme scheme,
			const CryptoBuffer& pubKey, const RawBuffer& buf, const CryptoBuffer& sig) {
		return VerifyV2(reg, scheme, pubKey, std::vector<RawBuffer>{ buf }, sig);
	}

	struct SignatureInputV2 {
		CryptoScheme Scheme;
		CryptoBuffer PublicKey;
		std::vector<RawBuffer> Buffers;
		CryptoBuffer Signature;
	};

	inline std::pair<std::vector<bool>, bool> VerifyMultiV2(
			const CryptoProviderRegistry& reg, const SignatureInputV2* pInputs, size_t count) {
		std::vector<bool> results(count);
		bool allValid = true;
		for (size_t i = 0; i < count; ++i) {
			results[i] = VerifyV2(reg, pInputs[i].Scheme, pInputs[i].PublicKey, pInputs[i].Buffers, pInputs[i].Signature);
			if (!results[i]) allValid = false;
		}
		return { std::move(results), allValid };
	}

	inline std::pair<SecureCryptoBuffer, CryptoBuffer> GenerateKeyPairV2(
			const CryptoProviderRegistry& reg, CryptoScheme scheme) {
		const auto& prov = reg.signatureProvider(scheme);
		SecureCryptoBuffer privKey; prov.generatePrivateKey(privKey);
		CryptoBuffer pubKey; prov.extractPublicKey(privKey, pubKey);
		return { std::move(privKey), std::move(pubKey) };
	}
}}

// BlockUtilsV2 inline
namespace catapult { namespace model { namespace BlockUtilsV2 {
	inline void SignTransaction(const crypto::CryptoProviderRegistry& reg, crypto::CryptoScheme scheme,
			const crypto::SecureCryptoBuffer& privKey, const crypto::CryptoBuffer& pubKey,
			uint8_t* pBuf, size_t txSize) {
		EntityHeaderV2Reader reader(pBuf, txSize);
		auto dataBuf = reader.dataBuffer();
		crypto::CryptoBuffer sig;
		crypto::SignV2(reg, scheme, privKey, pubKey, dataBuf, sig);
		std::memcpy(pBuf + EntityHeaderV2Layout::SignatureOffset(), sig.data(), sig.size());
	}

	inline bool VerifyTransactionSignature(const crypto::CryptoProviderRegistry& reg,
			const uint8_t* pBuf, size_t txSize) {
		EntityHeaderV2Reader reader(pBuf, txSize);
		auto sigBuf = reader.signature(); auto keyBuf = reader.signerPublicKey();
		crypto::CryptoBuffer pubKey(keyBuf.pData, keyBuf.Size);
		crypto::CryptoBuffer sig(sigBuf.pData, sigBuf.Size);
		return crypto::VerifyV2(reg, reader.cryptoScheme(), pubKey, reader.dataBuffer(), sig);
	}
}}}

// EntityHasherV2 inline
namespace catapult { namespace model { namespace EntityHasherV2 {
	inline Hash256 CalculateTransactionHash(const EntityHeaderV2Reader& reader, const GenerationHashSeed& seed) {
		Hash256 hash;
		crypto::Sha3_256_Builder sha3;
		sha3.update(reader.signature());
		sha3.update(reader.signerPublicKey());
		sha3.update(seed);
		sha3.update(reader.dataBuffer());
		sha3.final(hash);
		return hash;
	}
}}}

// AddressV2 inline
namespace catapult { namespace model { namespace AddressV2 {
	inline Address PublicKeyToAddress(const uint8_t* pKey, size_t keySize,
			NetworkIdentifier net, crypto::CryptoScheme scheme) {
		Hash256 h;
		crypto::Sha3_256(RawBuffer{ pKey, keySize }, h);
		Address addr{};
		addr.data()[0] = static_cast<uint8_t>(net);
		std::memcpy(addr.data() + 1, h.data(), 20);
		addr.data()[1] ^= static_cast<uint8_t>(scheme);
		Hash256 chk;
		crypto::Sha3_256(RawBuffer{ addr.data(), 21 }, chk);
		std::memcpy(addr.data() + 21, chk.data(), 3);
		return addr;
	}
	inline Address PublicKeyToAddress(const crypto::CryptoBuffer& key, NetworkIdentifier net, crypto::CryptoScheme scheme) {
		return PublicKeyToAddress(key.data(), key.size(), net, scheme);
	}
}}}

// ============================================================================
// Test Framework
// ============================================================================

static int g_testCount = 0, g_passCount = 0, g_failCount = 0;

#define TEST(name) \
	void test_##name(); \
	struct TR_##name { TR_##name() { \
		++g_testCount; \
		std::cout << "[TEST " << g_testCount << "] " << #name << " ... "; \
		try { test_##name(); std::cout << "PASSED" << std::endl; ++g_passCount; } \
		catch (const std::exception& e) { std::cout << "FAILED: " << e.what() << std::endl; ++g_failCount; } \
	}} g_tr_##name; \
	void test_##name()

#define ASSERT_EQ(e, a) do { auto _e=(e); auto _a=(a); if(_e!=_a) { \
	std::ostringstream s; s << "expected " << _e << " got " << _a << " [" << __LINE__ << "]"; \
	throw std::runtime_error(s.str()); } } while(0)
#define ASSERT_TRUE(c) do { if(!(c)) { std::ostringstream s; s << #c << " [" << __LINE__ << "]"; \
	throw std::runtime_error(s.str()); } } while(0)
#define ASSERT_FALSE(c) ASSERT_TRUE(!(c))

using namespace catapult;
using namespace catapult::crypto;
using namespace catapult::model;

// ============================================================================
// Test 1: Key pair generation via registry
// ============================================================================

TEST(MlDsa65_KeyPair_Generation_Via_Registry) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	ASSERT_EQ(5984u, privKey.size());  // 4032 (OQS sk) + 1952 (pk embedded)
	ASSERT_EQ(1952u, pubKey.size());

	// Keys should be non-zero
	bool allZero = true;
	for (size_t i = 0; i < pubKey.size(); ++i)
		if (pubKey.data()[i] != 0) { allZero = false; break; }
	ASSERT_FALSE(allZero);
}

// ============================================================================
// Test 2: SignV2 + VerifyV2 round-trip with raw buffers
// ============================================================================

TEST(MlDsa65_SignV2_VerifyV2_RoundTrip) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	uint8_t message[] = "Hello, post-quantum Symbol!";
	RawBuffer buf(message, sizeof(message) - 1);

	CryptoBuffer signature;
	SignV2(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey, buf, signature);
	ASSERT_EQ(3309u, signature.size());

	bool valid = VerifyV2(registry, CryptoScheme::Ml_Dsa_65, pubKey, buf, signature);
	ASSERT_TRUE(valid);
}

// ============================================================================
// Test 3: Tampered message rejection
// ============================================================================

TEST(MlDsa65_Tampered_Message_Rejected) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	uint8_t message[] = "Original message";
	RawBuffer buf(message, sizeof(message) - 1);

	CryptoBuffer signature;
	SignV2(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey, buf, signature);

	uint8_t tampered[] = "Tampered message";
	RawBuffer tamperBuf(tampered, sizeof(tampered) - 1);

	ASSERT_FALSE(VerifyV2(registry, CryptoScheme::Ml_Dsa_65, pubKey, tamperBuf, signature));
}

// ============================================================================
// Test 4: Wrong key rejection
// ============================================================================

TEST(MlDsa65_Wrong_Key_Rejected) {
	CryptoProviderRegistry registry;
	auto [privKey1, pubKey1] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);
	auto [privKey2, pubKey2] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	uint8_t message[] = "Test message";
	RawBuffer buf(message, sizeof(message) - 1);

	CryptoBuffer signature;
	SignV2(registry, CryptoScheme::Ml_Dsa_65, privKey1, pubKey1, buf, signature);

	// Verify with wrong key should fail
	ASSERT_FALSE(VerifyV2(registry, CryptoScheme::Ml_Dsa_65, pubKey2, buf, signature));
}

// ============================================================================
// Test 5: Full V2 transaction sign/verify cycle
// ============================================================================

TEST(MlDsa65_V2_Transaction_SignVerify) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);
	uint32_t payloadSize = 32;  // 32 bytes of transaction data
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 16 + payloadSize);  // +Fee+Deadline+payload

	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ml_Dsa_65);
	writer.setSignerPublicKey(pubKey.data(), pubKey.size());
	writer.setVersion(1);
	writer.setNetwork(NetworkIdentifier::Mainnet);
	writer.setType(EntityType::Transfer);

	// Write MaxFee and Deadline
	uint64_t fee = 100000, deadline = 9999999;
	writer.writeAt(bodyEnd, reinterpret_cast<const uint8_t*>(&fee), 8);
	writer.writeAt(bodyEnd + 8, reinterpret_cast<const uint8_t*>(&deadline), 8);

	// Write some payload data
	for (uint32_t i = 0; i < payloadSize; ++i)
		writer.data()[bodyEnd + 16 + i] = static_cast<uint8_t>(i);

	// Sign the transaction
	BlockUtilsV2::SignTransaction(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey,
		writer.data(), writer.size());

	// Verify
	ASSERT_TRUE(BlockUtilsV2::VerifyTransactionSignature(registry, writer.data(), writer.size()));

	// Tamper with payload and verify fails
	writer.data()[bodyEnd + 16] ^= 0xFF;
	ASSERT_FALSE(BlockUtilsV2::VerifyTransactionSignature(registry, writer.data(), writer.size()));
}

// ============================================================================
// Test 6: Multiple transaction batch verification
// ============================================================================

TEST(MlDsa65_BatchVerifyMultiV2) {
	CryptoProviderRegistry registry;

	constexpr size_t numTx = 5;
	std::vector<SignatureInputV2> inputs(numTx);
	std::vector<std::vector<uint8_t>> messages(numTx);

	for (size_t i = 0; i < numTx; ++i) {
		auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

		std::string msg = "Transaction #" + std::to_string(i);
		messages[i].assign(msg.begin(), msg.end());

		CryptoBuffer signature;
		RawBuffer buf(messages[i].data(), messages[i].size());
		SignV2(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey, buf, signature);

		inputs[i].Scheme = CryptoScheme::Ml_Dsa_65;
		inputs[i].PublicKey = std::move(pubKey);
		inputs[i].Buffers = { RawBuffer(messages[i].data(), messages[i].size()) };
		inputs[i].Signature = std::move(signature);
	}

	auto [results, allValid] = VerifyMultiV2(registry, inputs.data(), inputs.size());
	ASSERT_TRUE(allValid);
	for (size_t i = 0; i < numTx; ++i)
		ASSERT_TRUE(results[i]);
}

// ============================================================================
// Test 7: Batch verify with one bad signature
// ============================================================================

TEST(MlDsa65_BatchVerify_WithBadSignature) {
	CryptoProviderRegistry registry;

	constexpr size_t numTx = 3;
	std::vector<SignatureInputV2> inputs(numTx);
	std::vector<std::vector<uint8_t>> messages(numTx);

	for (size_t i = 0; i < numTx; ++i) {
		auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);
		std::string msg = "Msg " + std::to_string(i);
		messages[i].assign(msg.begin(), msg.end());

		CryptoBuffer signature;
		RawBuffer buf(messages[i].data(), messages[i].size());
		SignV2(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey, buf, signature);

		inputs[i].Scheme = CryptoScheme::Ml_Dsa_65;
		inputs[i].PublicKey = std::move(pubKey);
		inputs[i].Buffers = { RawBuffer(messages[i].data(), messages[i].size()) };
		inputs[i].Signature = std::move(signature);
	}

	// Tamper with signature of index 1
	inputs[1].Signature.data()[0] ^= 0xFF;

	auto [results, allValid] = VerifyMultiV2(registry, inputs.data(), inputs.size());
	ASSERT_FALSE(allValid);
	ASSERT_TRUE(results[0]);
	ASSERT_FALSE(results[1]);
	ASSERT_TRUE(results[2]);
}

// ============================================================================
// Test 8: Entity hash V2 — transaction hash
// ============================================================================

TEST(MlDsa65_EntityHashV2_TransactionHash) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 16);
	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ml_Dsa_65);
	writer.setSignerPublicKey(pubKey.data(), pubKey.size());
	writer.setVersion(1);
	writer.setNetwork(NetworkIdentifier::Mainnet);
	writer.setType(EntityType::Transfer);

	BlockUtilsV2::SignTransaction(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey,
		writer.data(), writer.size());

	GenerationHashSeed seed;
	std::memset(seed.data(), 0x42, 32);

	EntityHeaderV2Reader reader(writer.data(), writer.size());
	Hash256 hash1 = EntityHasherV2::CalculateTransactionHash(reader, seed);

	// Same input → same hash
	Hash256 hash2 = EntityHasherV2::CalculateTransactionHash(reader, seed);
	ASSERT_TRUE(hash1 == hash2);

	// Different seed → different hash
	GenerationHashSeed seed2;
	std::memset(seed2.data(), 0x99, 32);
	Hash256 hash3 = EntityHasherV2::CalculateTransactionHash(reader, seed2);
	ASSERT_TRUE(hash1 != hash3);
}

// ============================================================================
// Test 9: Address derivation from ML-DSA-65 public key
// ============================================================================

TEST(MlDsa65_AddressV2_Derivation) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	Address addr = AddressV2::PublicKeyToAddress(pubKey, NetworkIdentifier::Mainnet, CryptoScheme::Ml_Dsa_65);

	// Network byte should be Mainnet XOR with ML_DSA_65(0x01) at byte 1
	ASSERT_EQ(static_cast<uint8_t>(NetworkIdentifier::Mainnet), addr.data()[0]);

	// Deterministic — same key → same address
	Address addr2 = AddressV2::PublicKeyToAddress(pubKey, NetworkIdentifier::Mainnet, CryptoScheme::Ml_Dsa_65);
	ASSERT_TRUE(addr == addr2);

	// Different key → different address
	auto [privKey2, pubKey2] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);
	Address addr3 = AddressV2::PublicKeyToAddress(pubKey2, NetworkIdentifier::Mainnet, CryptoScheme::Ml_Dsa_65);
	ASSERT_TRUE(addr != addr3);
}

// ============================================================================
// Test 10: Address — different network produces different address
// ============================================================================

TEST(MlDsa65_AddressV2_DifferentNetworks) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	Address mainnet = AddressV2::PublicKeyToAddress(pubKey, NetworkIdentifier::Mainnet, CryptoScheme::Ml_Dsa_65);
	Address testnet = AddressV2::PublicKeyToAddress(pubKey, NetworkIdentifier::Testnet, CryptoScheme::Ml_Dsa_65);

	ASSERT_TRUE(mainnet != testnet);
	ASSERT_EQ(0x68u, mainnet.data()[0]);
	ASSERT_EQ(0x98u, testnet.data()[0]);
}

// ============================================================================
// Test 11: Complete end-to-end — keygen → tx build → sign → hash → verify
// ============================================================================

TEST(MlDsa65_EndToEnd_Pipeline) {
	CryptoProviderRegistry registry;

	// 1. Generate key pair
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	// 2. Derive address
	Address addr = AddressV2::PublicKeyToAddress(pubKey, NetworkIdentifier::Mainnet, CryptoScheme::Ml_Dsa_65);

	// 3. Build V2 transaction buffer
	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);
	uint32_t payloadSize = 48;
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 16 + payloadSize);

	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ml_Dsa_65);
	writer.setSignerPublicKey(pubKey.data(), pubKey.size());
	writer.setVersion(1);
	writer.setNetwork(NetworkIdentifier::Mainnet);
	writer.setType(EntityType::Transfer);

	uint64_t fee = 50000, deadline = 123456789;
	writer.writeAt(bodyEnd, reinterpret_cast<const uint8_t*>(&fee), 8);
	writer.writeAt(bodyEnd + 8, reinterpret_cast<const uint8_t*>(&deadline), 8);

	// Recipient address in payload
	writer.writeAt(bodyEnd + 16, addr.data(), 24);

	// 4. Sign
	BlockUtilsV2::SignTransaction(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey,
		writer.data(), writer.size());

	// 5. Hash
	GenerationHashSeed seed;
	std::memset(seed.data(), 0xAB, 32);
	EntityHeaderV2Reader reader(writer.data(), writer.size());
	Hash256 txHash = EntityHasherV2::CalculateTransactionHash(reader, seed);

	// Hash should be non-zero
	bool allZero = true;
	for (size_t i = 0; i < 32; ++i)
		if (txHash.data()[i] != 0) { allZero = false; break; }
	ASSERT_FALSE(allZero);

	// 6. Verify
	ASSERT_TRUE(BlockUtilsV2::VerifyTransactionSignature(registry, writer.data(), writer.size()));

	std::cout << std::endl << "    End-to-end pipeline: keygen → address → tx build → sign → hash → verify ✓" << std::endl << "    ";
}

// ============================================================================
// Test 12: Performance benchmark
// ============================================================================

TEST(MlDsa65_Performance_Benchmark) {
	CryptoProviderRegistry registry;
	auto [privKey, pubKey] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	uint8_t message[256];
	std::memset(message, 0x42, sizeof(message));
	RawBuffer buf(message, sizeof(message));

	constexpr int iterations = 100;

	// Sign benchmark
	auto signStart = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < iterations; ++i) {
		CryptoBuffer sig;
		SignV2(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey, buf, sig);
	}
	auto signEnd = std::chrono::high_resolution_clock::now();
	auto signUs = std::chrono::duration_cast<std::chrono::microseconds>(signEnd - signStart).count();

	// Verify benchmark
	CryptoBuffer signature;
	SignV2(registry, CryptoScheme::Ml_Dsa_65, privKey, pubKey, buf, signature);

	auto verifyStart = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < iterations; ++i)
		VerifyV2(registry, CryptoScheme::Ml_Dsa_65, pubKey, buf, signature);
	auto verifyEnd = std::chrono::high_resolution_clock::now();
	auto verifyUs = std::chrono::duration_cast<std::chrono::microseconds>(verifyEnd - verifyStart).count();

	std::cout << std::endl;
	std::cout << "    SignV2:   " << (signUs / iterations) << " µs/op  (" << iterations << " iterations)" << std::endl;
	std::cout << "    VerifyV2: " << (verifyUs / iterations) << " µs/op (" << iterations << " iterations)" << std::endl;
	std::cout << "    ";
}

// ============================================================================
// Main
// ============================================================================

int main() {
	std::cout << "\n=== Phase 3: Core Integration V2 Tests (ML-DSA-65 via liboqs) ===" << std::endl;
	std::cout << std::endl;

	std::cout << "\n=== Results ===" << std::endl;
	std::cout << "Total: " << g_testCount << "  Passed: " << g_passCount << "  Failed: " << g_failCount << std::endl;

	if (g_failCount > 0) {
		std::cout << "\n*** FAILURES DETECTED ***" << std::endl;
		return 1;
	}

	std::cout << "\nAll tests passed!" << std::endl;
	return 0;
}
