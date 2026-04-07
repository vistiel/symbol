/**
*** Phase 4: Cache & State V2 — Standalone Integration Tests
***
*** Tests the V2 notification, validation, batch verification, and account state
*** extensions that bridge Phase 1-3 crypto primitives with the catapult processing pipeline.
***
*** Components tested:
***   1. SignatureNotificationV2 — variable-length notification creation
***   2. SignatureValidatorV2 — CryptoProviderRegistry-based validation
***   3. BatchSignatureConsumerV2 — batch capture and verification
***   4. AccountStateV2Extension — variable-length public key storage + serialization
***   5. NotificationPublisherV2 — V2 entity → V2 notification conversion
***   6. End-to-end pipeline: entity build → notification → validation → state
***
*** Compile:
***   g++ -std=c++17 -O2 -I/usr/local/include -o cache_v2_test CacheStateV2Tests.cpp \
***       -L/usr/local/lib -loqs
***   LD_LIBRARY_PATH=/usr/local/lib ./cache_v2_test
**/

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>
#include <functional>

// ============================================================================
// Minimal type stubs (same as Phase 3 tests)
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
	struct GenerationHashSeed_tag { static constexpr size_t Size = 32; };
	struct Address_tag { static constexpr size_t Size = 24; };

	using Signature = utils::ByteArray<Signature_tag>;
	using Key = utils::ByteArray<Key_tag>;
	using Hash256 = utils::ByteArray<Hash256_tag>;
	using GenerationHashSeed = utils::ByteArray<GenerationHashSeed_tag>;
	using Address = utils::ByteArray<Address_tag>;

	using Height = uint64_t;
	template<typename T> using consumer = std::function<void(T, size_t)>;
}

namespace catapult { namespace model {
	enum class NetworkIdentifier : uint8_t { Mainnet = 0x68, Testnet = 0x98 };
	enum class EntityType : uint16_t { Transfer = 0x4154, Block_Normal = 0x8143 };
}}

// Validation result stub
namespace catapult { namespace validators {
	enum class ValidationResult : uint32_t { Success = 0, Failure = 1 };
	constexpr auto Failure_Signature_Not_Verifiable = ValidationResult::Failure;
}}

// ============================================================================
// Crypto stubs and real ML-DSA-65 implementation
// ============================================================================

namespace catapult { namespace crypto {
	enum class CryptoScheme : uint8_t { Ed25519 = 0x00, Ml_Dsa_65 = 0x01 };

	class CryptoBuffer {
	public:
		CryptoBuffer() = default;
		explicit CryptoBuffer(size_t size) : m_data(size) {}
		CryptoBuffer(const uint8_t* p, size_t s) : m_data(p, p + s) {}
		const uint8_t* data() const { return m_data.data(); }
		uint8_t* data() { return m_data.data(); }
		size_t size() const { return m_data.size(); }
		bool empty() const { return m_data.empty(); }
		void resize(size_t s) { m_data.resize(s); }
		bool operator==(const CryptoBuffer& rhs) const { return m_data == rhs.m_data; }
		bool operator!=(const CryptoBuffer& rhs) const { return !(*this == rhs); }
	private:
		std::vector<uint8_t> m_data;
	};

	class SecureCryptoBuffer {
	public:
		SecureCryptoBuffer() = default;
		explicit SecureCryptoBuffer(size_t s) : m_data(s) {}
		SecureCryptoBuffer(SecureCryptoBuffer&& rhs) noexcept : m_data(std::move(rhs.m_data)) {}
		SecureCryptoBuffer& operator=(SecureCryptoBuffer&& rhs) noexcept { m_data = std::move(rhs.m_data); return *this; }
		~SecureCryptoBuffer() {
			if (!m_data.empty()) { volatile uint8_t* p = m_data.data(); for (size_t i = 0; i < m_data.size(); ++i) p[i] = 0; }
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

	struct SignatureInputV2 {
		CryptoScheme Scheme;
		CryptoBuffer PublicKey;
		std::vector<RawBuffer> Buffers;
		CryptoBuffer Signature;
	};
}}

#include <oqs/oqs.h>

namespace catapult { namespace crypto {
	class MlDsa65SignatureProvider : public SignatureProvider {
	public:
		static constexpr size_t Public_Key_Size = 1952;
		static constexpr size_t Oqs_Secret_Key_Size = 4032;
		static constexpr size_t Private_Key_Size = Oqs_Secret_Key_Size + Public_Key_Size;
		static constexpr size_t Signature_Size = 3309;

		CryptoScheme scheme() const override { return CryptoScheme::Ml_Dsa_65; }
		const std::string& name() const override { static const std::string n = "ML-DSA-65"; return n; }
		size_t publicKeySize() const override { return Public_Key_Size; }
		size_t privateKeySize() const override { return Private_Key_Size; }
		size_t signatureSize() const override { return Signature_Size; }

		void extractPublicKey(const SecureCryptoBuffer& privKey, CryptoBuffer& pubKey) const override {
			pubKey.resize(Public_Key_Size);
			std::memcpy(pubKey.data(), privKey.data() + Oqs_Secret_Key_Size, Public_Key_Size);
		}
		void sign(const SecureCryptoBuffer& privKey, const CryptoBuffer&,
				const std::vector<RawBuffer>& bufs, CryptoBuffer& sig) const override {
			std::vector<uint8_t> msg;
			for (const auto& b : bufs) msg.insert(msg.end(), b.pData, b.pData + b.Size);
			sig.resize(Signature_Size);
			size_t sigLen = Signature_Size;
			if (OQS_SUCCESS != OQS_SIG_ml_dsa_65_sign(sig.data(), &sigLen, msg.data(), msg.size(), privKey.data()))
				throw std::runtime_error("ML-DSA-65 sign failed");
		}
		bool verify(const CryptoBuffer& pubKey, const std::vector<RawBuffer>& bufs, const CryptoBuffer& sig) const override {
			std::vector<uint8_t> msg;
			for (const auto& b : bufs) msg.insert(msg.end(), b.pData, b.pData + b.Size);
			return OQS_SUCCESS == OQS_SIG_ml_dsa_65_verify(msg.data(), msg.size(), sig.data(), sig.size(), pubKey.data());
		}
		void generatePrivateKey(SecureCryptoBuffer& privKey) const override {
			privKey = SecureCryptoBuffer(Private_Key_Size);
			if (OQS_SUCCESS != OQS_SIG_ml_dsa_65_keypair(privKey.data() + Oqs_Secret_Key_Size, privKey.data()))
				throw std::runtime_error("ML-DSA-65 keypair generation failed");
		}
	};

	class CryptoProviderRegistry {
	public:
		CryptoProviderRegistry() {
			m_sigProviders[CryptoScheme::Ml_Dsa_65] = std::make_shared<MlDsa65SignatureProvider>();
		}
		void registerSignatureProvider(std::shared_ptr<SignatureProvider> p) { m_sigProviders[p->scheme()] = std::move(p); }
		const SignatureProvider& signatureProvider(CryptoScheme s) const {
			auto it = m_sigProviders.find(s); if (it == m_sigProviders.end()) throw std::invalid_argument("unknown scheme");
			return *it->second;
		}
		bool hasSignatureProvider(CryptoScheme s) const { return m_sigProviders.count(s) > 0; }
	private:
		std::unordered_map<CryptoScheme, std::shared_ptr<SignatureProvider>> m_sigProviders;
	};

	inline void SignV2(const CryptoProviderRegistry& reg, CryptoScheme s, const SecureCryptoBuffer& sk,
			const CryptoBuffer& pk, const std::vector<RawBuffer>& bufs, CryptoBuffer& sig) {
		reg.signatureProvider(s).sign(sk, pk, bufs, sig);
	}
	inline void SignV2(const CryptoProviderRegistry& reg, CryptoScheme s, const SecureCryptoBuffer& sk,
			const CryptoBuffer& pk, const RawBuffer& buf, CryptoBuffer& sig) {
		SignV2(reg, s, sk, pk, std::vector<RawBuffer>{ buf }, sig);
	}
	inline bool VerifyV2(const CryptoProviderRegistry& reg, CryptoScheme s, const CryptoBuffer& pk,
			const std::vector<RawBuffer>& bufs, const CryptoBuffer& sig) {
		return reg.signatureProvider(s).verify(pk, bufs, sig);
	}
	inline bool VerifyV2(const CryptoProviderRegistry& reg, CryptoScheme s, const CryptoBuffer& pk,
			const RawBuffer& buf, const CryptoBuffer& sig) {
		return VerifyV2(reg, s, pk, std::vector<RawBuffer>{ buf }, sig);
	}
	inline std::pair<std::vector<bool>, bool> VerifyMultiV2(
			const CryptoProviderRegistry& reg, const SignatureInputV2* pIn, size_t cnt) {
		std::vector<bool> r(cnt); bool ok = true;
		for (size_t i = 0; i < cnt; ++i) {
			r[i] = VerifyV2(reg, pIn[i].Scheme, pIn[i].PublicKey, pIn[i].Buffers, pIn[i].Signature);
			if (!r[i]) ok = false;
		}
		return { std::move(r), ok };
	}
	inline std::pair<SecureCryptoBuffer, CryptoBuffer> GenerateKeyPairV2(const CryptoProviderRegistry& reg, CryptoScheme s) {
		const auto& p = reg.signatureProvider(s);
		SecureCryptoBuffer sk; p.generatePrivateKey(sk);
		CryptoBuffer pk; p.extractPublicKey(sk, pk);
		return { std::move(sk), std::move(pk) };
	}
}}

// ============================================================================
// SHA3-256 stub
// ============================================================================

namespace catapult { namespace crypto {
	inline void Sha3_256(const RawBuffer& input, Hash256& output) {
		std::memset(output.data(), 0, Hash256::Size);
		for (size_t i = 0; i < input.Size; ++i) {
			output.data()[i % 32] ^= input.pData[i];
			output.data()[(i + 13) % 32] ^= (input.pData[i] * 7 + 0x5A);
		}
	}
}}

// ============================================================================
// V2 Entity Header (from Phase 2)
// ============================================================================

namespace catapult { namespace model {
	struct CryptoFieldSizes { size_t signatureSize; size_t publicKeySize; };
	inline CryptoFieldSizes GetCryptoFieldSizes(crypto::CryptoScheme s) {
		switch (s) {
		case crypto::CryptoScheme::Ed25519: return { 64, 32 };
		case crypto::CryptoScheme::Ml_Dsa_65: return { 3309, 1952 };
		default: throw std::invalid_argument("unknown scheme");
		}
	}

	namespace EntityHeaderV2Layout {
		constexpr size_t CryptoSchemeId_Offset = 4;
		constexpr size_t Variable_Fields_Offset = 8;
		inline constexpr size_t SignatureOffset() { return Variable_Fields_Offset; }
		inline size_t SignerPublicKeyOffset(size_t sigSize) { return Variable_Fields_Offset + sigSize; }
		inline size_t HeaderSize(size_t sigSize, size_t keySize) { return Variable_Fields_Offset + sigSize + keySize + sizeof(uint32_t); }
		inline size_t VersionOffset(size_t s, size_t k) { return HeaderSize(s, k); }
		inline size_t NetworkOffset(size_t s, size_t k) { return VersionOffset(s, k) + 1; }
		inline size_t TypeOffset(size_t s, size_t k) { return NetworkOffset(s, k) + 1; }
		inline size_t EntityBodyEndOffset(size_t s, size_t k) { return TypeOffset(s, k) + 2; }
		inline size_t HeaderSize(crypto::CryptoScheme scheme) { auto f = GetCryptoFieldSizes(scheme); return HeaderSize(f.signatureSize, f.publicKeySize); }
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
		size_t headerSize() const { return EntityHeaderV2Layout::HeaderSize(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize); }
		RawBuffer signature() const { return { m_pData + EntityHeaderV2Layout::SignatureOffset(), m_fieldSizes.signatureSize }; }
		RawBuffer signerPublicKey() const {
			return { m_pData + EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize), m_fieldSizes.publicKeySize };
		}
		RawBuffer dataBuffer() const {
			auto h = headerSize(); auto s = size();
			if (s <= h) return { nullptr, 0 };
			return { m_pData + h, s - h };
		}
		const uint8_t* data() const { return m_pData; }
		size_t dataSize() const { return m_dataSize; }
	private:
		const uint8_t* m_pData; size_t m_dataSize;
		crypto::CryptoScheme m_scheme; CryptoFieldSizes m_fieldSizes;
	};

	class EntityHeaderV2Writer {
	public:
		EntityHeaderV2Writer(uint32_t totalSize, crypto::CryptoScheme scheme)
				: m_buffer(totalSize, 0), m_scheme(scheme), m_fieldSizes(GetCryptoFieldSizes(scheme)) {
			std::memcpy(m_buffer.data(), &totalSize, 4);
			m_buffer[EntityHeaderV2Layout::CryptoSchemeId_Offset] = static_cast<uint8_t>(scheme);
		}
		void setSignature(const uint8_t* p, size_t s) { std::memcpy(m_buffer.data() + EntityHeaderV2Layout::SignatureOffset(), p, s); }
		void setSignerPublicKey(const uint8_t* p, size_t s) {
			std::memcpy(m_buffer.data() + EntityHeaderV2Layout::SignerPublicKeyOffset(m_fieldSizes.signatureSize), p, s);
		}
		void setVersion(uint8_t v) { m_buffer[EntityHeaderV2Layout::VersionOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)] = v; }
		void setNetwork(NetworkIdentifier n) { m_buffer[EntityHeaderV2Layout::NetworkOffset(m_fieldSizes.signatureSize, m_fieldSizes.publicKeySize)] = static_cast<uint8_t>(n); }
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
	private:
		std::vector<uint8_t> m_buffer; crypto::CryptoScheme m_scheme; CryptoFieldSizes m_fieldSizes;
	};
}}

// BlockUtilsV2 inline (from Phase 3)
namespace catapult { namespace model { namespace BlockUtilsV2 {
	inline void SignTransaction(const crypto::CryptoProviderRegistry& reg, crypto::CryptoScheme scheme,
			const crypto::SecureCryptoBuffer& sk, const crypto::CryptoBuffer& pk,
			uint8_t* pBuf, size_t txSize) {
		EntityHeaderV2Reader reader(pBuf, txSize);
		auto dataBuf = reader.dataBuffer();
		crypto::CryptoBuffer sig;
		crypto::SignV2(reg, scheme, sk, pk, dataBuf, sig);
		std::memcpy(pBuf + EntityHeaderV2Layout::SignatureOffset(), sig.data(), sig.size());
	}
	inline bool VerifyTransactionSignature(const crypto::CryptoProviderRegistry& reg,
			const uint8_t* pBuf, size_t txSize) {
		EntityHeaderV2Reader reader(pBuf, txSize);
		auto sigBuf = reader.signature(); auto keyBuf = reader.signerPublicKey();
		crypto::CryptoBuffer pk(keyBuf.pData, keyBuf.Size);
		crypto::CryptoBuffer sig(sigBuf.pData, sigBuf.Size);
		return crypto::VerifyV2(reg, reader.cryptoScheme(), pk, reader.dataBuffer(), sig);
	}
}}}

// ============================================================================
// Phase 4 inline implementations (from new header files)
// ============================================================================

// --- Notification stubs ---
namespace catapult { namespace model {
	struct Notification { uint32_t Type; size_t Size; };
	constexpr uint32_t Core_Signature_V2_Notification = 0x00430017;
	constexpr uint32_t Core_Register_Account_Public_Key_V2_Notification = 0x00FF0018;

	struct SignatureNotificationV2 : public Notification {
		enum class ReplayProtectionMode { Enabled, Disabled };
		static constexpr auto Notification_Type = Core_Signature_V2_Notification;

		SignatureNotificationV2(crypto::CryptoScheme cryptoScheme, const RawBuffer& signerPublicKey,
				const RawBuffer& signature, const RawBuffer& data,
				ReplayProtectionMode dataReplayProtectionMode = ReplayProtectionMode::Disabled)
				: Notification{Notification_Type, sizeof(SignatureNotificationV2)}
				, CryptoScheme(cryptoScheme), SignerPublicKey(signerPublicKey)
				, Signature(signature), Data(data), DataReplayProtectionMode(dataReplayProtectionMode)
		{}

		crypto::CryptoScheme CryptoScheme;
		RawBuffer SignerPublicKey;
		RawBuffer Signature;
		RawBuffer Data;
		ReplayProtectionMode DataReplayProtectionMode;
	};

	struct AccountPublicKeyNotificationV2 : public Notification {
		static constexpr auto Notification_Type = Core_Register_Account_Public_Key_V2_Notification;
		AccountPublicKeyNotificationV2(crypto::CryptoScheme cryptoScheme, const RawBuffer& publicKey)
				: Notification{Notification_Type, sizeof(AccountPublicKeyNotificationV2)}
				, CryptoScheme(cryptoScheme), PublicKey(publicKey)
		{}
		crypto::CryptoScheme CryptoScheme;
		RawBuffer PublicKey;
	};
}}

// --- SignatureValidatorV2 ---
namespace catapult { namespace validators {
	class SignatureValidatorV2 {
	public:
		SignatureValidatorV2(const std::shared_ptr<const crypto::CryptoProviderRegistry>& pReg,
				const GenerationHashSeed& seed)
				: m_pRegistry(pReg), m_generationHashSeed(seed) {}

		ValidationResult validate(const model::SignatureNotificationV2& notification) const {
			if (!m_pRegistry->hasSignatureProvider(notification.CryptoScheme))
				return Failure_Signature_Not_Verifiable;
			const auto& provider = m_pRegistry->signatureProvider(notification.CryptoScheme);
			if (notification.SignerPublicKey.Size != provider.publicKeySize())
				return Failure_Signature_Not_Verifiable;
			if (notification.Signature.Size != provider.signatureSize())
				return Failure_Signature_Not_Verifiable;
			crypto::CryptoBuffer pk(notification.SignerPublicKey.pData, notification.SignerPublicKey.Size);
			crypto::CryptoBuffer sig(notification.Signature.pData, notification.Signature.Size);
			std::vector<RawBuffer> bufs;
			if (model::SignatureNotificationV2::ReplayProtectionMode::Enabled == notification.DataReplayProtectionMode)
				bufs.push_back(RawBuffer{ m_generationHashSeed.data(), GenerationHashSeed::Size });
			bufs.push_back(notification.Data);
			return crypto::VerifyV2(*m_pRegistry, notification.CryptoScheme, pk, bufs, sig)
				? ValidationResult::Success : Failure_Signature_Not_Verifiable;
		}
	private:
		std::shared_ptr<const crypto::CryptoProviderRegistry> m_pRegistry;
		GenerationHashSeed m_generationHashSeed;
	};
}}

// --- BatchSignatureConsumerV2 ---
namespace catapult { namespace consumers {
	class SignatureCapturingNotificationSubscriberV2 {
	public:
		explicit SignatureCapturingNotificationSubscriberV2(const GenerationHashSeed& seed)
				: m_generationHashSeed(seed), m_entityIndex(0) {}
		const auto& notificationToEntityIndexMap() const { return m_map; }
		const auto& inputs() const { return m_inputs; }
		size_t size() const { return m_inputs.size(); }
		void next() { ++m_entityIndex; }
		void add(const model::SignatureNotificationV2& notification) {
			m_map.push_back(m_entityIndex);
			crypto::SignatureInputV2 input;
			input.Scheme = notification.CryptoScheme;
			input.PublicKey = crypto::CryptoBuffer(notification.SignerPublicKey.pData, notification.SignerPublicKey.Size);
			input.Signature = crypto::CryptoBuffer(notification.Signature.pData, notification.Signature.Size);
			if (model::SignatureNotificationV2::ReplayProtectionMode::Enabled == notification.DataReplayProtectionMode)
				input.Buffers.push_back(RawBuffer{ m_generationHashSeed.data(), GenerationHashSeed::Size });
			input.Buffers.push_back(notification.Data);
			m_inputs.push_back(std::move(input));
		}
	private:
		GenerationHashSeed m_generationHashSeed;
		size_t m_entityIndex;
		std::vector<size_t> m_map;
		std::vector<crypto::SignatureInputV2> m_inputs;
	};

	inline std::pair<std::vector<bool>, bool> BatchVerifyV2(
			const crypto::CryptoProviderRegistry& reg, const std::vector<crypto::SignatureInputV2>& inputs) {
		if (inputs.empty()) return { {}, true };
		return crypto::VerifyMultiV2(reg, inputs.data(), inputs.size());
	}
	inline bool BatchVerifyV2ShortCircuit(
			const crypto::CryptoProviderRegistry& reg, const std::vector<crypto::SignatureInputV2>& inputs) {
		for (const auto& in : inputs) {
			crypto::CryptoBuffer pk = in.PublicKey; crypto::CryptoBuffer sig = in.Signature;
			if (!crypto::VerifyV2(reg, in.Scheme, pk, in.Buffers, sig)) return false;
		}
		return true;
	}
}}

// --- AccountStateV2Extension ---
namespace catapult { namespace state {
	struct AccountStateV2Extension {
		AccountStateV2Extension(crypto::CryptoScheme s, const crypto::CryptoBuffer& k)
				: CryptoScheme(s), FullPublicKey(k) {}
		AccountStateV2Extension(crypto::CryptoScheme s, const uint8_t* p, size_t n)
				: CryptoScheme(s), FullPublicKey(p, n) {}
		crypto::CryptoScheme CryptoScheme;
		crypto::CryptoBuffer FullPublicKey;
	};

	inline Key ComputePublicKeyHash(const crypto::CryptoBuffer& fullPk, crypto::CryptoScheme scheme) {
		Key result{};
		if (scheme == crypto::CryptoScheme::Ed25519 && fullPk.size() == 32) {
			std::memcpy(result.data(), fullPk.data(), 32);
		} else {
			Hash256 hash;
			crypto::Sha3_256(RawBuffer{ fullPk.data(), fullPk.size() }, hash);
			std::memcpy(result.data(), hash.data(), 32);
		}
		return result;
	}

	inline std::vector<uint8_t> SerializeV2Extension(const AccountStateV2Extension& ext) {
		std::vector<uint8_t> buf(1 + 4 + ext.FullPublicKey.size());
		buf[0] = static_cast<uint8_t>(ext.CryptoScheme);
		auto ks = static_cast<uint32_t>(ext.FullPublicKey.size());
		std::memcpy(buf.data() + 1, &ks, 4);
		std::memcpy(buf.data() + 5, ext.FullPublicKey.data(), ext.FullPublicKey.size());
		return buf;
	}

	inline std::optional<AccountStateV2Extension> DeserializeV2Extension(const uint8_t* p, size_t n) {
		if (n < 5) return std::nullopt;
		auto scheme = static_cast<crypto::CryptoScheme>(p[0]);
		uint32_t ks = 0; std::memcpy(&ks, p + 1, 4);
		if (n < 5 + ks || ks > 65536) return std::nullopt;
		return AccountStateV2Extension(scheme, p + 5, ks);
	}
}}

// --- NotificationPublisherV2 ---
namespace catapult { namespace model { namespace NotificationPublisherV2 {
	inline SignatureNotificationV2 CreateBlockSignatureNotification(const EntityHeaderV2Reader& reader) {
		return SignatureNotificationV2(reader.cryptoScheme(), reader.signerPublicKey(), reader.signature(),
			reader.dataBuffer(), SignatureNotificationV2::ReplayProtectionMode::Disabled);
	}
	inline SignatureNotificationV2 CreateTransactionSignatureNotification(
			const EntityHeaderV2Reader& reader, const RawBuffer& dataBuffer) {
		return SignatureNotificationV2(reader.cryptoScheme(), reader.signerPublicKey(), reader.signature(),
			dataBuffer, SignatureNotificationV2::ReplayProtectionMode::Enabled);
	}
	inline AccountPublicKeyNotificationV2 CreateAccountPublicKeyNotification(const EntityHeaderV2Reader& reader) {
		return AccountPublicKeyNotificationV2(reader.cryptoScheme(), reader.signerPublicKey());
	}
	inline bool IsV2Entity(const uint8_t* pBuf, size_t bufSize) {
		return bufSize >= 5 && pBuf[4] != 0x00;
	}
	inline crypto::CryptoScheme GetCryptoScheme(const uint8_t* pBuf, size_t bufSize) {
		if (bufSize < 5) return crypto::CryptoScheme::Ed25519;
		return static_cast<crypto::CryptoScheme>(pBuf[4]);
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
	std::ostringstream s; s << "expected " << _e << " got " << _a << " [line " << __LINE__ << "]"; \
	throw std::runtime_error(s.str()); } } while(0)
#define ASSERT_TRUE(c) do { if(!(c)) { std::ostringstream s; s << #c << " [line " << __LINE__ << "]"; \
	throw std::runtime_error(s.str()); } } while(0)
#define ASSERT_FALSE(c) ASSERT_TRUE(!(c))

using namespace catapult;
using namespace catapult::crypto;
using namespace catapult::model;
using namespace catapult::validators;
using namespace catapult::consumers;
using namespace catapult::state;

// ============================================================================
// Helper: build and sign a V2 ML-DSA-65 transaction
// ============================================================================

struct SignedV2Transaction {
	std::vector<uint8_t> buffer;
	CryptoBuffer publicKey;
	SecureCryptoBuffer privateKey;
};

SignedV2Transaction BuildSignedMlDsa65Transaction(
		const CryptoProviderRegistry& reg, uint32_t payloadSize = 32) {
	auto [sk, pk] = GenerateKeyPairV2(reg, CryptoScheme::Ml_Dsa_65);
	auto bodyEnd = EntityHeaderV2Layout::EntityBodyEndOffset(3309, 1952);
	uint32_t totalSize = static_cast<uint32_t>(bodyEnd + 16 + payloadSize);

	EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ml_Dsa_65);
	writer.setSignerPublicKey(pk.data(), pk.size());
	writer.setVersion(1);
	writer.setNetwork(NetworkIdentifier::Mainnet);
	writer.setType(EntityType::Transfer);

	uint64_t fee = 100000, deadline = 9999999;
	writer.writeAt(bodyEnd, reinterpret_cast<const uint8_t*>(&fee), 8);
	writer.writeAt(bodyEnd + 8, reinterpret_cast<const uint8_t*>(&deadline), 8);
	for (uint32_t i = 0; i < payloadSize; ++i)
		writer.data()[bodyEnd + 16 + i] = static_cast<uint8_t>(i ^ 0xAB);

	BlockUtilsV2::SignTransaction(reg, CryptoScheme::Ml_Dsa_65, sk, pk, writer.data(), writer.size());

	std::vector<uint8_t> buf(writer.data(), writer.data() + writer.size());
	return { std::move(buf), std::move(pk), std::move(sk) };
}

// ============================================================================
// Test 1: SignatureNotificationV2 creation from V2 entity
// ============================================================================

TEST(NotificationV2_CreateFromEntity) {
	CryptoProviderRegistry registry;
	auto tx = BuildSignedMlDsa65Transaction(registry);

	// Create notification from entity buffer
	EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());
	auto notification = NotificationPublisherV2::CreateBlockSignatureNotification(reader);

	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ml_Dsa_65), static_cast<uint8_t>(notification.CryptoScheme));
	ASSERT_EQ(1952u, notification.SignerPublicKey.Size);
	ASSERT_EQ(3309u, notification.Signature.Size);
	ASSERT_TRUE(notification.Data.Size > 0);
}

// ============================================================================
// Test 2: SignatureNotificationV2 carries correct data references
// ============================================================================

TEST(NotificationV2_ZeroCopyReferences) {
	CryptoProviderRegistry registry;
	auto tx = BuildSignedMlDsa65Transaction(registry);
	EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());
	auto notification = NotificationPublisherV2::CreateBlockSignatureNotification(reader);

	// The notification should reference data within the original buffer (zero-copy)
	auto bufStart = tx.buffer.data();
	auto bufEnd = tx.buffer.data() + tx.buffer.size();
	ASSERT_TRUE(notification.SignerPublicKey.pData >= bufStart && notification.SignerPublicKey.pData < bufEnd);
	ASSERT_TRUE(notification.Signature.pData >= bufStart && notification.Signature.pData < bufEnd);
}

// ============================================================================
// Test 3: SignatureValidatorV2 — valid signature accepted
// ============================================================================

TEST(ValidatorV2_ValidSignature_Accepted) {
	auto pReg = std::make_shared<CryptoProviderRegistry>();
	GenerationHashSeed seed; std::memset(seed.data(), 0x42, 32);
	SignatureValidatorV2 validator(pReg, seed);

	auto tx = BuildSignedMlDsa65Transaction(*pReg);
	EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());

	// Block-style notification (no replay protection) — should validate
	auto notif = NotificationPublisherV2::CreateBlockSignatureNotification(reader);
	ASSERT_EQ(static_cast<uint32_t>(ValidationResult::Success), static_cast<uint32_t>(validator.validate(notif)));
}

// ============================================================================
// Test 4: SignatureValidatorV2 — tampered data rejected
// ============================================================================

TEST(ValidatorV2_TamperedData_Rejected) {
	auto pReg = std::make_shared<CryptoProviderRegistry>();
	GenerationHashSeed seed; std::memset(seed.data(), 0x42, 32);
	SignatureValidatorV2 validator(pReg, seed);

	auto tx = BuildSignedMlDsa65Transaction(*pReg);
	// Tamper with payload
	tx.buffer[tx.buffer.size() - 1] ^= 0xFF;

	EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());
	auto notif = NotificationPublisherV2::CreateBlockSignatureNotification(reader);
	ASSERT_EQ(static_cast<uint32_t>(Failure_Signature_Not_Verifiable), static_cast<uint32_t>(validator.validate(notif)));
}

// ============================================================================
// Test 5: SignatureValidatorV2 — wrong key size rejected
// ============================================================================

TEST(ValidatorV2_WrongKeySize_Rejected) {
	auto pReg = std::make_shared<CryptoProviderRegistry>();
	GenerationHashSeed seed;
	SignatureValidatorV2 validator(pReg, seed);

	// Create a fake notification with wrong key size
	uint8_t fakePk[100] = {};
	uint8_t fakeSig[3309] = {};
	uint8_t fakeData[32] = {};
	SignatureNotificationV2 notif(CryptoScheme::Ml_Dsa_65,
		RawBuffer(fakePk, 100),     // wrong size (should be 1952)
		RawBuffer(fakeSig, 3309),
		RawBuffer(fakeData, 32));

	ASSERT_EQ(static_cast<uint32_t>(Failure_Signature_Not_Verifiable), static_cast<uint32_t>(validator.validate(notif)));
}

// ============================================================================
// Test 6: SignatureValidatorV2 — unknown scheme rejected
// ============================================================================

TEST(ValidatorV2_UnknownScheme_Rejected) {
	auto pReg = std::make_shared<CryptoProviderRegistry>();
	GenerationHashSeed seed;
	SignatureValidatorV2 validator(pReg, seed);

	uint8_t fakePk[32] = {}; uint8_t fakeSig[64] = {}; uint8_t fakeData[32] = {};
	SignatureNotificationV2 notif(static_cast<CryptoScheme>(0xFF),
		RawBuffer(fakePk, 32), RawBuffer(fakeSig, 64), RawBuffer(fakeData, 32));

	ASSERT_EQ(static_cast<uint32_t>(Failure_Signature_Not_Verifiable), static_cast<uint32_t>(validator.validate(notif)));
}

// ============================================================================
// Test 7: SignatureValidatorV2 — transaction with replay protection
// ============================================================================

TEST(ValidatorV2_TransactionWithReplayProtection) {
	auto pReg = std::make_shared<CryptoProviderRegistry>();
	GenerationHashSeed seed; std::memset(seed.data(), 0xAB, 32);

	auto [sk, pk] = GenerateKeyPairV2(*pReg, CryptoScheme::Ml_Dsa_65);

	// Build transaction body (after header)
	uint8_t body[48]; for (int i = 0; i < 48; ++i) body[i] = static_cast<uint8_t>(i);

	// Sign with replay protection: Sign(seed || body)
	CryptoBuffer sig;
	std::vector<RawBuffer> bufs = {
		RawBuffer(seed.data(), GenerationHashSeed::Size),
		RawBuffer(body, sizeof(body))
	};
	SignV2(*pReg, CryptoScheme::Ml_Dsa_65, sk, pk, bufs, sig);

	// Create notification with replay protection enabled
	SignatureNotificationV2 notif(CryptoScheme::Ml_Dsa_65,
		RawBuffer(pk.data(), pk.size()),
		RawBuffer(sig.data(), sig.size()),
		RawBuffer(body, sizeof(body)),
		SignatureNotificationV2::ReplayProtectionMode::Enabled);

	SignatureValidatorV2 validator(pReg, seed);
	ASSERT_EQ(static_cast<uint32_t>(ValidationResult::Success), static_cast<uint32_t>(validator.validate(notif)));

	// Wrong seed should fail
	GenerationHashSeed wrongSeed; std::memset(wrongSeed.data(), 0x99, 32);
	SignatureValidatorV2 badValidator(pReg, wrongSeed);
	ASSERT_EQ(static_cast<uint32_t>(Failure_Signature_Not_Verifiable), static_cast<uint32_t>(badValidator.validate(notif)));
}

// ============================================================================
// Test 8: BatchSignatureConsumerV2 — capture notifications
// ============================================================================

TEST(BatchConsumerV2_CaptureNotifications) {
	CryptoProviderRegistry registry;
	GenerationHashSeed seed; std::memset(seed.data(), 0x42, 32);
	SignatureCapturingNotificationSubscriberV2 sub(seed);

	// Build 3 transactions and capture notifications
	for (int i = 0; i < 3; ++i) {
		auto tx = BuildSignedMlDsa65Transaction(registry, 32 + i * 8);
		EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());
		auto notif = NotificationPublisherV2::CreateBlockSignatureNotification(reader);
		sub.add(notif);
		sub.next();
	}

	ASSERT_EQ(3u, sub.size());
	ASSERT_EQ(3u, sub.inputs().size());
	ASSERT_EQ(3u, sub.notificationToEntityIndexMap().size());

	// Entity indices should be 0, 1, 2
	ASSERT_EQ(0u, sub.notificationToEntityIndexMap()[0]);
	ASSERT_EQ(1u, sub.notificationToEntityIndexMap()[1]);
	ASSERT_EQ(2u, sub.notificationToEntityIndexMap()[2]);
}

// ============================================================================
// Test 9: BatchSignatureConsumerV2 — batch verify all valid
// ============================================================================

TEST(BatchConsumerV2_BatchVerify_AllValid) {
	CryptoProviderRegistry registry;
	GenerationHashSeed seed;
	SignatureCapturingNotificationSubscriberV2 sub(seed);

	// Keep transactions alive so RawBuffer references remain valid
	std::vector<SignedV2Transaction> transactions;
	for (int i = 0; i < 5; ++i) {
		transactions.push_back(BuildSignedMlDsa65Transaction(registry));
		auto& tx = transactions.back();
		EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());
		auto notif = NotificationPublisherV2::CreateBlockSignatureNotification(reader);
		sub.add(notif);
		sub.next();
	}

	auto [results, allValid] = BatchVerifyV2(registry, sub.inputs());
	ASSERT_TRUE(allValid);
	ASSERT_EQ(5u, results.size());
	for (size_t i = 0; i < 5; ++i)
		ASSERT_TRUE(results[i]);
}

// ============================================================================
// Test 10: BatchSignatureConsumerV2 — batch verify with tampered signature
// ============================================================================

TEST(BatchConsumerV2_BatchVerify_WithTampered) {
	CryptoProviderRegistry registry;
	GenerationHashSeed seed;

	// Build 3 valid inputs — keep transactions alive
	std::vector<SignedV2Transaction> transactions;
	std::vector<crypto::SignatureInputV2> inputs;
	for (int i = 0; i < 3; ++i) {
		transactions.push_back(BuildSignedMlDsa65Transaction(registry));
		auto& tx = transactions.back();
		EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());

		crypto::SignatureInputV2 input;
		input.Scheme = CryptoScheme::Ml_Dsa_65;
		input.PublicKey = CryptoBuffer(reader.signerPublicKey().pData, reader.signerPublicKey().Size);
		input.Signature = CryptoBuffer(reader.signature().pData, reader.signature().Size);
		input.Buffers = { reader.dataBuffer() };
		inputs.push_back(std::move(input));
	}

	// Tamper with signature of index 1
	inputs[1].Signature.data()[0] ^= 0xFF;

	auto [results, allValid] = BatchVerifyV2(registry, inputs);
	ASSERT_FALSE(allValid);
	ASSERT_TRUE(results[0]);
	ASSERT_FALSE(results[1]);
	ASSERT_TRUE(results[2]);
}

// ============================================================================
// Test 11: BatchVerifyV2ShortCircuit — stops on first failure
// ============================================================================

TEST(BatchConsumerV2_ShortCircuit) {
	CryptoProviderRegistry registry;

	std::vector<SignedV2Transaction> transactions;
	std::vector<crypto::SignatureInputV2> inputs;
	for (int i = 0; i < 3; ++i) {
		transactions.push_back(BuildSignedMlDsa65Transaction(registry));
		auto& tx = transactions.back();
		EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());
		crypto::SignatureInputV2 input;
		input.Scheme = CryptoScheme::Ml_Dsa_65;
		input.PublicKey = CryptoBuffer(reader.signerPublicKey().pData, reader.signerPublicKey().Size);
		input.Signature = CryptoBuffer(reader.signature().pData, reader.signature().Size);
		input.Buffers = { reader.dataBuffer() };
		inputs.push_back(std::move(input));
	}

	// All valid
	ASSERT_TRUE(BatchVerifyV2ShortCircuit(registry, inputs));

	// Tamper
	inputs[0].Signature.data()[0] ^= 0xFF;
	ASSERT_FALSE(BatchVerifyV2ShortCircuit(registry, inputs));
}

// ============================================================================
// Test 12: AccountStateV2Extension — ML-DSA-65 key storage
// ============================================================================

TEST(AccountStateV2_MlDsa65_KeyStorage) {
	CryptoProviderRegistry registry;
	auto [sk, pk] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	AccountStateV2Extension ext(CryptoScheme::Ml_Dsa_65, pk);
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ml_Dsa_65), static_cast<uint8_t>(ext.CryptoScheme));
	ASSERT_EQ(1952u, ext.FullPublicKey.size());
	ASSERT_TRUE(ext.FullPublicKey == pk);
}

// ============================================================================
// Test 13: AccountStateV2Extension — ComputePublicKeyHash
// ============================================================================

TEST(AccountStateV2_ComputePublicKeyHash) {
	CryptoProviderRegistry registry;
	auto [sk, pk] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	Key hash = ComputePublicKeyHash(pk, CryptoScheme::Ml_Dsa_65);

	// Hash should be non-zero
	bool allZero = true;
	for (size_t i = 0; i < 32; ++i) if (hash.data()[i] != 0) { allZero = false; break; }
	ASSERT_FALSE(allZero);

	// Same key → same hash
	Key hash2 = ComputePublicKeyHash(pk, CryptoScheme::Ml_Dsa_65);
	ASSERT_TRUE(hash == hash2);

	// Different key → different hash
	auto [sk2, pk2] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);
	Key hash3 = ComputePublicKeyHash(pk2, CryptoScheme::Ml_Dsa_65);
	ASSERT_TRUE(hash != hash3);
}

// ============================================================================
// Test 14: AccountStateV2Extension — serialization round-trip
// ============================================================================

TEST(AccountStateV2_Serialization_RoundTrip) {
	CryptoProviderRegistry registry;
	auto [sk, pk] = GenerateKeyPairV2(registry, CryptoScheme::Ml_Dsa_65);

	AccountStateV2Extension ext(CryptoScheme::Ml_Dsa_65, pk);
	auto serialized = SerializeV2Extension(ext);

	// Expected size: 1 (scheme) + 4 (keySize) + 1952 (key) = 1957
	ASSERT_EQ(1957u, serialized.size());

	auto deserialized = DeserializeV2Extension(serialized.data(), serialized.size());
	ASSERT_TRUE(deserialized.has_value());
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ml_Dsa_65), static_cast<uint8_t>(deserialized->CryptoScheme));
	ASSERT_EQ(1952u, deserialized->FullPublicKey.size());
	ASSERT_TRUE(deserialized->FullPublicKey == pk);
}

// ============================================================================
// Test 15: AccountStateV2Extension — deserialization of truncated buffer
// ============================================================================

TEST(AccountStateV2_Deserialization_TruncatedBuffer) {
	// Too short for header
	uint8_t buf1[3] = { 0x01, 0x00, 0x00 };
	ASSERT_FALSE(DeserializeV2Extension(buf1, 3).has_value());

	// Header claims 100 bytes but only 10 available
	uint8_t buf2[10] = {};
	buf2[0] = 0x01;  // ML-DSA-65
	uint32_t keySize = 100;
	std::memcpy(buf2 + 1, &keySize, 4);
	ASSERT_FALSE(DeserializeV2Extension(buf2, 10).has_value());
}

// ============================================================================
// Test 16: AccountStateV2Extension — rejects oversized key
// ============================================================================

TEST(AccountStateV2_Deserialization_RejectsOversizedKey) {
	uint8_t buf[10] = {};
	buf[0] = 0x01;
	uint32_t keySize = 100000;  // > 65536 limit
	std::memcpy(buf + 1, &keySize, 4);
	ASSERT_FALSE(DeserializeV2Extension(buf, 10).has_value());
}

// ============================================================================
// Test 17: NotificationPublisherV2 — IsV2Entity detection
// ============================================================================

TEST(NotificationPublisherV2_IsV2Entity) {
	// Ed25519 entity (scheme 0x00) — should NOT be V2
	uint8_t ed25519Buf[8] = {};
	ed25519Buf[4] = 0x00;
	ASSERT_FALSE(NotificationPublisherV2::IsV2Entity(ed25519Buf, 8));

	// ML-DSA-65 entity (scheme 0x01) — should be V2
	uint8_t mldsaBuf[8] = {};
	mldsaBuf[4] = 0x01;
	ASSERT_TRUE(NotificationPublisherV2::IsV2Entity(mldsaBuf, 8));

	// Buffer too short
	ASSERT_FALSE(NotificationPublisherV2::IsV2Entity(ed25519Buf, 3));
}

// ============================================================================
// Test 18: NotificationPublisherV2 — GetCryptoScheme
// ============================================================================

TEST(NotificationPublisherV2_GetCryptoScheme) {
	uint8_t buf[8] = {};
	buf[4] = 0x01;
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ml_Dsa_65),
			  static_cast<uint8_t>(NotificationPublisherV2::GetCryptoScheme(buf, 8)));

	// Default for too-short buffer
	ASSERT_EQ(static_cast<uint8_t>(CryptoScheme::Ed25519),
			  static_cast<uint8_t>(NotificationPublisherV2::GetCryptoScheme(buf, 2)));
}

// ============================================================================
// Test 19: End-to-end pipeline: entity → notification → validator → account state
// ============================================================================

TEST(EndToEnd_EntityToNotificationToValidatorToState) {
	auto pReg = std::make_shared<CryptoProviderRegistry>();
	GenerationHashSeed seed; std::memset(seed.data(), 0x42, 32);

	// 1. Build signed V2 transaction
	auto tx = BuildSignedMlDsa65Transaction(*pReg);

	// 2. Detect V2 entity
	ASSERT_TRUE(NotificationPublisherV2::IsV2Entity(tx.buffer.data(), tx.buffer.size()));

	// 3. Create V2 notifications
	EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());
	auto sigNotif = NotificationPublisherV2::CreateBlockSignatureNotification(reader);
	auto acctNotif = NotificationPublisherV2::CreateAccountPublicKeyNotification(reader);

	// 4. Validate signature
	SignatureValidatorV2 validator(pReg, seed);
	ASSERT_EQ(static_cast<uint32_t>(ValidationResult::Success), static_cast<uint32_t>(validator.validate(sigNotif)));

	// 5. Create V2 account state extension
	crypto::CryptoBuffer fullPk(acctNotif.PublicKey.pData, acctNotif.PublicKey.Size);
	AccountStateV2Extension ext(acctNotif.CryptoScheme, fullPk);

	// 6. Compute public key hash for cache lookup
	Key keyHash = ComputePublicKeyHash(ext.FullPublicKey, ext.CryptoScheme);

	// 7. Verify the key hash is deterministic
	Key keyHash2 = ComputePublicKeyHash(fullPk, CryptoScheme::Ml_Dsa_65);
	ASSERT_TRUE(keyHash == keyHash2);

	// 8. Serialize and deserialize extension
	auto serialized = SerializeV2Extension(ext);
	auto deserialized = DeserializeV2Extension(serialized.data(), serialized.size());
	ASSERT_TRUE(deserialized.has_value());
	ASSERT_TRUE(deserialized->FullPublicKey == fullPk);

	std::cout << std::endl
		<< "    Pipeline: entity → V2 detect → notification → validate → state → serialize ✓" << std::endl
		<< "    ";
}

// ============================================================================
// Test 20: Performance — batch verify throughput
// ============================================================================

TEST(Performance_BatchVerify_Throughput) {
	CryptoProviderRegistry registry;

	constexpr size_t numTx = 50;
	std::vector<crypto::SignatureInputV2> inputs;
	std::vector<SignedV2Transaction> transactions;

	for (size_t i = 0; i < numTx; ++i) {
		transactions.push_back(BuildSignedMlDsa65Transaction(registry));
		auto& tx = transactions.back();
		EntityHeaderV2Reader reader(tx.buffer.data(), tx.buffer.size());

		crypto::SignatureInputV2 input;
		input.Scheme = CryptoScheme::Ml_Dsa_65;
		input.PublicKey = CryptoBuffer(reader.signerPublicKey().pData, reader.signerPublicKey().Size);
		input.Signature = CryptoBuffer(reader.signature().pData, reader.signature().Size);
		input.Buffers = { reader.dataBuffer() };
		inputs.push_back(std::move(input));
	}

	auto start = std::chrono::high_resolution_clock::now();
	auto [results, allValid] = BatchVerifyV2(registry, inputs);
	auto end = std::chrono::high_resolution_clock::now();
	auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

	ASSERT_TRUE(allValid);
	std::cout << std::endl;
	std::cout << "    BatchVerifyV2: " << numTx << " ML-DSA-65 signatures in " << us << " µs"
			  << " (" << (us / numTx) << " µs/verify)" << std::endl;
	std::cout << "    ";
}

// ============================================================================
// Main
// ============================================================================

#include <chrono>

int main() {
	std::cout << "\n=== Phase 4: Cache & State V2 Integration Tests (ML-DSA-65 via liboqs) ===" << std::endl;
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
