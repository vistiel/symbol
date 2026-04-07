// AccountState V1→V2 Migration Utility
//
// Provides functions to upgrade AccountState storage from V1 (Ed25519-only,
// fixed 32-byte public keys) to V2 (variable-length public keys with
// CryptoScheme-aware extensions).
//
// This is a header-only utility intended to be called during a hard-fork
// activation to upgrade the account state cache.
//
// Build (standalone test):
//   g++ -std=c++17 -O2 -I/usr/local/include \
//       -DMIGRATION_STANDALONE_TEST \
//       -o migrate_test tools/pqc/MigrateAccountState.cpp \
//       -L/usr/local/lib -loqs
//
//   LD_LIBRARY_PATH=/usr/local/lib ./migrate_test

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace catapult { namespace tools { namespace migration {

	// ---- Schema Version Constants ----

	constexpr uint8_t State_Version_V1 = 1;
	constexpr uint8_t State_Version_V2 = 2;

	// ---- CryptoScheme enum (mirrors types.cats) ----

	enum class CryptoScheme : uint8_t {
		Ed25519 = 0x00,
		Ml_Dsa_65 = 0x01
	};

	// ---- V1 AccountState Serialized Layout ----
	// (Simplified — full catapult AccountState has more fields;
	//  this focuses on the public key migration aspect)
	//
	// [Address: 24 bytes]
	// [AddressHeight: 8 bytes]
	// [PublicKey: 32 bytes]
	// [PublicKeyHeight: 8 bytes]
	// [AccountType: 1 byte]
	// ... (supplemental keys, activity buckets, balances)

	struct V1PublicKeyRecord {
		std::array<uint8_t, 24> Address;
		uint64_t AddressHeight;
		std::array<uint8_t, 32> PublicKey;
		uint64_t PublicKeyHeight;
		uint8_t AccountType;
	};

	// ---- V2 AccountState Extension ----
	// Appended after V1 fields when State_Version = 2:
	//
	// [CryptoScheme: 1 byte]
	// [FullPublicKeySize: 4 bytes (uint32)]
	// [FullPublicKey: FullPublicKeySize bytes]

	struct V2Extension {
		CryptoScheme Scheme;
		std::vector<uint8_t> FullPublicKey;
	};

	// ---- Migration Result ----

	struct MigrationResult {
		uint64_t totalAccounts;
		uint64_t upgradedAccounts;     // Ed25519 accounts upgraded to V2 format
		uint64_t alreadyV2Accounts;    // Already V2 (skipped)
		uint64_t errors;
		std::vector<std::string> errorMessages;

		bool isSuccess() const { return 0 == errors; }
	};

	// ---- Serialization helpers ----

	inline std::vector<uint8_t> serializeV2Extension(const V2Extension& ext) {
		std::vector<uint8_t> buffer;
		buffer.reserve(1 + 4 + ext.FullPublicKey.size());

		// CryptoScheme (1 byte)
		buffer.push_back(static_cast<uint8_t>(ext.Scheme));

		// FullPublicKeySize (4 bytes, little-endian)
		uint32_t keySize = static_cast<uint32_t>(ext.FullPublicKey.size());
		buffer.push_back(static_cast<uint8_t>(keySize & 0xFF));
		buffer.push_back(static_cast<uint8_t>((keySize >> 8) & 0xFF));
		buffer.push_back(static_cast<uint8_t>((keySize >> 16) & 0xFF));
		buffer.push_back(static_cast<uint8_t>((keySize >> 24) & 0xFF));

		// FullPublicKey
		buffer.insert(buffer.end(), ext.FullPublicKey.begin(), ext.FullPublicKey.end());

		return buffer;
	}

	inline V2Extension deserializeV2Extension(const uint8_t* data, size_t size) {
		if (size < 5)
			throw std::runtime_error("V2 extension data too short");

		V2Extension ext;
		ext.Scheme = static_cast<CryptoScheme>(data[0]);

		uint32_t keySize = data[1]
			| (static_cast<uint32_t>(data[2]) << 8)
			| (static_cast<uint32_t>(data[3]) << 16)
			| (static_cast<uint32_t>(data[4]) << 24);

		if (keySize > 65536)
			throw std::runtime_error("V2 extension key size too large: " + std::to_string(keySize));

		if (5 + keySize > size)
			throw std::runtime_error("V2 extension data truncated");

		ext.FullPublicKey.assign(data + 5, data + 5 + keySize);
		return ext;
	}

	// ---- Migration Logic ----

	/// Creates a V2 extension for an existing Ed25519 account.
	/// The 32-byte public key is preserved as-is in the V2 extension,
	/// and AccountState.PublicKey remains unchanged (identity function for Ed25519).
	inline V2Extension createEd25519V2Extension(const std::array<uint8_t, 32>& publicKey) {
		V2Extension ext;
		ext.Scheme = CryptoScheme::Ed25519;
		ext.FullPublicKey.assign(publicKey.begin(), publicKey.end());
		return ext;
	}

	/// Callback interface for iterating over accounts during migration.
	/// The migrator calls this for each account to write the V2 extension.
	using AccountVisitor = std::function<bool(
		const std::array<uint8_t, 24>& address,    // account address
		const std::array<uint8_t, 32>& publicKey,   // current V1 public key
		uint8_t currentStateVersion,                 // 1 or 2
		const V2Extension& extension                 // V2 extension to write
	)>;

	/// Simulates migration of accounts from V1 to V2.
	/// In production, this would iterate over the AccountStateCache delta
	/// and append V2 extensions to each account.
	///
	/// @param accounts Vector of (address, publicKey, stateVersion) tuples.
	/// @param visitor  Callback to write V2 extension for each account.
	/// @returns MigrationResult summary.
	inline MigrationResult migrateAccounts(
		const std::vector<std::tuple<std::array<uint8_t, 24>, std::array<uint8_t, 32>, uint8_t>>& accounts,
		const AccountVisitor& visitor
	) {
		MigrationResult result{};
		result.totalAccounts = accounts.size();

		for (const auto& [address, publicKey, stateVersion] : accounts) {
			if (State_Version_V2 == stateVersion) {
				++result.alreadyV2Accounts;
				continue;
			}

			try {
				auto ext = createEd25519V2Extension(publicKey);
				if (!visitor(address, publicKey, stateVersion, ext)) {
					++result.errors;
					result.errorMessages.push_back("visitor returned false for account");
				} else {
					++result.upgradedAccounts;
				}
			} catch (const std::exception& ex) {
				++result.errors;
				result.errorMessages.push_back(std::string("exception: ") + ex.what());
			}
		}

		return result;
	}

	// ---- Hard Fork Height Configuration ----

	struct HardForkConfig {
		uint64_t activationHeight;      // Block height at which V2 format activates
		bool allowMixedTransactions;    // Allow V1 and V2 transactions in same block
		std::vector<CryptoScheme> enabledSchemes; // Enabled crypto schemes post-fork
	};

	inline HardForkConfig createDefaultHardForkConfig(uint64_t activationHeight) {
		return HardForkConfig{
			activationHeight,
			true, // allow mixed V1/V2 during transition
			{ CryptoScheme::Ed25519, CryptoScheme::Ml_Dsa_65 }
		};
	}

	/// Checks if V2 entities should be accepted at the given block height.
	inline bool isV2Active(const HardForkConfig& config, uint64_t blockHeight) {
		return blockHeight >= config.activationHeight;
	}

	/// Checks if a crypto scheme is enabled in the hard fork config.
	inline bool isSchemeEnabled(const HardForkConfig& config, CryptoScheme scheme) {
		for (const auto& s : config.enabledSchemes) {
			if (s == scheme) return true;
		}
		return false;
	}

}}} // namespace catapult::tools::migration

// ========================================================================
// Standalone test
// ========================================================================

#ifdef MIGRATION_STANDALONE_TEST

#include <cassert>
#include <oqs/oqs.h>

namespace {
	using namespace catapult::tools::migration;

	int runMigrationTests() {
		int passed = 0;
		int failed = 0;

		auto TEST = [&](const char* name, bool condition) {
			if (condition) {
				std::cout << "  PASS: " << name << "\n";
				++passed;
			} else {
				std::cout << "  FAIL: " << name << "\n";
				++failed;
			}
		};

		std::cout << "=== AccountState Migration Tests ===\n\n";

		// Test 1: V2 Extension serialization round-trip (Ed25519)
		{
			std::array<uint8_t, 32> pubkey{};
			for (int i = 0; i < 32; ++i) pubkey[i] = static_cast<uint8_t>(i + 1);

			auto ext = createEd25519V2Extension(pubkey);
			auto serialized = serializeV2Extension(ext);
			auto deserialized = deserializeV2Extension(serialized.data(), serialized.size());

			TEST("V2Extension_Ed25519_RoundTrip",
				deserialized.Scheme == CryptoScheme::Ed25519
				&& deserialized.FullPublicKey.size() == 32
				&& 0 == std::memcmp(deserialized.FullPublicKey.data(), pubkey.data(), 32));
		}

		// Test 2: V2 Extension serialization round-trip (ML-DSA-65)
		{
			V2Extension ext;
			ext.Scheme = CryptoScheme::Ml_Dsa_65;
			ext.FullPublicKey.resize(1952);
			for (size_t i = 0; i < 1952; ++i)
				ext.FullPublicKey[i] = static_cast<uint8_t>(i & 0xFF);

			auto serialized = serializeV2Extension(ext);
			TEST("V2Extension_MlDsa65_SerializedSize", serialized.size() == 1 + 4 + 1952);

			auto deserialized = deserializeV2Extension(serialized.data(), serialized.size());
			TEST("V2Extension_MlDsa65_RoundTrip",
				deserialized.Scheme == CryptoScheme::Ml_Dsa_65
				&& deserialized.FullPublicKey.size() == 1952
				&& deserialized.FullPublicKey == ext.FullPublicKey);
		}

		// Test 3: Deserialization rejects truncated buffer
		{
			bool threw = false;
			try {
				uint8_t tiny[] = { 0x00, 0x20, 0x00, 0x00 }; // only 4 bytes
				deserializeV2Extension(tiny, 4);
			} catch (const std::runtime_error&) {
				threw = true;
			}
			TEST("V2Extension_Deserialization_RejectsTruncated", threw);
		}

		// Test 4: Deserialization rejects oversized key
		{
			bool threw = false;
			try {
				uint8_t buf[] = { 0x01, 0x01, 0x00, 0x01, 0x00 }; // keySize = 65537
				deserializeV2Extension(buf, 5);
			} catch (const std::runtime_error&) {
				threw = true;
			}
			TEST("V2Extension_Deserialization_RejectsOversizedKey", threw);
		}

		// Test 5: Batch migration of Ed25519 accounts
		{
			std::vector<std::tuple<std::array<uint8_t, 24>, std::array<uint8_t, 32>, uint8_t>> accounts;
			for (int i = 0; i < 100; ++i) {
				std::array<uint8_t, 24> addr{};
				std::array<uint8_t, 32> pk{};
				addr[0] = static_cast<uint8_t>(i);
				pk[0] = static_cast<uint8_t>(i);
				accounts.emplace_back(addr, pk, State_Version_V1);
			}

			std::vector<V2Extension> writtenExtensions;
			auto result = migrateAccounts(accounts, [&](const auto&, const auto&, uint8_t, const V2Extension& ext) {
				writtenExtensions.push_back(ext);
				return true;
			});

			TEST("Migration_BatchEd25519_AllUpgraded",
				result.totalAccounts == 100
				&& result.upgradedAccounts == 100
				&& result.errors == 0
				&& writtenExtensions.size() == 100);
		}

		// Test 6: Migration skips already-V2 accounts
		{
			std::vector<std::tuple<std::array<uint8_t, 24>, std::array<uint8_t, 32>, uint8_t>> accounts;
			for (int i = 0; i < 10; ++i) {
				std::array<uint8_t, 24> addr{};
				std::array<uint8_t, 32> pk{};
				uint8_t version = (i < 5) ? State_Version_V1 : State_Version_V2;
				accounts.emplace_back(addr, pk, version);
			}

			auto result = migrateAccounts(accounts, [](const auto&, const auto&, uint8_t, const V2Extension&) {
				return true;
			});

			TEST("Migration_SkipsV2Accounts",
				result.upgradedAccounts == 5
				&& result.alreadyV2Accounts == 5
				&& result.errors == 0);
		}

		// Test 7: Migration handles visitor failure
		{
			std::vector<std::tuple<std::array<uint8_t, 24>, std::array<uint8_t, 32>, uint8_t>> accounts;
			accounts.emplace_back(std::array<uint8_t, 24>{}, std::array<uint8_t, 32>{}, State_Version_V1);

			auto result = migrateAccounts(accounts, [](const auto&, const auto&, uint8_t, const V2Extension&) {
				return false; // simulate write failure
			});

			TEST("Migration_HandlesVisitorFailure",
				result.errors == 1
				&& result.upgradedAccounts == 0);
		}

		// Test 8: Hard fork config
		{
			auto config = createDefaultHardForkConfig(1'000'000);
			TEST("HardFork_NotActiveBeforeHeight", !isV2Active(config, 999'999));
			TEST("HardFork_ActiveAtHeight", isV2Active(config, 1'000'000));
			TEST("HardFork_ActiveAfterHeight", isV2Active(config, 1'000'001));
			TEST("HardFork_Ed25519Enabled", isSchemeEnabled(config, CryptoScheme::Ed25519));
			TEST("HardFork_MlDsa65Enabled", isSchemeEnabled(config, CryptoScheme::Ml_Dsa_65));
		}

		// Test 9: Real ML-DSA-65 key migration (using liboqs)
		{
			OQS_SIG* mldsaSig = OQS_SIG_new("ML-DSA-65");
			bool mldsaOk = false;
			if (mldsaSig) {
				std::vector<uint8_t> pk(mldsaSig->length_public_key);
				std::vector<uint8_t> sk(mldsaSig->length_secret_key);
				if (OQS_SUCCESS == OQS_SIG_keypair(mldsaSig, pk.data(), sk.data())) {
					// Create V2 extension for ML-DSA-65 account
					V2Extension ext;
					ext.Scheme = CryptoScheme::Ml_Dsa_65;
					ext.FullPublicKey = pk;

					auto serialized = serializeV2Extension(ext);
					auto deserialized = deserializeV2Extension(serialized.data(), serialized.size());

					mldsaOk = (deserialized.Scheme == CryptoScheme::Ml_Dsa_65)
						&& (deserialized.FullPublicKey.size() == 1952)
						&& (deserialized.FullPublicKey == pk);

					// Sign and verify with the full key to confirm it works post-migration
					std::vector<uint8_t> msg = { 'h', 'e', 'l', 'l', 'o' };
					std::vector<uint8_t> sig(mldsaSig->length_signature);
					size_t sigLen = 0;
					if (OQS_SUCCESS == OQS_SIG_sign(mldsaSig, sig.data(), &sigLen,
							msg.data(), msg.size(), sk.data())) {
						sig.resize(sigLen);
						mldsaOk = mldsaOk && (OQS_SUCCESS == OQS_SIG_verify(mldsaSig,
							msg.data(), msg.size(), sig.data(), sig.size(),
							deserialized.FullPublicKey.data()));
					} else {
						mldsaOk = false;
					}
				}
				OQS_SIG_free(mldsaSig);
			}
			TEST("Migration_MlDsa65_RealKey_RoundTrip", mldsaOk);
		}

		// Test 10: V2 extension format byte layout
		{
			V2Extension ext;
			ext.Scheme = CryptoScheme::Ml_Dsa_65;
			ext.FullPublicKey.resize(1952, 0xAB);

			auto buf = serializeV2Extension(ext);
			// Verify exact byte layout
			TEST("V2Extension_ByteLayout",
				buf[0] == 0x01                                          // CryptoScheme::Ml_Dsa_65
				&& buf[1] == 0xA0 && buf[2] == 0x07                    // 1952 = 0x07A0 (LE)
				&& buf[3] == 0x00 && buf[4] == 0x00
				&& buf.size() == 1957                                   // 1 + 4 + 1952
				&& buf[5] == 0xAB && buf[1956] == 0xAB);               // key data
		}

		std::cout << "\n=== Results: " << passed << " passed, " << failed << " failed ===\n";
		return failed > 0 ? 1 : 0;
	}
}

int main() {
	return runMigrationTests();
}

#endif // MIGRATION_STANDALONE_TEST
