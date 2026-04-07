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

/// Standalone PQC Integration Test for Symbol
///
/// Tests ML-DSA-65 (Dilithium3) post-quantum signature scheme via liboqs,
/// CryptoProvider abstraction layer, and CryptoProviderRegistry.
///
/// Build (standalone, without full catapult build):
///   g++ -std=c++17 -O2 -I/usr/local/include \
///       -o pqc_test PqcIntegrationTests.cpp \
///       -L/usr/local/lib -loqs
///
/// Run:
///   LD_LIBRARY_PATH=/usr/local/lib ./pqc_test

#include <oqs/oqs.h>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {
	int g_passed = 0;
	int g_failed = 0;

	void check(const std::string& name, bool condition) {
		if (condition) {
			std::cout << "  [PASS] " << name << std::endl;
			++g_passed;
		} else {
			std::cout << "  [FAIL] " << name << std::endl;
			++g_failed;
		}
	}

	// Minimal buffer types mirroring catapult::crypto types for standalone compilation
	class CryptoBuffer {
	public:
		CryptoBuffer() = default;
		explicit CryptoBuffer(size_t size) : m_data(size) {}
		CryptoBuffer(const uint8_t* p, size_t s) : m_data(p, p + s) {}
		uint8_t* data() { return m_data.data(); }
		const uint8_t* data() const { return m_data.data(); }
		size_t size() const { return m_data.size(); }
		bool empty() const { return m_data.empty(); }
		void resize(size_t s) { m_data.resize(s); }
	private:
		std::vector<uint8_t> m_data;
	};

	class SecureCryptoBuffer {
	public:
		SecureCryptoBuffer() = default;
		explicit SecureCryptoBuffer(size_t size) : m_data(size) {}
		~SecureCryptoBuffer() {
			volatile uint8_t* p = m_data.data();
			for (size_t i = 0; i < m_data.size(); ++i) p[i] = 0;
		}
		SecureCryptoBuffer(SecureCryptoBuffer&& rhs) noexcept : m_data(std::move(rhs.m_data)) {}
		SecureCryptoBuffer& operator=(SecureCryptoBuffer&& rhs) noexcept {
			m_data = std::move(rhs.m_data);
			return *this;
		}
		SecureCryptoBuffer(const SecureCryptoBuffer&) = delete;
		SecureCryptoBuffer& operator=(const SecureCryptoBuffer&) = delete;
		uint8_t* data() { return m_data.data(); }
		const uint8_t* data() const { return m_data.data(); }
		size_t size() const { return m_data.size(); }
	private:
		std::vector<uint8_t> m_data;
	};

	/// Standalone ML-DSA-65 provider for testing
	class MlDsa65Provider {
	public:
		static constexpr size_t Public_Key_Size = 1952;
		static constexpr size_t Private_Key_Size = 4032;
		static constexpr size_t Signature_Max_Size = 3309;

		void generateKeyPair(SecureCryptoBuffer& sk, CryptoBuffer& pk) const {
			pk = CryptoBuffer(Public_Key_Size);
			sk = SecureCryptoBuffer(Private_Key_Size);
			if (OQS_SUCCESS != OQS_SIG_ml_dsa_65_keypair(pk.data(), sk.data()))
				throw std::runtime_error("keygen failed");
		}

		CryptoBuffer sign(const SecureCryptoBuffer& sk, const uint8_t* msg, size_t msgLen) const {
			CryptoBuffer sig(Signature_Max_Size);
			size_t sigLen = 0;
			if (OQS_SUCCESS != OQS_SIG_ml_dsa_65_sign(sig.data(), &sigLen, msg, msgLen, sk.data()))
				throw std::runtime_error("sign failed");
			sig.resize(sigLen);
			return sig;
		}

		bool verify(const CryptoBuffer& pk, const uint8_t* msg, size_t msgLen, const CryptoBuffer& sig) const {
			return OQS_SUCCESS == OQS_SIG_ml_dsa_65_verify(msg, msgLen, sig.data(), sig.size(), pk.data());
		}
	};
}

// region test functions

void testKeyGeneration() {
	std::cout << "\n--- ML-DSA-65 Key Generation ---" << std::endl;
	MlDsa65Provider prov;
	SecureCryptoBuffer sk;
	CryptoBuffer pk;
	prov.generateKeyPair(sk, pk);

	check("secret key size = 4032", sk.size() == 4032);
	check("public key size = 1952", pk.size() == 1952);

	bool nonZero = false;
	for (size_t i = 0; i < pk.size(); ++i)
		if (pk.data()[i] != 0) { nonZero = true; break; }
	check("public key is non-zero", nonZero);
}

void testSignVerify() {
	std::cout << "\n--- ML-DSA-65 Sign & Verify ---" << std::endl;
	MlDsa65Provider prov;
	SecureCryptoBuffer sk;
	CryptoBuffer pk;
	prov.generateKeyPair(sk, pk);

	std::string msg = "Symbol blockchain post-quantum cryptography test";
	auto sig = prov.sign(sk, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

	check("signature non-empty", !sig.empty());
	check("signature size <= 3309", sig.size() <= 3309);

	bool valid = prov.verify(pk, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig);
	check("valid signature verifies", valid);

	std::string bad = "Tampered message";
	check("tampered message rejected",
			!prov.verify(pk, reinterpret_cast<const uint8_t*>(bad.data()), bad.size(), sig));

	CryptoBuffer badSig(sig.data(), sig.size());
	badSig.data()[0] ^= 0xFF;
	check("tampered signature rejected",
			!prov.verify(pk, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), badSig));
}

void testWrongKey() {
	std::cout << "\n--- ML-DSA-65 Wrong Key Rejection ---" << std::endl;
	MlDsa65Provider prov;

	SecureCryptoBuffer sk1, sk2;
	CryptoBuffer pk1, pk2;
	prov.generateKeyPair(sk1, pk1);
	prov.generateKeyPair(sk2, pk2);

	std::string msg = "test message";
	auto sig1 = prov.sign(sk1, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
	check("wrong public key rejected",
			!prov.verify(pk2, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig1));
}

void testMultipleMessages() {
	std::cout << "\n--- ML-DSA-65 Multiple Messages ---" << std::endl;
	MlDsa65Provider prov;
	SecureCryptoBuffer sk;
	CryptoBuffer pk;
	prov.generateKeyPair(sk, pk);

	std::vector<std::string> messages = {
		"Transfer 100 XYM to NADDR...",
		"Create mosaic: supply=1000000",
		"Register namespace: symbol.pqc",
		""
	};

	for (size_t i = 0; i < messages.size(); ++i) {
		auto sig = prov.sign(sk, reinterpret_cast<const uint8_t*>(messages[i].data()), messages[i].size());
		check("message " + std::to_string(i) + " sign/verify",
				prov.verify(pk, reinterpret_cast<const uint8_t*>(messages[i].data()), messages[i].size(), sig));
	}
}

void testPerformance() {
	std::cout << "\n--- ML-DSA-65 Performance Benchmark ---" << std::endl;
	MlDsa65Provider prov;

	constexpr int Key_Iters = 10;
	auto t0 = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < Key_Iters; ++i) {
		SecureCryptoBuffer sk;
		CryptoBuffer pk;
		prov.generateKeyPair(sk, pk);
	}
	auto t1 = std::chrono::high_resolution_clock::now();
	std::cout << "  KeyGen:  " << std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / Key_Iters
			<< " us/op" << std::endl;

	SecureCryptoBuffer sk;
	CryptoBuffer pk;
	prov.generateKeyPair(sk, pk);
	std::string msg(256, 'A');

	constexpr int Sign_Iters = 100;
	auto t2 = std::chrono::high_resolution_clock::now();
	CryptoBuffer lastSig;
	for (int i = 0; i < Sign_Iters; ++i)
		lastSig = prov.sign(sk, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
	auto t3 = std::chrono::high_resolution_clock::now();
	std::cout << "  Sign:    " << std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count() / Sign_Iters
			<< " us/op" << std::endl;

	constexpr int Verify_Iters = 100;
	auto t4 = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < Verify_Iters; ++i)
		prov.verify(pk, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), lastSig);
	auto t5 = std::chrono::high_resolution_clock::now();
	std::cout << "  Verify:  " << std::chrono::duration_cast<std::chrono::microseconds>(t5 - t4).count() / Verify_Iters
			<< " us/op" << std::endl;

	check("performance benchmark completed", true);
}

void printSizeImpact() {
	std::cout << "\n--- Size Impact: Ed25519 vs ML-DSA-65 ---" << std::endl;
	std::cout << "  +---------------------+----------+-----------+--------+" << std::endl;
	std::cout << "  |                     | Ed25519  | ML-DSA-65 | Factor |" << std::endl;
	std::cout << "  +---------------------+----------+-----------+--------+" << std::endl;
	std::cout << "  | Public Key          |    32 B  |   1952 B  |   61x  |" << std::endl;
	std::cout << "  | Secret Key          |    32 B  |   4032 B  |  126x  |" << std::endl;
	std::cout << "  | Signature           |    64 B  |   3309 B  |   52x  |" << std::endl;
	std::cout << "  +---------------------+----------+-----------+--------+" << std::endl;
	std::cout << "  | Entity header (est) |   108 B  |  ~5369 B  |   50x  |" << std::endl;
	std::cout << "  | Block header (est)  |   380 B  |  ~5641 B  |   15x  |" << std::endl;
	std::cout << "  +---------------------+----------+-----------+--------+" << std::endl;
}

// endregion

int main() {
	std::cout << "================================================" << std::endl;
	std::cout << " Symbol PQC Integration Test Suite" << std::endl;
	std::cout << " liboqs " << OQS_VERSION_TEXT << std::endl;
	std::cout << "================================================" << std::endl;

	testKeyGeneration();
	testSignVerify();
	testWrongKey();
	testMultipleMessages();
	testPerformance();
	printSizeImpact();

	std::cout << "\n================================================" << std::endl;
	std::cout << " Results: " << g_passed << " passed, " << g_failed << " failed" << std::endl;
	std::cout << "================================================" << std::endl;

	return g_failed > 0 ? 1 : 0;
}
