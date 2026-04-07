// Generates ML-DSA-65 test vectors in JSON format for SDK cross-validation.
// Output: tests/vectors/symbol/crypto/10.test-mldsa65-keys.json
//         tests/vectors/symbol/crypto/11.test-mldsa65-sign.json
//
// Build:
//   g++ -std=c++17 -O2 -I/usr/local/include -o generate_pqc_vectors \
//       tools/pqc/GenerateTestVectors.cpp -L/usr/local/lib -loqs
//
// Run:
//   LD_LIBRARY_PATH=/usr/local/lib ./generate_pqc_vectors

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <oqs/oqs.h>

namespace {
	constexpr const char* Algorithm = "ML-DSA-65";
	constexpr size_t Num_Key_Vectors = 10;
	constexpr size_t Num_Sign_Vectors = 10;
	constexpr size_t Max_Message_Size = 200;

	std::string toHex(const uint8_t* data, size_t size) {
		std::ostringstream oss;
		for (size_t i = 0; i < size; ++i)
			oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
		return oss.str();
	}

	std::string escapeJson(const std::string& s) {
		return s; // hex strings don't need JSON escaping
	}

	struct KeyTestVector {
		std::vector<uint8_t> privateKey; // OQS secret key (4032) || public key (1952) = 5984
		std::vector<uint8_t> publicKey;  // 1952 bytes
	};

	struct SignTestVector {
		std::vector<uint8_t> privateKey; // 5984 bytes (our format)
		std::vector<uint8_t> publicKey;  // 1952 bytes
		size_t length;
		std::vector<uint8_t> data;
		std::vector<uint8_t> signature;  // 3309 bytes
	};

	bool generateKeyVectors(std::vector<KeyTestVector>& vectors) {
		OQS_SIG* sig = OQS_SIG_new(Algorithm);
		if (!sig) {
			std::cerr << "ERROR: failed to create " << Algorithm << " instance\n";
			return false;
		}

		for (size_t i = 0; i < Num_Key_Vectors; ++i) {
			KeyTestVector vec;
			vec.publicKey.resize(sig->length_public_key);
			std::vector<uint8_t> oqsSk(sig->length_secret_key);

			if (OQS_SUCCESS != OQS_SIG_keypair(sig, vec.publicKey.data(), oqsSk.data())) {
				std::cerr << "ERROR: keypair generation failed at index " << i << "\n";
				OQS_SIG_free(sig);
				return false;
			}

			// Our combined format: sk(4032) || pk(1952)
			vec.privateKey.resize(sig->length_secret_key + sig->length_public_key);
			std::memcpy(vec.privateKey.data(), oqsSk.data(), sig->length_secret_key);
			std::memcpy(vec.privateKey.data() + sig->length_secret_key, vec.publicKey.data(), sig->length_public_key);

			vectors.push_back(std::move(vec));
		}

		OQS_SIG_free(sig);
		return true;
	}

	bool generateSignVectors(const std::vector<KeyTestVector>& keyVectors, std::vector<SignTestVector>& signVectors) {
		OQS_SIG* sig = OQS_SIG_new(Algorithm);
		if (!sig) return false;

		std::mt19937 rng(42); // deterministic seed for reproducibility
		std::uniform_int_distribution<size_t> lenDist(1, Max_Message_Size);
		std::uniform_int_distribution<int> byteDist(0, 255);

		for (size_t i = 0; i < Num_Sign_Vectors; ++i) {
			const auto& kv = keyVectors[i % keyVectors.size()];

			SignTestVector vec;
			vec.privateKey = kv.privateKey;
			vec.publicKey = kv.publicKey;
			vec.length = lenDist(rng);
			vec.data.resize(vec.length);
			for (size_t j = 0; j < vec.length; ++j)
				vec.data[j] = static_cast<uint8_t>(byteDist(rng));

			// Sign using OQS secret key (first 4032 bytes)
			vec.signature.resize(sig->length_signature);
			size_t sigLen = 0;
			if (OQS_SUCCESS != OQS_SIG_sign(sig, vec.signature.data(), &sigLen,
					vec.data.data(), vec.data.size(), kv.privateKey.data())) {
				std::cerr << "ERROR: signing failed at index " << i << "\n";
				OQS_SIG_free(sig);
				return false;
			}
			vec.signature.resize(sigLen);

			// Verify to ensure correctness
			if (OQS_SUCCESS != OQS_SIG_verify(sig, vec.data.data(), vec.data.size(),
					vec.signature.data(), vec.signature.size(), kv.publicKey.data())) {
				std::cerr << "ERROR: verification failed at index " << i << "\n";
				OQS_SIG_free(sig);
				return false;
			}

			signVectors.push_back(std::move(vec));
		}

		OQS_SIG_free(sig);
		return true;
	}

	void writeKeyVectorsJson(const std::vector<KeyTestVector>& vectors, const std::string& path) {
		std::ofstream out(path);
		out << "[\n";
		for (size_t i = 0; i < vectors.size(); ++i) {
			const auto& v = vectors[i];
			out << "  {\n";
			out << "    \"privateKey\": \"" << toHex(v.privateKey.data(), v.privateKey.size()) << "\",\n";
			out << "    \"publicKey\": \"" << toHex(v.publicKey.data(), v.publicKey.size()) << "\"\n";
			out << "  }";
			if (i + 1 < vectors.size()) out << ",";
			out << "\n";
		}
		out << "]\n";
		out.close();
		std::cout << "  wrote " << vectors.size() << " key vectors to " << path << "\n";
	}

	void writeSignVectorsJson(const std::vector<SignTestVector>& vectors, const std::string& path) {
		std::ofstream out(path);
		out << "[\n";
		for (size_t i = 0; i < vectors.size(); ++i) {
			const auto& v = vectors[i];
			out << "  {\n";
			out << "    \"privateKey\": \"" << toHex(v.privateKey.data(), v.privateKey.size()) << "\",\n";
			out << "    \"publicKey\": \"" << toHex(v.publicKey.data(), v.publicKey.size()) << "\",\n";
			out << "    \"length\": " << v.length << ",\n";
			out << "    \"data\": \"" << toHex(v.data.data(), v.data.size()) << "\",\n";
			out << "    \"signature\": \"" << toHex(v.signature.data(), v.signature.size()) << "\"\n";
			out << "  }";
			if (i + 1 < vectors.size()) out << ",";
			out << "\n";
		}
		out << "]\n";
		out.close();
		std::cout << "  wrote " << vectors.size() << " sign vectors to " << path << "\n";
	}
}

int main() {
	std::cout << "=== ML-DSA-65 Test Vector Generator ===\n\n";

	// Generate key vectors
	std::vector<KeyTestVector> keyVectors;
	std::cout << "Generating " << Num_Key_Vectors << " key pair vectors...\n";
	if (!generateKeyVectors(keyVectors)) return 1;

	// Generate sign vectors
	std::vector<SignTestVector> signVectors;
	std::cout << "Generating " << Num_Sign_Vectors << " sign/verify vectors...\n";
	if (!generateSignVectors(keyVectors, signVectors)) return 1;

	// Write JSON files
	std::cout << "\nWriting test vector files...\n";
	writeKeyVectorsJson(keyVectors, "tests/vectors/symbol/crypto/10.test-mldsa65-keys.json");
	writeSignVectorsJson(signVectors, "tests/vectors/symbol/crypto/11.test-mldsa65-sign.json");

	std::cout << "\nDone. Vectors can be used for cross-SDK validation.\n";
	std::cout << "  Private key format: OQS_secret_key(4032) || public_key(1952) = 5984 bytes\n";
	std::cout << "  Public key: " << keyVectors[0].publicKey.size() << " bytes\n";
	std::cout << "  Signature: " << signVectors[0].signature.size() << " bytes\n";
	return 0;
}
