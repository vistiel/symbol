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
#include "SecureByteArray.h"
#include "catapult/types.h"
#include "catapult/utils/NonCopyable.h"
#include <memory>
#include <string>
#include <vector>

namespace catapult { namespace crypto {

	/// Identifier for a cryptographic scheme.
	enum class CryptoScheme : uint8_t {
		/// Ed25519 (current default).
		Ed25519 = 0x00,

		/// ML-DSA-65 (Dilithium3, NIST PQC standard).
		Ml_Dsa_65 = 0x01
	};

	/// Variable-length byte container for cryptographic data (keys, signatures).
	class CryptoBuffer {
	public:
		CryptoBuffer() = default;

		explicit CryptoBuffer(size_t size) : m_data(size) {}

		CryptoBuffer(const uint8_t* pData, size_t size) : m_data(pData, pData + size) {}

		template<typename TByteArray>
		explicit CryptoBuffer(const TByteArray& byteArray)
			: m_data(byteArray.data(), byteArray.data() + byteArray.size())
		{}

	public:
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

	/// Secure variable-length byte container that zeroes memory on destruction.
	class SecureCryptoBuffer {
	public:
		SecureCryptoBuffer() = default;
		explicit SecureCryptoBuffer(size_t size) : m_data(size) {}

		SecureCryptoBuffer(SecureCryptoBuffer&& rhs) noexcept : m_data(std::move(rhs.m_data)) {}

		SecureCryptoBuffer& operator=(SecureCryptoBuffer&& rhs) noexcept {
			secureWipe();
			m_data = std::move(rhs.m_data);
			return *this;
		}

		SecureCryptoBuffer(const SecureCryptoBuffer&) = delete;
		SecureCryptoBuffer& operator=(const SecureCryptoBuffer&) = delete;

		~SecureCryptoBuffer() { secureWipe(); }

	public:
		const uint8_t* data() const { return m_data.data(); }
		uint8_t* data() { return m_data.data(); }
		size_t size() const { return m_data.size(); }
		bool empty() const { return m_data.empty(); }

	private:
		void secureWipe() {
			if (!m_data.empty())
				SecureZero(m_data.data(), m_data.size());
		}

		std::vector<uint8_t> m_data;
	};

	/// Abstract interface for a digital signature provider.
	/// All post-quantum and classical signature schemes must implement this interface.
	class SignatureProvider : public utils::NonCopyable {
	public:
		virtual ~SignatureProvider() = default;

	public:
		/// Gets the crypto scheme identifier.
		virtual CryptoScheme scheme() const = 0;

		/// Gets a human-readable name for the scheme.
		virtual const std::string& name() const = 0;

		/// Gets the public key size in bytes.
		virtual size_t publicKeySize() const = 0;

		/// Gets the private key size in bytes.
		virtual size_t privateKeySize() const = 0;

		/// Gets the signature size in bytes.
		virtual size_t signatureSize() const = 0;

	public:
		/// Extracts a public key from \a privateKey into \a publicKey.
		virtual void extractPublicKey(const SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const = 0;

		/// Signs data in \a buffers using \a privateKey and \a publicKey, placing result in \a signature.
		/// \note Throws on failure.
		virtual void sign(
				const SecureCryptoBuffer& privateKey,
				const CryptoBuffer& publicKey,
				const std::vector<RawBuffer>& buffers,
				CryptoBuffer& signature) const = 0;

		/// Verifies that \a signature of data in \a buffers is valid for \a publicKey.
		/// Returns \c true if valid.
		virtual bool verify(
				const CryptoBuffer& publicKey,
				const std::vector<RawBuffer>& buffers,
				const CryptoBuffer& signature) const = 0;

		/// Generates a new random private key into \a privateKey.
		virtual void generatePrivateKey(SecureCryptoBuffer& privateKey) const = 0;
	};

	/// Abstract interface for a key encapsulation mechanism (KEM) provider.
	/// Used for key exchange in a post-quantum setting.
	class KemProvider : public utils::NonCopyable {
	public:
		virtual ~KemProvider() = default;

	public:
		/// Gets the crypto scheme identifier.
		virtual CryptoScheme scheme() const = 0;

		/// Gets a human-readable name for the scheme.
		virtual const std::string& name() const = 0;

		/// Gets the public key size in bytes.
		virtual size_t publicKeySize() const = 0;

		/// Gets the private key size in bytes.
		virtual size_t privateKeySize() const = 0;

		/// Gets the ciphertext size in bytes.
		virtual size_t ciphertextSize() const = 0;

		/// Gets the shared secret size in bytes.
		virtual size_t sharedSecretSize() const = 0;

	public:
		/// Generates a new KEM key pair.
		virtual void generateKeyPair(SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const = 0;

		/// Encapsulates a shared secret for \a publicKey.
		/// Produces \a ciphertext and \a sharedSecret.
		virtual void encapsulate(
				const CryptoBuffer& publicKey,
				CryptoBuffer& ciphertext,
				SecureCryptoBuffer& sharedSecret) const = 0;

		/// Decapsulates \a ciphertext using \a privateKey to recover \a sharedSecret.
		virtual void decapsulate(
				const SecureCryptoBuffer& privateKey,
				const CryptoBuffer& ciphertext,
				SecureCryptoBuffer& sharedSecret) const = 0;
	};
}}
