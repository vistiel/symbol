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
#include "catapult/model/NotificationsV2.h"
#include "catapult/crypto/CryptoProvider.h"
#include "catapult/crypto/CryptoProviderRegistry.h"
#include "catapult/crypto/SignerV2.h"
#include <memory>

namespace catapult { namespace validators {

	/// V2 signature validator that uses CryptoProviderRegistry for scheme-agnostic verification.
	///
	/// This is the V2 counterpart to SignatureValidator.cpp, which calls crypto::Verify()
	/// (hardcoded to Ed25519). SignatureValidatorV2 reads the CryptoSchemeId from the
	/// SignatureNotificationV2 and dispatches to the correct provider.
	///
	/// Validates:
	/// - The CryptoScheme is registered in the registry
	/// - The public key size matches the provider's expected size
	/// - The signature size matches the provider's expected size
	/// - The signature is cryptographically valid
	class SignatureValidatorV2 {
	public:
		/// Creates a V2 signature validator around \a registry and \a generationHashSeed.
		SignatureValidatorV2(
				const std::shared_ptr<const crypto::CryptoProviderRegistry>& pRegistry,
				const GenerationHashSeed& generationHashSeed)
				: m_pRegistry(pRegistry)
				, m_generationHashSeed(generationHashSeed)
		{}

	public:
		/// Validates a V2 signature notification.
		/// Returns ValidationResult::Success if the signature is valid.
		ValidationResult validate(const model::SignatureNotificationV2& notification) const {
			// Check that the scheme is registered
			if (!m_pRegistry->hasSignatureProvider(notification.CryptoScheme))
				return Failure_Signature_Not_Verifiable;

			const auto& provider = m_pRegistry->signatureProvider(notification.CryptoScheme);

			// Validate field sizes
			if (notification.SignerPublicKey.Size != provider.publicKeySize())
				return Failure_Signature_Not_Verifiable;

			if (notification.Signature.Size != provider.signatureSize())
				return Failure_Signature_Not_Verifiable;

			// Build verification buffers
			crypto::CryptoBuffer pubKey(notification.SignerPublicKey.pData, notification.SignerPublicKey.Size);
			crypto::CryptoBuffer signature(notification.Signature.pData, notification.Signature.Size);

			std::vector<RawBuffer> buffers;
			if (model::SignatureNotificationV2::ReplayProtectionMode::Enabled == notification.DataReplayProtectionMode)
				buffers.push_back(RawBuffer{ m_generationHashSeed.data(), GenerationHashSeed::Size });

			buffers.push_back(notification.Data);

			// Verify via registry
			auto isVerified = crypto::VerifyV2(*m_pRegistry, notification.CryptoScheme, pubKey, buffers, signature);
			return isVerified ? ValidationResult::Success : Failure_Signature_Not_Verifiable;
		}

	private:
		std::shared_ptr<const crypto::CryptoProviderRegistry> m_pRegistry;
		GenerationHashSeed m_generationHashSeed;
	};
}}
