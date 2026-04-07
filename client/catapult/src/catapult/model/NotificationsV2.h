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
#include "Notifications.h"
#include "catapult/crypto/CryptoProvider.h"

namespace catapult { namespace model {

	// region V2 signature notification

	/// Notifies the presence of a V2 signature with variable-length crypto fields.
	///
	/// Unlike V1 SignatureNotification (which holds const Key& and const Signature&,
	/// both fixed-size), this notification uses RawBuffer to reference variable-length
	/// public keys and signatures from V2 entity buffers.
	///
	/// The CryptoSchemeId allows validators to dispatch to the correct
	/// CryptoProviderRegistry-based verification routine.
	struct SignatureNotificationV2 : public Notification {
	public:
		/// Replay protection modes.
		enum class ReplayProtectionMode { Enabled, Disabled };

	public:
		/// Matching notification type.
		/// \note Uses a distinct notification type code (0x0017) to coexist with V1 (0x0007).
		static constexpr auto Notification_Type = Core_Signature_V2_Notification;

	public:
		/// Creates a V2 signature notification around variable-length \a signerPublicKey,
		/// \a signature and \a data, with \a cryptoScheme identifying the algorithm and
		/// optional replay protection mode (\a dataReplayProtectionMode).
		SignatureNotificationV2(
				crypto::CryptoScheme cryptoScheme,
				const RawBuffer& signerPublicKey,
				const RawBuffer& signature,
				const RawBuffer& data,
				ReplayProtectionMode dataReplayProtectionMode = ReplayProtectionMode::Disabled)
				: Notification(Notification_Type, sizeof(SignatureNotificationV2))
				, CryptoScheme(cryptoScheme)
				, SignerPublicKey(signerPublicKey)
				, Signature(signature)
				, Data(data)
				, DataReplayProtectionMode(dataReplayProtectionMode)
		{}

	public:
		/// Cryptographic scheme identifier.
		crypto::CryptoScheme CryptoScheme;

		/// Signer public key (variable-length, references V2 entity buffer).
		RawBuffer SignerPublicKey;

		/// Signature (variable-length, references V2 entity buffer).
		RawBuffer Signature;

		/// Signed data.
		RawBuffer Data;

		/// Replay protection mode applied to data.
		ReplayProtectionMode DataReplayProtectionMode;
	};

	// endregion

	// region V2 account public key notification

	/// Notifies use of a V2 account with variable-length public key.
	struct AccountPublicKeyNotificationV2 : public Notification {
	public:
		/// Matching notification type.
		static constexpr auto Notification_Type = Core_Register_Account_Public_Key_V2_Notification;

	public:
		/// Creates a notification around \a cryptoScheme and \a publicKey.
		AccountPublicKeyNotificationV2(crypto::CryptoScheme cryptoScheme, const RawBuffer& publicKey)
				: Notification(Notification_Type, sizeof(AccountPublicKeyNotificationV2))
				, CryptoScheme(cryptoScheme)
				, PublicKey(publicKey)
		{}

	public:
		/// Cryptographic scheme.
		crypto::CryptoScheme CryptoScheme;

		/// Public key (variable-length).
		RawBuffer PublicKey;
	};

	// endregion
}}
