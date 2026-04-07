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
#include "EntityHeaderV2.h"
#include "NotificationsV2.h"

namespace catapult { namespace model {

	/// Utility functions for publishing V2 notifications from V2 entity buffers.
	///
	/// These are the V2 counterparts to the notification-raising code in
	/// NotificationPublisher.cpp. The key difference is that V2 notifications
	/// use RawBuffer (variable-length) instead of const Key& and const Signature&.
	///
	/// Integration path:
	/// 1. When processing an entity, check CryptoSchemeId at offset 4
	/// 2. If CryptoSchemeId == 0x00 (Ed25519), use V1 path (no changes)
	/// 3. If CryptoSchemeId != 0x00 (PQC), use V2 path (these functions)
	namespace NotificationPublisherV2 {

		/// Creates a V2 signature notification from a V2 entity header reader.
		/// The notification references the signature and public key directly from
		/// the entity buffer (zero-copy).
		inline SignatureNotificationV2 CreateBlockSignatureNotification(const EntityHeaderV2Reader& reader) {
			// For blocks, the signable data is everything after the header (body + footer)
			auto dataBuf = reader.dataBuffer();
			return SignatureNotificationV2(
					reader.cryptoScheme(),
					reader.signerPublicKey(),
					reader.signature(),
					dataBuf,
					SignatureNotificationV2::ReplayProtectionMode::Disabled);
		}

		/// Creates a V2 signature notification for a transaction from a V2 entity reader.
		/// Replay protection is enabled for transactions.
		inline SignatureNotificationV2 CreateTransactionSignatureNotification(
				const EntityHeaderV2Reader& reader,
				const RawBuffer& dataBuffer) {
			return SignatureNotificationV2(
					reader.cryptoScheme(),
					reader.signerPublicKey(),
					reader.signature(),
					dataBuffer,
					SignatureNotificationV2::ReplayProtectionMode::Enabled);
		}

		/// Creates a V2 account public key notification from a V2 entity header reader.
		inline AccountPublicKeyNotificationV2 CreateAccountPublicKeyNotification(const EntityHeaderV2Reader& reader) {
			return AccountPublicKeyNotificationV2(reader.cryptoScheme(), reader.signerPublicKey());
		}

		/// Checks if an entity buffer is a V2 entity (non-Ed25519 crypto scheme).
		/// \note Ed25519 entities (scheme 0x00) should use V1 notifications for
		///       backward compatibility and to benefit from Ed25519 batch verification.
		inline bool IsV2Entity(const uint8_t* pBuffer, size_t bufferSize) {
			if (bufferSize < 5)
				return false;
			// CryptoSchemeId is at offset 4 (after Size field)
			return pBuffer[4] != 0x00;
		}

		/// Returns the CryptoSchemeId from a raw entity buffer, or Ed25519 (0x00) if buffer too small.
		inline crypto::CryptoScheme GetCryptoScheme(const uint8_t* pBuffer, size_t bufferSize) {
			if (bufferSize < 5)
				return crypto::CryptoScheme::Ed25519;
			return static_cast<crypto::CryptoScheme>(pBuffer[4]);
		}
	}
}}
