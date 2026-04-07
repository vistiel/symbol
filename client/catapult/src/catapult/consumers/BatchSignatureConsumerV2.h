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
#include <vector>

namespace catapult { namespace consumers {

	/// Captures V2 signature notifications from the notification stream and
	/// converts them to SignatureInputV2 for batch verification.
	///
	/// This is the V2 counterpart to SignatureCapturingNotificationSubscriber
	/// in BatchSignatureConsumer.cpp. The V1 version captures SignatureNotification
	/// (fixed-size Key& + Signature&) and builds crypto::SignatureInput.
	/// This version captures SignatureNotificationV2 (RawBuffer + CryptoScheme)
	/// and builds crypto::SignatureInputV2.
	class SignatureCapturingNotificationSubscriberV2 {
	public:
		explicit SignatureCapturingNotificationSubscriberV2(const GenerationHashSeed& generationHashSeed)
				: m_generationHashSeed(generationHashSeed)
				, m_entityIndex(0)
		{}

	public:
		const auto& notificationToEntityIndexMap() const {
			return m_notificationToEntityIndexMap;
		}

		const auto& inputs() const {
			return m_inputs;
		}

		size_t size() const {
			return m_inputs.size();
		}

	public:
		void next() {
			++m_entityIndex;
		}

		/// Processes a V2 signature notification, converting it to a SignatureInputV2.
		void add(const model::SignatureNotificationV2& notification) {
			m_notificationToEntityIndexMap.push_back(m_entityIndex);

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
		std::vector<size_t> m_notificationToEntityIndexMap;
		std::vector<crypto::SignatureInputV2> m_inputs;
	};

	/// Performs batch verification of V2 signature inputs using the CryptoProviderRegistry.
	///
	/// Unlike V1 batch verification (which uses Ed25519 multi-scalar multiplication),
	/// V2 verification is per-signature since PQC schemes don't support batch math.
	/// However, V2 verification is still parallelizable across threads.
	///
	/// Returns a vector of validation results per signature input, and an aggregate result.
	inline std::pair<std::vector<bool>, bool> BatchVerifyV2(
			const crypto::CryptoProviderRegistry& registry,
			const std::vector<crypto::SignatureInputV2>& inputs) {
		if (inputs.empty())
			return { {}, true };

		return crypto::VerifyMultiV2(registry, inputs.data(), inputs.size());
	}

	/// Short-circuit batch verification: returns false on first invalid signature.
	inline bool BatchVerifyV2ShortCircuit(
			const crypto::CryptoProviderRegistry& registry,
			const std::vector<crypto::SignatureInputV2>& inputs) {
		if (inputs.empty())
			return true;

		for (const auto& input : inputs) {
			crypto::CryptoBuffer pubKey = input.PublicKey;
			crypto::CryptoBuffer sig = input.Signature;
			if (!crypto::VerifyV2(registry, input.Scheme, pubKey, input.Buffers, sig))
				return false;
		}
		return true;
	}
}}
