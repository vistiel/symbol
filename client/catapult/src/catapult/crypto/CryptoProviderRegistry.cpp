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

#include "CryptoProviderRegistry.h"
#include "Ed25519SignatureProvider.h"
#include "catapult/exceptions.h"

namespace catapult { namespace crypto {

	CryptoProviderRegistry::CryptoProviderRegistry() {
		registerSignatureProvider(std::make_shared<Ed25519SignatureProvider>());
	}

	void CryptoProviderRegistry::registerSignatureProvider(std::shared_ptr<SignatureProvider> pProvider) {
		auto schemeId = static_cast<uint8_t>(pProvider->scheme());
		auto result = m_signatureProviders.emplace(schemeId, std::move(pProvider));
		if (!result.second)
			CATAPULT_THROW_INVALID_ARGUMENT_1("signature provider already registered for scheme", schemeId);
	}

	void CryptoProviderRegistry::registerKemProvider(std::shared_ptr<KemProvider> pProvider) {
		auto schemeId = static_cast<uint8_t>(pProvider->scheme());
		auto result = m_kemProviders.emplace(schemeId, std::move(pProvider));
		if (!result.second)
			CATAPULT_THROW_INVALID_ARGUMENT_1("KEM provider already registered for scheme", schemeId);
	}

	const SignatureProvider& CryptoProviderRegistry::signatureProvider(CryptoScheme scheme) const {
		auto schemeId = static_cast<uint8_t>(scheme);
		auto iter = m_signatureProviders.find(schemeId);
		if (m_signatureProviders.end() == iter)
			CATAPULT_THROW_INVALID_ARGUMENT_1("no signature provider registered for scheme", schemeId);

		return *iter->second;
	}

	const KemProvider& CryptoProviderRegistry::kemProvider(CryptoScheme scheme) const {
		auto schemeId = static_cast<uint8_t>(scheme);
		auto iter = m_kemProviders.find(schemeId);
		if (m_kemProviders.end() == iter)
			CATAPULT_THROW_INVALID_ARGUMENT_1("no KEM provider registered for scheme", schemeId);

		return *iter->second;
	}

	const SignatureProvider& CryptoProviderRegistry::defaultSignatureProvider() const {
		return signatureProvider(CryptoScheme::Ed25519);
	}

	bool CryptoProviderRegistry::hasSignatureProvider(CryptoScheme scheme) const {
		return m_signatureProviders.end() != m_signatureProviders.find(static_cast<uint8_t>(scheme));
	}

	bool CryptoProviderRegistry::hasKemProvider(CryptoScheme scheme) const {
		return m_kemProviders.end() != m_kemProviders.find(static_cast<uint8_t>(scheme));
	}
}}
