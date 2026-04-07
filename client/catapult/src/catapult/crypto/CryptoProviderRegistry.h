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
#include "CryptoProvider.h"
#include <unordered_map>

namespace catapult { namespace crypto {

	/// Registry that maps crypto scheme identifiers to their providers.
	/// This is the central point for crypto agility — new schemes are registered here.
	class CryptoProviderRegistry {
	public:
		/// Creates a registry with the default (Ed25519) provider pre-registered.
		CryptoProviderRegistry();

	public:
		/// Registers a signature \a provider for the given scheme.
		/// \note Throws if a provider for the same scheme is already registered.
		void registerSignatureProvider(std::shared_ptr<SignatureProvider> pProvider);

		/// Registers a KEM \a provider for the given scheme.
		/// \note Throws if a provider for the same scheme is already registered.
		void registerKemProvider(std::shared_ptr<KemProvider> pProvider);

	public:
		/// Gets the signature provider for \a scheme.
		/// \note Throws if scheme is not registered.
		const SignatureProvider& signatureProvider(CryptoScheme scheme) const;

		/// Gets the KEM provider for \a scheme.
		/// \note Throws if scheme is not registered.
		const KemProvider& kemProvider(CryptoScheme scheme) const;

		/// Gets the default signature provider (Ed25519).
		const SignatureProvider& defaultSignatureProvider() const;

		/// Returns \c true if a signature provider is registered for \a scheme.
		bool hasSignatureProvider(CryptoScheme scheme) const;

		/// Returns \c true if a KEM provider is registered for \a scheme.
		bool hasKemProvider(CryptoScheme scheme) const;

	private:
		std::unordered_map<uint8_t, std::shared_ptr<SignatureProvider>> m_signatureProviders;
		std::unordered_map<uint8_t, std::shared_ptr<KemProvider>> m_kemProviders;
	};
}}
