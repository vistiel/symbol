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
#include "catapult/crypto/Hashes.h"
#include "catapult/types.h"

namespace catapult { namespace model {

	/// V2 Entity hashing that works with variable-length signatures and public keys.
	///
	/// Symbol's entity hash formula:
	///   BlockHash       = SHA3-256(Signature || SignerPublicKey || DataBuffer)
	///   TransactionHash = SHA3-256(Signature || SignerPublicKey || GenerationHashSeed || DataBuffer)
	///
	/// In V1, Signature is always 64 bytes and SignerPublicKey always 32 bytes.
	/// In V2, these sizes depend on the CryptoSchemeId in the entity header.
	namespace EntityHasherV2 {

		/// Calculates the hash for a V2 block header.
		inline Hash256 CalculateBlockHash(const EntityHeaderV2Reader& reader) {
			Hash256 entityHash;
			crypto::Sha3_256_Builder sha3;

			sha3.update(reader.signature());
			sha3.update(reader.signerPublicKey());
			sha3.update(reader.dataBuffer());

			sha3.final(entityHash);
			return entityHash;
		}

		/// Calculates the hash for a V2 block header, excluding \a footerSize bytes.
		inline Hash256 CalculateBlockHash(const EntityHeaderV2Reader& reader, size_t footerSize) {
			Hash256 entityHash;
			crypto::Sha3_256_Builder sha3;

			sha3.update(reader.signature());
			sha3.update(reader.signerPublicKey());

			auto hdrSize = reader.headerSize();
			auto entitySize = reader.size();
			if (entitySize > hdrSize + footerSize) {
				RawBuffer dataBuffer = { reader.data() + hdrSize, entitySize - hdrSize - footerSize };
				sha3.update(dataBuffer);
			}

			sha3.final(entityHash);
			return entityHash;
		}

		/// Calculates the hash for a V2 transaction with the given \a generationHashSeed.
		inline Hash256 CalculateTransactionHash(
				const EntityHeaderV2Reader& reader,
				const GenerationHashSeed& generationHashSeed) {
			Hash256 entityHash;
			crypto::Sha3_256_Builder sha3;

			sha3.update(reader.signature());
			sha3.update(reader.signerPublicKey());
			sha3.update(generationHashSeed);
			sha3.update(reader.dataBuffer());

			sha3.final(entityHash);
			return entityHash;
		}

		/// Calculates the hash for a V2 transaction with explicit data buffer
		/// and \a generationHashSeed.
		inline Hash256 CalculateTransactionHash(
				const EntityHeaderV2Reader& reader,
				const GenerationHashSeed& generationHashSeed,
				const RawBuffer& dataBuffer) {
			Hash256 entityHash;
			crypto::Sha3_256_Builder sha3;

			sha3.update(reader.signature());
			sha3.update(reader.signerPublicKey());
			sha3.update(generationHashSeed);
			sha3.update(dataBuffer);

			sha3.final(entityHash);
			return entityHash;
		}
	}
}}
