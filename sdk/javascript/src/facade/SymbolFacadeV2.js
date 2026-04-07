import { Hash256 } from '../CryptoTypes.js';
import { KeyPairV2, VerifierV2 } from '../symbol/KeyPairV2.js';
import { PublicKeyV2, SignatureV2 } from '../symbol/CryptoTypesV2.js';
import {
	CryptoScheme,
	getSignatureSize,
	getPublicKeySize,
	getEntityHeaderV2Size
} from '../symbol/CryptoScheme.js';
import { sha3_256 } from '@noble/hashes/sha3.js';

/**
 * Returns the V2 transaction header size for a given crypto scheme.
 * Layout: Size(4) + CryptoSchemeId(1) + Reserved(3) + Signature(S) + PublicKey(K) + Reserved(4)
 * @param {number} schemeId CryptoScheme identifier.
 * @returns {number} Header size.
 */
const getTransactionHeaderV2Size = schemeId => getEntityHeaderV2Size(schemeId);

/**
 * Checks if a serialized entity uses V2 format (non-zero CryptoSchemeId at offset 4).
 * @param {Uint8Array} buffer Serialized entity buffer.
 * @returns {boolean} true if V2 entity.
 */
export const isV2Entity = buffer => {
	if (!buffer || buffer.length < 8) return false;
	return 0 !== buffer[4];
};

/**
 * Reads the CryptoSchemeId from a serialized entity buffer.
 * @param {Uint8Array} buffer Serialized entity buffer.
 * @returns {number} CryptoScheme identifier.
 */
export const getCryptoSchemeFromBuffer = buffer => {
	if (!buffer || buffer.length < 5) throw new Error('buffer too short to read CryptoSchemeId');
	return buffer[4];
};

/**
 * Extracts the signature from a V2 entity buffer.
 * @param {Uint8Array} buffer Serialized V2 entity.
 * @param {number} schemeId CryptoScheme identifier.
 * @returns {SignatureV2} Extracted signature.
 */
export const extractV2Signature = (buffer, schemeId) => {
	const sigSize = getSignatureSize(schemeId);
	return new SignatureV2(buffer.subarray(8, 8 + sigSize));
};

/**
 * Extracts the signer public key from a V2 entity buffer.
 * @param {Uint8Array} buffer Serialized V2 entity.
 * @param {number} schemeId CryptoScheme identifier.
 * @returns {PublicKeyV2} Extracted public key.
 */
export const extractV2SignerPublicKey = (buffer, schemeId) => {
	const sigSize = getSignatureSize(schemeId);
	const keySize = getPublicKeySize(schemeId);
	return new PublicKeyV2(buffer.subarray(8 + sigSize, 8 + sigSize + keySize));
};

/**
 * Gets the transaction data buffer from a V2 entity for signing/hashing.
 * @param {Uint8Array} buffer Serialized V2 transaction.
 * @param {number} schemeId CryptoScheme identifier.
 * @returns {Uint8Array} Data portion of the transaction.
 */
export const transactionDataBufferV2 = (buffer, schemeId) => {
	const headerSize = getTransactionHeaderV2Size(schemeId);
	return buffer.subarray(headerSize);
};

/**
 * V2 extensions for SymbolFacade.
 * Provides methods for signing, verifying, and hashing V2 entities
 * that use variable-length cryptographic fields.
 */
export class SymbolFacadeV2Extensions {
	/**
	 * Creates V2 facade extensions.
	 * @param {object} network Network object with generationHashSeed.
	 */
	constructor(network) {
		this.network = network;
	}

	/**
	 * Gets the payload to sign for a V2 transaction.
	 * @param {Uint8Array} transactionBuffer Serialized V2 transaction.
	 * @param {number} schemeId CryptoScheme identifier.
	 * @returns {Uint8Array} Signable payload (generationHashSeed || transactionData).
	 */
	extractSigningPayloadV2(transactionBuffer, schemeId) {
		const dataBuffer = transactionDataBufferV2(transactionBuffer, schemeId);
		return new Uint8Array([
			...this.network.generationHashSeed.bytes,
			...dataBuffer
		]);
	}

	/**
	 * Signs a V2 transaction buffer.
	 * @param {KeyPairV2} keyPair V2 key pair.
	 * @param {Uint8Array} transactionBuffer Serialized V2 transaction (signature field will be overwritten).
	 * @returns {SignatureV2} Transaction signature.
	 */
	signTransactionV2(keyPair, transactionBuffer) {
		const schemeId = keyPair.cryptoScheme;
		const payload = this.extractSigningPayloadV2(transactionBuffer, schemeId);
		return keyPair.sign(payload);
	}

	/**
	 * Verifies a V2 transaction signature.
	 * @param {Uint8Array} transactionBuffer Serialized V2 transaction.
	 * @returns {boolean} true if signature is valid.
	 */
	verifyTransactionV2(transactionBuffer) {
		const schemeId = getCryptoSchemeFromBuffer(transactionBuffer);
		const signature = extractV2Signature(transactionBuffer, schemeId);
		const publicKey = extractV2SignerPublicKey(transactionBuffer, schemeId);
		const payload = this.extractSigningPayloadV2(transactionBuffer, schemeId);
		return new VerifierV2(publicKey).verify(payload, signature);
	}

	/**
	 * Hashes a V2 transaction.
	 * @param {Uint8Array} transactionBuffer Serialized V2 transaction.
	 * @returns {Hash256} Transaction hash.
	 */
	hashTransactionV2(transactionBuffer) {
		const schemeId = getCryptoSchemeFromBuffer(transactionBuffer);
		const signature = extractV2Signature(transactionBuffer, schemeId);
		const publicKey = extractV2SignerPublicKey(transactionBuffer, schemeId);
		const dataBuffer = transactionDataBufferV2(transactionBuffer, schemeId);

		const hasher = sha3_256.create();
		hasher.update(signature.bytes);
		hasher.update(publicKey.bytes);
		hasher.update(this.network.generationHashSeed.bytes);
		hasher.update(dataBuffer);
		return new Hash256(hasher.digest());
	}
}

export default {
	SymbolFacadeV2Extensions,
	isV2Entity,
	getCryptoSchemeFromBuffer,
	extractV2Signature,
	extractV2SignerPublicKey,
	transactionDataBufferV2
};
