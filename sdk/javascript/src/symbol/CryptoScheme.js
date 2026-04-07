/**
 * Cryptographic scheme identifiers matching CryptoSchemeId in types.cats.
 * Used for dispatching V2 crypto operations to the appropriate algorithm.
 */

/**
 * Enumeration of supported cryptographic schemes.
 */
export const CryptoScheme = Object.freeze({
	/** Ed25519 (default, backward-compatible with V1). */
	ED25519: 0x00,

	/** ML-DSA-65 (NIST FIPS 204, Dilithium3). */
	ML_DSA_65: 0x01
});

/** Signature sizes per crypto scheme (bytes). */
export const SIGNATURE_SIZES = Object.freeze({
	[CryptoScheme.ED25519]: 64,
	[CryptoScheme.ML_DSA_65]: 3309
});

/** Public key sizes per crypto scheme (bytes). */
export const PUBLIC_KEY_SIZES = Object.freeze({
	[CryptoScheme.ED25519]: 32,
	[CryptoScheme.ML_DSA_65]: 1952
});

/** Private key sizes per crypto scheme (bytes). */
export const PRIVATE_KEY_SIZES = Object.freeze({
	[CryptoScheme.ED25519]: 32,
	[CryptoScheme.ML_DSA_65]: 5984 // OQS secret key (4032) || public key (1952)
});

/**
 * Gets the signature size for a given crypto scheme.
 * @param {number} schemeId Crypto scheme identifier.
 * @returns {number} Signature size in bytes.
 */
export const getSignatureSize = schemeId => {
	const size = SIGNATURE_SIZES[schemeId];
	if (undefined === size) throw new Error(`unsupported crypto scheme: ${schemeId}`);
	return size;
};

/**
 * Gets the public key size for a given crypto scheme.
 * @param {number} schemeId Crypto scheme identifier.
 * @returns {number} Public key size in bytes.
 */
export const getPublicKeySize = schemeId => {
	const size = PUBLIC_KEY_SIZES[schemeId];
	if (undefined === size) throw new Error(`unsupported crypto scheme: ${schemeId}`);
	return size;
};

/**
 * Gets the V2 entity header size for a given crypto scheme.
 * Header layout: Size(4) + CryptoSchemeId(1) + Reserved(3) + Signature(S) + PublicKey(K) + Reserved(4)
 * @param {number} schemeId Crypto scheme identifier.
 * @returns {number} Header size in bytes.
 */
export const getEntityHeaderV2Size = schemeId => 4 + 1 + 3 + getSignatureSize(schemeId) + getPublicKeySize(schemeId) + 4;

export default CryptoScheme;
