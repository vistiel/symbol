import { PublicKeyV2, SignatureV2, PrivateKeyV2 } from './CryptoTypesV2.js';
import { CryptoScheme, PUBLIC_KEY_SIZES, PRIVATE_KEY_SIZES, SIGNATURE_SIZES } from './CryptoScheme.js';
import ed25519 from '../impl/ed25519.js';
import { deepCompare } from '../utils/arrayHelpers.js';

const HASH_MODE = 'Sha2_512';

// ML-DSA-65 key/signature constants
const ML_DSA_65_OQS_SECRET_KEY_SIZE = 4032;
const ML_DSA_65_PUBLIC_KEY_SIZE = 1952;

/**
 * Registry of PQC signing implementations.
 * The ML-DSA-65 backend must be registered externally (native addon or WASM).
 *
 * Expected backend interface:
 *   {
 *     generateKeyPair(): { publicKey: Uint8Array(1952), secretKey: Uint8Array(4032) }
 *     sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array(3309)
 *     verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean
 *   }
 */
const pqcBackends = {};

/**
 * Registers a PQC signing backend for a given crypto scheme.
 * @param {number} schemeId CryptoScheme identifier.
 * @param {object} backend Implementation object with generateKeyPair/sign/verify.
 */
export const registerPqcBackend = (schemeId, backend) => {
	pqcBackends[schemeId] = backend;
};

/**
 * Gets the registered PQC backend for a given crypto scheme.
 * @param {number} schemeId CryptoScheme identifier.
 * @returns {object} Backend implementation.
 */
const getPqcBackend = schemeId => {
	const backend = pqcBackends[schemeId];
	if (!backend) throw new Error(`no PQC backend registered for scheme ${schemeId}; call registerPqcBackend() first`);
	return backend;
};

/**
 * Represents a V2 key pair supporting both Ed25519 and post-quantum schemes.
 */
export class KeyPairV2 {
	/**
	 * Creates a V2 key pair from a private key.
	 * @param {PrivateKeyV2} privateKey V2 private key (size determines scheme).
	 */
	constructor(privateKey) {
		if (!(privateKey instanceof PrivateKeyV2))
			throw new TypeError('privateKey must be a PrivateKeyV2 instance');

		this._scheme = privateKey.cryptoScheme;
		this._privateKey = privateKey;

		if (CryptoScheme.ED25519 === this._scheme) {
			this._keyPair = ed25519.get().keyPairFromSeed(HASH_MODE, this._privateKey.bytes);
		}
		// For PQC schemes, the public key is extracted from the stored private key format
	}

	/** Gets the crypto scheme identifier. */
	get cryptoScheme() {
		return this._scheme;
	}

	/**
	 * Gets the public key.
	 * @returns {PublicKeyV2} Public key.
	 */
	get publicKey() {
		if (CryptoScheme.ED25519 === this._scheme) {
			return new PublicKeyV2(this._keyPair.publicKey);
		}

		// ML-DSA-65: public key is stored at offset OQS_SECRET_KEY_SIZE in the private key
		const pkOffset = ML_DSA_65_OQS_SECRET_KEY_SIZE;
		return new PublicKeyV2(this._privateKey.bytes.subarray(pkOffset, pkOffset + ML_DSA_65_PUBLIC_KEY_SIZE));
	}

	/**
	 * Gets the private key.
	 * @returns {PrivateKeyV2} Private key.
	 */
	get privateKey() {
		return new PrivateKeyV2(this._privateKey.bytes);
	}

	/**
	 * Signs a message.
	 * @param {Uint8Array} message Message to sign.
	 * @returns {SignatureV2} Signature.
	 */
	sign(message) {
		if (CryptoScheme.ED25519 === this._scheme) {
			return new SignatureV2(ed25519.get().sign(HASH_MODE, message, this._keyPair));
		}

		const backend = getPqcBackend(this._scheme);
		const oqsSk = this._privateKey.bytes.subarray(0, ML_DSA_65_OQS_SECRET_KEY_SIZE);
		return new SignatureV2(backend.sign(message, oqsSk));
	}

	/**
	 * Generates a new V2 key pair for the given crypto scheme.
	 * @param {number} schemeId CryptoScheme identifier.
	 * @returns {Promise<KeyPairV2>} Generated key pair.
	 */
	static async generate(schemeId = CryptoScheme.ED25519) {
		if (CryptoScheme.ED25519 === schemeId) {
			const { randomBytes } = await import('crypto');
			const seed = randomBytes(32);
			return new KeyPairV2(new PrivateKeyV2(seed));
		}

		const backend = getPqcBackend(schemeId);
		const { publicKey: pk, secretKey: sk } = backend.generateKeyPair();

		// Store in our format: sk(4032) || pk(1952)
		const combined = new Uint8Array(PRIVATE_KEY_SIZES[schemeId]);
		combined.set(sk, 0);
		combined.set(pk, sk.length);
		return new KeyPairV2(new PrivateKeyV2(combined));
	}
}

/**
 * Verifies V2 signatures from any supported crypto scheme.
 */
export class VerifierV2 {
	/**
	 * Creates a V2 verifier from a public key.
	 * @param {PublicKeyV2} publicKey V2 public key.
	 */
	constructor(publicKey) {
		if (!(publicKey instanceof PublicKeyV2))
			throw new TypeError('publicKey must be a PublicKeyV2 instance');

		if (0 === deepCompare(new Uint8Array(publicKey.bytes.length), publicKey.bytes))
			throw new Error('public key cannot be zero');

		this.publicKey = publicKey;
		this._scheme = publicKey.cryptoScheme;
	}

	/** Gets the crypto scheme identifier. */
	get cryptoScheme() {
		return this._scheme;
	}

	/**
	 * Verifies a message signature.
	 * @param {Uint8Array} message Message to verify.
	 * @param {SignatureV2} signature Signature to verify.
	 * @returns {boolean} true if signature is valid.
	 */
	verify(message, signature) {
		if (CryptoScheme.ED25519 === this._scheme) {
			return ed25519.get().verify(HASH_MODE, message, signature.bytes, this.publicKey.bytes);
		}

		const backend = getPqcBackend(this._scheme);
		return backend.verify(message, signature.bytes, this.publicKey.bytes);
	}
}

export default {
	KeyPairV2,
	VerifierV2,
	registerPqcBackend
};
