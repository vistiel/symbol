import { hexToUint8, uint8ToHex } from '../utils/converter.js';
import { CryptoScheme, PUBLIC_KEY_SIZES, PRIVATE_KEY_SIZES, SIGNATURE_SIZES } from './CryptoScheme.js';

/**
 * Variable-length byte array for V2 cryptographic values.
 * Unlike the V1 ByteArray (which enforces a fixed size), this allows
 * sizes determined at runtime by CryptoSchemeId.
 */
class VariableSizeByteArray {
	/**
	 * Creates a variable-size byte array.
	 * @param {Uint8Array|string} arrayInput Byte array or hex string.
	 * @param {string} name Type name for diagnostics.
	 */
	constructor(arrayInput, name = 'VariableSizeByteArray') {
		let rawBytes = arrayInput;
		if ('string' === typeof rawBytes)
			rawBytes = hexToUint8(rawBytes);

		this.bytes = new Uint8Array(rawBytes);
		this._name = name;
	}

	/** Returns the byte length. */
	get size() {
		return this.bytes.length;
	}

	toString() {
		return uint8ToHex(this.bytes);
	}

	toJson() {
		return this.toString();
	}
}

/**
 * Represents a V2 public key (variable-length: 32B for Ed25519, 1952B for ML-DSA-65).
 */
export class PublicKeyV2 extends VariableSizeByteArray {
	static NAME = 'PublicKeyV2';

	/**
	 * Creates a V2 public key.
	 * @param {Uint8Array|string} publicKey Public key bytes or hex string.
	 */
	constructor(publicKey) {
		super(publicKey instanceof PublicKeyV2 ? publicKey.bytes : publicKey, PublicKeyV2.NAME);
	}

	/**
	 * Infers the crypto scheme from this key's size.
	 * @returns {number} CryptoScheme identifier.
	 */
	get cryptoScheme() {
		for (const [scheme, size] of Object.entries(PUBLIC_KEY_SIZES)) {
			if (Number(size) === this.bytes.length) return Number(scheme);
		}
		throw new Error(`cannot infer crypto scheme from public key size ${this.bytes.length}`);
	}

	/**
	 * Creates a V2 public key validating against a crypto scheme.
	 * @param {number} schemeId Crypto scheme identifier.
	 * @param {Uint8Array|string} publicKey Public key bytes or hex.
	 * @returns {PublicKeyV2} Validated public key.
	 */
	static fromScheme(schemeId, publicKey) {
		const pk = new PublicKeyV2(publicKey);
		const expected = PUBLIC_KEY_SIZES[schemeId];
		if (undefined === expected) throw new Error(`unsupported crypto scheme: ${schemeId}`);
		if (pk.bytes.length !== expected)
			throw new RangeError(`public key size ${pk.bytes.length} does not match scheme ${schemeId} (expected ${expected})`);
		return pk;
	}
}

/**
 * Represents a V2 signature (variable-length: 64B for Ed25519, 3309B for ML-DSA-65).
 */
export class SignatureV2 extends VariableSizeByteArray {
	static NAME = 'SignatureV2';

	constructor(signature) {
		super(signature, SignatureV2.NAME);
	}

	get cryptoScheme() {
		for (const [scheme, size] of Object.entries(SIGNATURE_SIZES)) {
			if (Number(size) === this.bytes.length) return Number(scheme);
		}
		throw new Error(`cannot infer crypto scheme from signature size ${this.bytes.length}`);
	}

	static zero(schemeId = CryptoScheme.ED25519) {
		const size = SIGNATURE_SIZES[schemeId];
		if (undefined === size) throw new Error(`unsupported crypto scheme: ${schemeId}`);
		return new SignatureV2(new Uint8Array(size));
	}
}

/**
 * Represents a V2 private key (variable-length: 32B for Ed25519, 5984B for ML-DSA-65).
 */
export class PrivateKeyV2 extends VariableSizeByteArray {
	static NAME = 'PrivateKeyV2';

	constructor(privateKey) {
		super(privateKey, PrivateKeyV2.NAME);
	}

	get cryptoScheme() {
		for (const [scheme, size] of Object.entries(PRIVATE_KEY_SIZES)) {
			if (Number(size) === this.bytes.length) return Number(scheme);
		}
		throw new Error(`cannot infer crypto scheme from private key size ${this.bytes.length}`);
	}
}

export default {
	PublicKeyV2,
	SignatureV2,
	PrivateKeyV2,
	VariableSizeByteArray
};
