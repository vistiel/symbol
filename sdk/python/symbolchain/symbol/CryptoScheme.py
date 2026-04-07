"""Cryptographic scheme identifiers matching CryptoSchemeId in types.cats."""

from enum import IntEnum


class CryptoScheme(IntEnum):
	"""Enumeration of supported cryptographic schemes."""

	ED25519 = 0x00
	"""Ed25519 (default, backward-compatible with V1)."""

	ML_DSA_65 = 0x01
	"""ML-DSA-65 (NIST FIPS 204, Dilithium3)."""


SIGNATURE_SIZES = {
	CryptoScheme.ED25519: 64,
	CryptoScheme.ML_DSA_65: 3309,
}

PUBLIC_KEY_SIZES = {
	CryptoScheme.ED25519: 32,
	CryptoScheme.ML_DSA_65: 1952,
}

PRIVATE_KEY_SIZES = {
	CryptoScheme.ED25519: 32,
	CryptoScheme.ML_DSA_65: 5984,  # OQS secret key (4032) + public key (1952)
}


def get_signature_size(scheme_id):
	"""Gets the signature size for a given crypto scheme."""
	if scheme_id not in SIGNATURE_SIZES:
		raise ValueError(f'unsupported crypto scheme: {scheme_id}')
	return SIGNATURE_SIZES[scheme_id]


def get_public_key_size(scheme_id):
	"""Gets the public key size for a given crypto scheme."""
	if scheme_id not in PUBLIC_KEY_SIZES:
		raise ValueError(f'unsupported crypto scheme: {scheme_id}')
	return PUBLIC_KEY_SIZES[scheme_id]


def get_entity_header_v2_size(scheme_id):
	"""Gets the V2 entity header size for a given crypto scheme."""
	return 4 + 1 + 3 + get_signature_size(scheme_id) + get_public_key_size(scheme_id) + 4
