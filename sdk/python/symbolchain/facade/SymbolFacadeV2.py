"""V2 extensions for SymbolFacade supporting variable-length crypto fields."""

import hashlib

from ..CryptoTypes import Hash256
from ..symbol.CryptoScheme import CryptoScheme, get_signature_size, get_public_key_size, get_entity_header_v2_size
from ..symbol.CryptoTypesV2 import PublicKeyV2, SignatureV2
from ..symbol.KeyPairV2 import VerifierV2


def is_v2_entity(buffer):
	"""Checks if a serialized entity uses V2 format (non-zero CryptoSchemeId at offset 4)."""
	if not buffer or len(buffer) < 8:
		return False
	return buffer[4] != 0


def get_crypto_scheme_from_buffer(buffer):
	"""Reads the CryptoSchemeId from a serialized entity buffer."""
	if not buffer or len(buffer) < 5:
		raise ValueError('buffer too short to read CryptoSchemeId')
	return buffer[4]


def extract_v2_signature(buffer, scheme_id):
	"""Extracts the signature from a V2 entity buffer."""
	sig_size = get_signature_size(scheme_id)
	return SignatureV2(buffer[8:8 + sig_size])


def extract_v2_signer_public_key(buffer, scheme_id):
	"""Extracts the signer public key from a V2 entity buffer."""
	sig_size = get_signature_size(scheme_id)
	key_size = get_public_key_size(scheme_id)
	offset = 8 + sig_size
	return PublicKeyV2(buffer[offset:offset + key_size])


def transaction_data_buffer_v2(buffer, scheme_id):
	"""Gets the transaction data buffer from a V2 entity for signing/hashing."""
	header_size = get_entity_header_v2_size(scheme_id)
	return buffer[header_size:]


class SymbolFacadeV2Extensions:
	"""V2 extensions for SymbolFacade for signing, verifying, and hashing V2 entities."""

	def __init__(self, network):
		"""Creates V2 facade extensions."""
		self.network = network

	def extract_signing_payload_v2(self, transaction_buffer, scheme_id):
		"""Gets the payload to sign for a V2 transaction."""
		data_buffer = transaction_data_buffer_v2(transaction_buffer, scheme_id)
		return self.network.generation_hash_seed.bytes + data_buffer

	def sign_transaction_v2(self, key_pair, transaction_buffer):
		"""Signs a V2 transaction buffer."""
		scheme_id = key_pair.crypto_scheme
		payload = self.extract_signing_payload_v2(transaction_buffer, scheme_id)
		return key_pair.sign(payload)

	def verify_transaction_v2(self, transaction_buffer):
		"""Verifies a V2 transaction signature."""
		scheme_id = get_crypto_scheme_from_buffer(transaction_buffer)
		signature = extract_v2_signature(transaction_buffer, scheme_id)
		public_key = extract_v2_signer_public_key(transaction_buffer, scheme_id)
		payload = self.extract_signing_payload_v2(transaction_buffer, scheme_id)
		return VerifierV2(public_key).verify(payload, signature)

	def hash_transaction_v2(self, transaction_buffer):
		"""Hashes a V2 transaction."""
		scheme_id = get_crypto_scheme_from_buffer(transaction_buffer)
		signature = extract_v2_signature(transaction_buffer, scheme_id)
		public_key = extract_v2_signer_public_key(transaction_buffer, scheme_id)
		data_buffer = transaction_data_buffer_v2(transaction_buffer, scheme_id)

		hasher = hashlib.sha3_256()
		hasher.update(signature.bytes)
		hasher.update(public_key.bytes)
		hasher.update(self.network.generation_hash_seed.bytes)
		hasher.update(data_buffer)
		return Hash256(hasher.digest())
