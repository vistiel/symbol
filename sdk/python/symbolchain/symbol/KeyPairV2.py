"""V2 key pair and verifier supporting Ed25519 and post-quantum schemes."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .CryptoScheme import CryptoScheme, PRIVATE_KEY_SIZES
from .CryptoTypesV2 import PublicKeyV2, SignatureV2, PrivateKeyV2

# ML-DSA-65 key layout constants
_ML_DSA_65_OQS_SECRET_KEY_SIZE = 4032
_ML_DSA_65_PUBLIC_KEY_SIZE = 1952

# PQC backend registry
_pqc_backends = {}


def register_pqc_backend(scheme_id, backend):
	"""Registers a PQC signing backend for a given crypto scheme.

	Expected backend interface:
		generate_key_pair() -> (public_key: bytes, secret_key: bytes)
		sign(message: bytes, secret_key: bytes) -> bytes
		verify(message: bytes, signature: bytes, public_key: bytes) -> bool
	"""
	_pqc_backends[scheme_id] = backend


def _get_pqc_backend(scheme_id):
	if scheme_id not in _pqc_backends:
		raise RuntimeError(f'no PQC backend registered for scheme {scheme_id}; call register_pqc_backend() first')
	return _pqc_backends[scheme_id]


class KeyPairV2:
	"""Represents a V2 key pair supporting Ed25519 and post-quantum schemes."""

	def __init__(self, private_key):
		"""Creates a V2 key pair from a V2 private key (size determines scheme)."""
		if not isinstance(private_key, PrivateKeyV2):
			raise TypeError('private_key must be a PrivateKeyV2 instance')

		self._scheme = private_key.crypto_scheme
		self._private_key = private_key

		if self._scheme == CryptoScheme.ED25519:
			self._sk = ed25519.Ed25519PrivateKey.from_private_bytes(private_key.bytes)

	@property
	def crypto_scheme(self):
		"""Gets the crypto scheme identifier."""
		return self._scheme

	@property
	def public_key(self):
		"""Gets the public key."""
		if self._scheme == CryptoScheme.ED25519:
			raw = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
			return PublicKeyV2(raw)

		# ML-DSA-65: public key stored at offset OQS_SECRET_KEY_SIZE
		pk_offset = _ML_DSA_65_OQS_SECRET_KEY_SIZE
		return PublicKeyV2(self._private_key.bytes[pk_offset:pk_offset + _ML_DSA_65_PUBLIC_KEY_SIZE])

	@property
	def private_key(self):
		"""Gets the private key."""
		return PrivateKeyV2(self._private_key.bytes)

	def sign(self, message):
		"""Signs a message."""
		if self._scheme == CryptoScheme.ED25519:
			return SignatureV2(self._sk.sign(message))

		backend = _get_pqc_backend(self._scheme)
		oqs_sk = self._private_key.bytes[:_ML_DSA_65_OQS_SECRET_KEY_SIZE]
		return SignatureV2(backend.sign(message, oqs_sk))

	@staticmethod
	def generate(scheme_id=CryptoScheme.ED25519):
		"""Generates a new V2 key pair for the given crypto scheme."""
		if scheme_id == CryptoScheme.ED25519:
			sk = ed25519.Ed25519PrivateKey.generate()
			raw_sk = sk.private_bytes(
				encoding=serialization.Encoding.Raw,
				format=serialization.PrivateFormat.Raw,
				encryption_algorithm=serialization.NoEncryption()
			)
			return KeyPairV2(PrivateKeyV2(raw_sk))

		backend = _get_pqc_backend(scheme_id)
		pk, sk = backend.generate_key_pair()

		# Store in our format: sk || pk
		combined = sk + pk
		if len(combined) != PRIVATE_KEY_SIZES[scheme_id]:
			raise ValueError(f'generated key size mismatch: {len(combined)} != {PRIVATE_KEY_SIZES[scheme_id]}')
		return KeyPairV2(PrivateKeyV2(combined))


class VerifierV2:
	"""Verifies V2 signatures from any supported crypto scheme."""

	def __init__(self, public_key):
		"""Creates a V2 verifier from a V2 public key."""
		if not isinstance(public_key, PublicKeyV2):
			raise TypeError('public_key must be a PublicKeyV2 instance')

		if bytes(len(public_key.bytes)) == public_key.bytes:
			raise ValueError('public key cannot be zero')

		self.public_key = public_key
		self._scheme = public_key.crypto_scheme

		if self._scheme == CryptoScheme.ED25519:
			self._pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key.bytes)

	@property
	def crypto_scheme(self):
		"""Gets the crypto scheme identifier."""
		return self._scheme

	def verify(self, message, signature):
		"""Verifies a message signature."""
		if self._scheme == CryptoScheme.ED25519:
			try:
				self._pk.verify(signature.bytes, message)
				return True
			except InvalidSignature:
				return False

		backend = _get_pqc_backend(self._scheme)
		return backend.verify(message, signature.bytes, self.public_key.bytes)
