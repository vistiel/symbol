"""Variable-length V2 cryptographic types for post-quantum crypto support."""

from binascii import hexlify, unhexlify

from .CryptoScheme import CryptoScheme, PUBLIC_KEY_SIZES, PRIVATE_KEY_SIZES, SIGNATURE_SIZES


class VariableSizeByteArray:
	"""Variable-length byte array for V2 cryptographic values."""

	def __init__(self, array_input, tag=None):
		"""Creates a variable-size byte array from bytes or hex string."""
		raw_bytes = array_input
		if isinstance(raw_bytes, str):
			raw_bytes = unhexlify(raw_bytes)
		if isinstance(raw_bytes, bytearray):
			raw_bytes = bytes(raw_bytes)

		self.bytes = raw_bytes
		self._tag = tag

	@property
	def size(self):
		"""Returns the byte length."""
		return len(self.bytes)

	def __eq__(self, other):
		return isinstance(other, VariableSizeByteArray) and self.bytes == other.bytes and self._tag == other._tag

	def __ne__(self, other):
		return not self == other

	def __hash__(self):
		return hash(self.bytes)

	def __str__(self):
		return hexlify(self.bytes).decode('utf8').upper()

	def __repr__(self):
		return f'{self._tag.__name__ if self._tag else "VariableSizeByteArray"}(\'{str(self)}\')'

	def to_json(self):
		"""Returns representation that can be stored in JSON."""
		return str(self)


class PublicKeyV2(VariableSizeByteArray):
	"""Represents a V2 public key (variable-length)."""

	def __init__(self, public_key):
		raw = public_key.bytes if isinstance(public_key, PublicKeyV2) else public_key
		super().__init__(raw, PublicKeyV2)

	@property
	def crypto_scheme(self):
		"""Infers the crypto scheme from this key's size."""
		for scheme, size in PUBLIC_KEY_SIZES.items():
			if size == len(self.bytes):
				return scheme
		raise ValueError(f'cannot infer crypto scheme from public key size {len(self.bytes)}')

	@staticmethod
	def from_scheme(scheme_id, public_key):
		"""Creates a V2 public key validating against a crypto scheme."""
		pk = PublicKeyV2(public_key)
		expected = PUBLIC_KEY_SIZES.get(scheme_id)
		if expected is None:
			raise ValueError(f'unsupported crypto scheme: {scheme_id}')
		if len(pk.bytes) != expected:
			raise ValueError(f'public key size {len(pk.bytes)} does not match scheme {scheme_id} (expected {expected})')
		return pk


class SignatureV2(VariableSizeByteArray):
	"""Represents a V2 signature (variable-length)."""

	def __init__(self, signature):
		super().__init__(signature, SignatureV2)

	@property
	def crypto_scheme(self):
		"""Infers the crypto scheme from this signature's size."""
		for scheme, size in SIGNATURE_SIZES.items():
			if size == len(self.bytes):
				return scheme
		raise ValueError(f'cannot infer crypto scheme from signature size {len(self.bytes)}')

	@staticmethod
	def zero(scheme_id=CryptoScheme.ED25519):
		"""Creates a zeroed signature for the given scheme."""
		size = SIGNATURE_SIZES.get(scheme_id)
		if size is None:
			raise ValueError(f'unsupported crypto scheme: {scheme_id}')
		return SignatureV2(bytes(size))


class PrivateKeyV2(VariableSizeByteArray):
	"""Represents a V2 private key (variable-length)."""

	def __init__(self, private_key):
		super().__init__(private_key, PrivateKeyV2)

	@property
	def crypto_scheme(self):
		"""Infers the crypto scheme from this key's size."""
		for scheme, size in PRIVATE_KEY_SIZES.items():
			if size == len(self.bytes):
				return scheme
		raise ValueError(f'cannot infer crypto scheme from private key size {len(self.bytes)}')
