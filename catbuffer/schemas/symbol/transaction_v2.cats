import "entity_v2.cats"
import "transaction_type.cats"

# V2 transaction with crypto-agile (variable-length) signatures and keys.
#
# The V2 format introduces CryptoSchemeId to support post-quantum
# cryptographic schemes alongside the existing Ed25519.
# Entity parsing uses CryptoSchemeId to determine field sizes at runtime.
#
# NOTE: This schema defines the logical structure. The actual wire format
# requires runtime interpretation of CryptoSchemeId to determine
# signature and public key sizes. Concrete V2 transaction types
# (e.g., TransferTransactionV2) will be defined per transaction plugin.

# V2 binary layout for an embedded transaction header.
inline struct EmbeddedTransactionHeaderV2
	inline SizePrefixedEntityV2

	# Cryptographic scheme used for the signer's public key.
	crypto_scheme_id = CryptoSchemeId

	# Reserved padding to align end of EmbeddedTransactionHeaderV2 on 8-byte boundary.
	embedded_transaction_header_v2_reserved_1 = make_reserved(uint8, 0)
	embedded_transaction_header_v2_reserved_2 = make_reserved(uint8, 0)
	embedded_transaction_header_v2_reserved_3 = make_reserved(uint8, 0)
