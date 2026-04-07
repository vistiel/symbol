import "transaction_v2.cats"

# V2 cosignature with crypto-agile (variable-length) signatures and keys.
#
# Unlike V1 Cosignature which has fixed-size PublicKey (32B) and Signature (64B),
# V2 includes a CryptoSchemeId to support variable-length crypto fields.

# V2 Cosignature attached to an AggregateCompleteTransaction or AggregateBondedTransaction.
#
# Wire format:
#   [8 bytes]  Version (uint64)
#   [1 byte]   CryptoSchemeId
#   [7 bytes]  Reserved padding
#   [K bytes]  SignerPublicKey — size determined by CryptoSchemeId
#   [S bytes]  Signature — size determined by CryptoSchemeId
#
# For ED25519: K=32, S=64 → total = 8+8+32+64 = 112 bytes
# For ML_DSA_65: K=1952, S=3309 → total = 8+8+1952+3309 = 5277 bytes
@is_aligned
struct CosignatureV2
	# Version.
	version = uint64

	# Cryptographic scheme used for cosigner keys and signature.
	crypto_scheme_id = CryptoSchemeId

	# Reserved padding.
	cosignature_v2_reserved_1 = make_reserved(uint8, 0)
	cosignature_v2_reserved_2 = make_reserved(uint8, 0)
	cosignature_v2_reserved_3 = make_reserved(uint8, 0)
	cosignature_v2_reserved_4 = make_reserved(uint32, 0)

# V2 Cosignature detached from an aggregate transaction.
@is_aligned
struct DetachedCosignatureV2
	inline CosignatureV2

	# Hash of the AggregateBondedTransaction that is signed by this cosignature.
	parent_hash = Hash256
