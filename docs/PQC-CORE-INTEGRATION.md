# Phase 3: PQC Core Integration

## Overview

Phase 3 migrates the core cryptographic operations (signing, verification, hashing, address derivation) to use the CryptoProviderRegistry abstraction from Phase 1, combined with the V2 wire format from Phase 2. This creates a complete V2 pipeline where transactions and blocks can be signed and verified using any registered cryptographic scheme (Ed25519, ML-DSA-65, or future algorithms).

**Core Principle**: All V1 APIs are preserved unchanged. V2 APIs are purely additive — they coexist with V1 functions and route through the CryptoProviderRegistry for scheme-agnostic operation.

## Architecture

```
                    ┌──────────────────────────────────┐
                    │     Application Layer              │
                    │  (Consumers, Validators, etc.)     │
                    └───────┬──────────────┬────────────┘
                            │              │
                  ┌─────────▼──────┐ ┌─────▼──────────┐
                  │   V1 APIs      │ │   V2 APIs       │
                  │  (Ed25519      │ │  (Any scheme     │
                  │   fixed-size)  │ │   variable-size) │
                  └─────┬──────────┘ └────┬────────────┘
                        │                 │
                        │    ┌────────────▼────────────┐
                        │    │ CryptoProviderRegistry   │
                        │    │   ├── Ed25519Provider    │
                        │    │   ├── MlDsa65Provider    │
                        │    │   └── (future schemes)   │
                        │    └─────────────────────────┘
                        │                 │
                  ┌─────▼─────┐  ┌───────▼──────────┐
                  │  donna     │  │  liboqs (ML-DSA)  │
                  │ (Ed25519)  │  │  (future: ML-KEM) │
                  └────────────┘  └──────────────────┘
```

## New Files

### `src/catapult/crypto/SignerV2.h`

V2 counterpart to `Signer.h`. Provides scheme-agnostic signing and verification via the registry.

| Function | Description |
|----------|-------------|
| `SignV2(registry, scheme, privKey, pubKey, buffers, signature)` | Sign multiple buffers |
| `SignV2(registry, scheme, privKey, pubKey, buffer, signature)` | Sign single buffer |
| `VerifyV2(registry, scheme, pubKey, buffers, signature)` | Verify against multiple buffers |
| `VerifyV2(registry, scheme, pubKey, buffer, signature)` | Verify against single buffer |
| `VerifyMultiV2(registry, inputs, count)` | Batch verify (returns per-signature results) |
| `VerifyMultiV2ShortCircuit(registry, inputs, count)` | Batch verify, stop on first failure |
| `GenerateKeyPairV2(registry, scheme)` | Generate private + public key pair |

**Key difference from V1**: V1 uses fixed-size `Key` (32B) and `Signature` (64B). V2 uses variable-length `CryptoBuffer` and `SecureCryptoBuffer`.

**Batch verification note**: V1's `VerifyMulti` uses Ed25519 batch verification (multi-scalar multiplication). Since PQC schemes lack this mathematical property, `VerifyMultiV2` verifies each signature individually. A future optimization could segregate Ed25519 inputs for batch processing.

### `src/catapult/model/EntityHasherV2.h`

V2 counterpart to `EntityHasher.cpp`. Computes hashes for V2 entities with variable-length signatures and public keys.

| Function | Description |
|----------|-------------|
| `CalculateBlockHash(reader)` | Hash block from V2 entity reader |
| `CalculateBlockHash(reader, footer)` | Hash block with footer data |
| `CalculateTransactionHash(reader, generationHashSeed)` | Hash transaction with generation hash |

**Hash formula** (transaction):
```
SHA3-256( Signature || SignerPublicKey || GenerationHashSeed || EntityBody )
```

This is identical to V1's formula but supports variable-length signature and key fields via the `EntityHeaderV2Reader`.

### `src/catapult/model/BlockUtilsV2.h`

V2 counterpart to `BlockUtils.cpp`. Provides block and transaction signing/verification using V2 wire format.

| Function | Description |
|----------|-------------|
| `SignBlockHeader(registry, scheme, privKey, pubKey, buffer, size)` | Sign a block header |
| `VerifyBlockHeaderSignature(registry, buffer, size)` | Verify block header signature |
| `SignTransaction(registry, scheme, privKey, pubKey, buffer, size)` | Sign a transaction |
| `VerifyTransactionSignature(registry, buffer, size)` | Verify transaction signature |
| `SignTransactionWithReplayProtection(...)` | Sign with generation hash prepended |
| `VerifyTransactionSignatureWithReplayProtection(...)` | Verify with replay protection |

### `src/catapult/model/AddressV2.h`

V2 counterpart to `Address.cpp`. Derives addresses from variable-length public keys.

| Function | Description |
|----------|-------------|
| `PublicKeyToAddress(key, keySize, network, scheme)` | Derive address from raw key bytes |
| `PublicKeyToAddress(cryptoBuffer, network, scheme)` | Derive address from CryptoBuffer |
| `IsValidAddress(address)` | Validate checksum |
| `ExtractSchemeHint(address)` | Extract CryptoSchemeId from address byte |

**Address format**:
```
Byte 0:    NetworkIdentifier (0x68 = Mainnet, 0x98 = Testnet)
Byte 1:    SHA3-256(pubKey)[0] XOR CryptoSchemeId
Bytes 2-20: SHA3-256(pubKey)[1..19]
Bytes 21-23: SHA3-256(Bytes 0-20)[0..2]  (checksum)
```

The XOR of `CryptoSchemeId` into byte 1 ensures that:
- Ed25519 addresses (scheme 0x00) are identical to V1 addresses
- ML-DSA-65 addresses (scheme 0x01) produce distinct addresses for the same public key hash

## Bug Fix: ML-DSA-65 Private Key Format

### Problem

The original `MlDsa65SignatureProvider::generatePrivateKey()` generated a keypair via `OQS_SIG_ml_dsa_65_keypair()` but discarded the public key. The `extractPublicKey()` method then attempted to read the last 1952 bytes of the 4032-byte OQS secret key as the public key.

**This is incorrect**: Unlike Ed25519 (where libsodium stores `sk || pk`), the ML-DSA-65 secret key format in liboqs is:
```
ρ (32B) || K (32B) || tr (64B) || s₁ || s₂ || t₀    [4032 bytes total]
```
The public key `ρ || t₁` is NOT embedded at the end of the secret key.

### Fix

Adopted the libsodium convention: store `sk(4032) || pk(1952)` in the private key buffer:

```cpp
// Header
static constexpr size_t Oqs_Secret_Key_Size = 4032;
static constexpr size_t Private_Key_Size = Oqs_Secret_Key_Size + Public_Key_Size;  // 5984

// Key generation: write pk after sk
OQS_SIG_ml_dsa_65_keypair(
    privateKey.data() + Oqs_Secret_Key_Size,  // pk at offset 4032
    privateKey.data());                       // sk at offset 0

// Public key extraction: read from offset 4032
publicKey = CryptoBuffer(privateKey.data() + Oqs_Secret_Key_Size, Public_Key_Size);
```

liboqs `sign()` only reads the first 4032 bytes from the secret key pointer, so the embedded public key does not interfere.

## Tests

### `tests/catapult/crypto/CoreIntegrationV2Tests.cpp`

12 standalone end-to-end tests covering the full V2 pipeline:

| # | Test | Description |
|---|------|-------------|
| 1 | KeyPair_Generation_Via_Registry | Generate ML-DSA-65 keypair through registry, verify sizes |
| 2 | SignV2_VerifyV2_RoundTrip | Sign/verify round-trip with raw buffers |
| 3 | Tampered_Message_Rejected | Modified message fails verification |
| 4 | Wrong_Key_Rejected | Signature verified with wrong key fails |
| 5 | V2_Transaction_SignVerify | Full V2 transaction build → sign → verify cycle |
| 6 | BatchVerifyMultiV2 | Batch verify 5 independent signatures |
| 7 | BatchVerify_WithBadSignature | Batch verify with one known-bad signature |
| 8 | EntityHashV2_TransactionHash | Hash determinism and seed sensitivity |
| 9 | AddressV2_Derivation | Address from ML-DSA-65 key: determinism, uniqueness |
| 10 | AddressV2_DifferentNetworks | Same key, different network → different address |
| 11 | EndToEnd_Pipeline | Full pipeline: keygen → address → tx build → sign → hash → verify |
| 12 | Performance_Benchmark | ML-DSA-65 Sign/Verify throughput (100 iterations) |

### Build & Run

```bash
cd client/catapult
g++ -std=c++17 -O2 -I/usr/local/include \
    -o core_v2_test tests/catapult/crypto/CoreIntegrationV2Tests.cpp \
    -L/usr/local/lib -loqs
LD_LIBRARY_PATH=/usr/local/lib ./core_v2_test
```

### Performance Results

| Operation | Latency |
|-----------|---------|
| ML-DSA-65 SignV2 | ~107 µs/op |
| ML-DSA-65 VerifyV2 | ~38 µs/op |

For comparison, Ed25519 Sign is ~20 µs and Verify is ~60 µs. ML-DSA-65 signing is ~5x slower but verification is ~1.6x faster — a favorable tradeoff since nodes verify far more often than they sign.

## Migration Path: V1 → V2

The V2 APIs are designed for parallel deployment alongside V1:

1. **Node startup**: Register providers in `CryptoProviderRegistry` (Ed25519 auto-registered, ML-DSA-65 registered by plugin)
2. **Transaction processing**: Check `CryptoSchemeId` field in entity header
   - `0x00` (Ed25519): Use V1 path (zero overhead, existing code unchanged)
   - `0x01` (ML-DSA-65): Use V2 path (registry dispatch)
3. **Block verification**: `VerifyBlockHeaderSignature` reads scheme from header, dispatches accordingly
4. **Address derivation**: V2 addresses with scheme `0x00` are identical to V1 addresses

## Relationship to Other Phases

- **Phase 1** (Abstraction Layer): Provides `CryptoProviderRegistry`, `SignatureProvider`, `MlDsa65SignatureProvider`
- **Phase 2** (Wire Protocol V2): Provides `EntityHeaderV2Reader/Writer`, `EntitySerializerV2`, V2 catbuffer schemas
- **Phase 3** (This): Connects Phase 1 providers with Phase 2 wire format through V2 signing/hashing/address APIs
- **Phase 4** (Cache & Performance): Will integrate V2 entities into blockchain state management
- **Phase 5** (SDK & Migration): Will expose V2 APIs to SDKs and provide migration tooling
