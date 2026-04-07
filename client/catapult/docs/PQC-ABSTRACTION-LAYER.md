# Post-Quantum Cryptography Abstraction Layer

## 概要

このドキュメントは、Symbol (catapult) ブロックチェーンに量子耐性暗号を導入するための **Phase 1: 暗号抽象化レイヤー** の実装記録です。

### 背景

Symbol は現在 Ed25519 署名を `donna` ライブラリ経由でハードコードしており、将来の暗号方式変更に対応する仕組みがありません。量子コンピュータの発展に備えて、署名方式を差し替え可能にする抽象化レイヤーを導入しました。

### 目的

- 既存の Ed25519 コードを変更せずに、暗号プロバイダーの抽象化インターフェースを追加する
- NIST PQC 標準 ML-DSA-65 (Dilithium3) の署名プロバイダーを liboqs 経由で実装する
- 将来のハードフォークで暗号方式を切り替えるための基盤を整備する

---

## アーキテクチャ

```
                  ┌──────────────────────────┐
                  │  CryptoProviderRegistry  │
                  └────────────┬─────────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
      ┌───────────────────┐ ┌─────────────┐ ┌──────────┐
      │ SignatureProvider │ │ KemProvider │ │  (将来)  │
      │    (abstract)     │ │ (abstract)  │ │          │
      └───────┬───────────┘ └─────────────┘ └──────────┘
              │
      ┌───────┴──────────┐
      ▼                  ▼
┌────────────┐  ┌─────────────────┐
│  Ed25519   │  │   ML-DSA-65     │
│  Provider  │  │   Provider      │
│  (donna)   │  │   (liboqs)      │
└────────────┘  └─────────────────┘
```

### 設計方針

1. **既存コード非破壊**: 現行の `Sign()` / `Verify()` / `KeyPair` API は一切変更しない
2. **可変長対応**: Ed25519 (署名64B) と ML-DSA-65 (署名3309B) を同一インターフェースで扱う `CryptoBuffer` / `SecureCryptoBuffer` 型を導入
3. **レジストリパターン**: `CryptoProviderRegistry` で複数の暗号スキームを管理。デフォルトで Ed25519 が登録される
4. **セキュリティ**: `SecureCryptoBuffer` は破棄時に自動ゼロ化（`SecureZero` と同等の保護）

---

## 追加ファイル一覧

### 抽象化インターフェース

| ファイル | 説明 |
|---|---|
| `src/catapult/crypto/CryptoProvider.h` | `SignatureProvider` / `KemProvider` 抽象クラス、`CryptoBuffer` / `SecureCryptoBuffer` 型、`CryptoScheme` 列挙 |
| `src/catapult/crypto/CryptoProviderRegistry.h` | スキーム別プロバイダーレジストリ（ヘッダー） |
| `src/catapult/crypto/CryptoProviderRegistry.cpp` | レジストリ実装 |

### Ed25519 プロバイダー

| ファイル | 説明 |
|---|---|
| `src/catapult/crypto/Ed25519SignatureProvider.h` | Ed25519 → `SignatureProvider` アダプター（ヘッダー） |
| `src/catapult/crypto/Ed25519SignatureProvider.cpp` | 既存 donna ベース `Sign()` / `Verify()` へのブリッジ実装 |

### ML-DSA-65 (Dilithium3) プロバイダー

| ファイル | 説明 |
|---|---|
| `src/catapult/crypto/MlDsa65SignatureProvider.h` | ML-DSA-65 → `SignatureProvider` アダプター（ヘッダー） |
| `src/catapult/crypto/MlDsa65SignatureProvider.cpp` | liboqs `OQS_SIG_ml_dsa_65_*` API を使った実装 |

### テスト

| ファイル | 説明 |
|---|---|
| `tests/catapult/crypto/PqcIntegrationTests.cpp` | スタンドアロン統合テスト（14テストケース） |

---

## 主要インターフェース

### SignatureProvider

```cpp
class SignatureProvider {
public:
    virtual CryptoScheme scheme() const = 0;
    virtual const std::string& name() const = 0;
    virtual size_t publicKeySize() const = 0;
    virtual size_t privateKeySize() const = 0;
    virtual size_t signatureSize() const = 0;

    virtual void extractPublicKey(const SecureCryptoBuffer& privateKey, CryptoBuffer& publicKey) const = 0;
    virtual void sign(const SecureCryptoBuffer& privateKey, const CryptoBuffer& publicKey,
                      const std::vector<RawBuffer>& buffers, CryptoBuffer& signature) const = 0;
    virtual bool verify(const CryptoBuffer& publicKey, const std::vector<RawBuffer>& buffers,
                        const CryptoBuffer& signature) const = 0;
    virtual void generatePrivateKey(SecureCryptoBuffer& privateKey) const = 0;
};
```

### CryptoProviderRegistry

```cpp
CryptoProviderRegistry registry;  // Ed25519 が自動登録される
registry.registerSignatureProvider(std::make_shared<MlDsa65SignatureProvider>());

const auto& ed25519 = registry.defaultSignatureProvider();
const auto& mlDsa = registry.signatureProvider(CryptoScheme::Ml_Dsa_65);
```

### CryptoScheme

```cpp
enum class CryptoScheme : uint8_t {
    Ed25519   = 0x00,
    Ml_Dsa_65 = 0x01
};
```

---

## サイズ影響分析

| 項目 | Ed25519 | ML-DSA-65 | 倍率 |
|---|---|---|---|
| 公開鍵 | 32 B | 1,952 B | 61x |
| 秘密鍵 | 32 B | 4,032 B | 126x |
| 署名 | 64 B | 3,309 B | 52x |
| VerifiableEntity ヘッダー (推定) | 108 B | ~5,369 B | 50x |
| ブロックヘッダー (推定) | 380 B | ~5,641 B | 15x |

---

## パフォーマンスベンチマーク

ML-DSA-65 (liboqs 0.12.0, x86_64) での測定結果:

| 操作 | 所要時間 |
|---|---|
| 鍵生成 | 50 µs/op |
| 署名 | 115 µs/op |
| 検証 | 47 µs/op |

Ed25519 と同等のオーダーであり、パフォーマンス面での実用性は十分です。

---

## 依存関係

### liboqs (Open Quantum Safe)

- バージョン: 0.12.0
- ライセンス: MIT
- https://github.com/open-quantum-safe/liboqs

インストール手順:

```bash
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja lib/liboqs.so
sudo ninja install && sudo ldconfig
```

---

## テスト実行方法

### スタンドアロンテスト（catapult ビルド不要）

```bash
cd client/catapult/tests/catapult/crypto
g++ -std=c++17 -O2 -I/usr/local/include -o pqc_test PqcIntegrationTests.cpp -L/usr/local/lib -loqs
LD_LIBRARY_PATH=/usr/local/lib ./pqc_test
```

### テストケース一覧

| # | テスト | 内容 |
|---|---|---|
| 1-3 | Key Generation | 鍵サイズ、非ゼロ確認 |
| 4-8 | Sign & Verify | 正常署名検証、メッセージ改ざん検知、署名改ざん検知 |
| 9 | Wrong Key Rejection | 他者の公開鍵での検証拒否 |
| 10-13 | Multiple Messages | 複数トランザクション種別の署名検証 |
| 14 | Performance Benchmark | 鍵生成・署名・検証の所要時間計測 |

---

## 今後のフェーズ

### Phase 2: ワイヤープロトコル再設計
- `VerifiableEntityHeader` の `Signature` / `Key` を可変長化
- `#pragma pack(1)` 固定長レイアウトの脱却
- catbuffer スキーマ (.cats) の改訂
- **ハードフォークが必要**

### Phase 3: コア機能移植
- `Signer.cpp` の内部を `CryptoProviderRegistry` 経由に切り替え
- VRF の PQC 対応
- ECDH → ML-KEM (Kyber) への切り替え
- アドレス導出の再設計

### Phase 4: キャッシュ・パフォーマンス
- キャッシュの可変長キー対応
- Merkle Tree の最適化

### Phase 5: SDK・テスト・移行
- JavaScript / Python SDK の PQC 対応
- ハイブリッド署名（Ed25519 + ML-DSA-65）による段階的移行

---

## 実装日

2026年4月8日
