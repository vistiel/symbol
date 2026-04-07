# Phase 2: Wire Protocol V2 — 可変長暗号フィールド対応

## 概要

Phase 1 の暗号抽象化レイヤーの上に、**ワイヤープロトコル V2** を定義しました。V1 の `#pragma pack(1)` 固定長レイアウトを脱却し、`CryptoSchemeId` による暗号方式判別で可変長の署名・公開鍵をサポートします。

### 設計の要点

1. **CryptoSchemeId バイト**: V1 の `Reserved1` フィールド（常に `0x00000000`）の先頭バイトを `CryptoSchemeId` として再利用。Ed25519 = `0x00` のため **V1 とバイナリ互換**
2. **ランタイムオフセット**: `Header_Size` がコンパイル時定数からランタイム関数に変更
3. **バッファベースアクセサー**: `EntityHeaderV2Reader` / `Writer` がバイトバッファ上のフィールドにアクセス（`#pragma pack(1)` 構造体に依存しない）
4. **既存コード非破壊**: V1 の構造体・API は一切変更なし

---

## V2 ワイヤーフォーマット

### VerifiableEntity V2 (トランザクション・ブロック)

```
Offset      Size          Field
─────────────────────────────────────────────────────────
0x00        4 (uint32)    Size
0x04        1 (uint8)     CryptoSchemeId
0x05        3             Reserved1 (padding)
0x08        S             Signature       ← スキーム依存
0x08+S      K             SignerPublicKey  ← スキーム依存
0x08+S+K    4 (uint32)    Reserved2
0x0C+S+K    1 (uint8)     Version
0x0D+S+K    1 (uint8)     Network
0x0E+S+K    2 (uint16)    Type
```

| スキーム | S (署名) | K (公開鍵) | Header_Size | EntityBody終端 |
|---|---|---|---|---|
| Ed25519 (0x00) | 64 | 32 | **108** (V1同一) | 112 |
| ML-DSA-65 (0x01) | 3,309 | 1,952 | **5,273** | 5,277 |

### EmbeddedTransaction V2 (署名なし、Aggregate内部用)

```
Offset      Size          Field
─────────────────────────────────────────────────────────
0x00        4 (uint32)    Size
0x04        1 (uint8)     CryptoSchemeId
0x05        3             Reserved1
0x08        K             SignerPublicKey  ← スキーム依存
0x08+K      4 (uint32)    Reserved2
0x0C+K      1 (uint8)     Version
0x0D+K      1 (uint8)     Network
0x0E+K      2 (uint16)    Type
```

| スキーム | EmbeddedHeader_Size |
|---|---|
| Ed25519 | **44** (V1同一) |
| ML-DSA-65 | **1,964** |

### Cosignature V2

```
Offset      Size          Field
─────────────────────────────────────────────────────────
0x00        8 (uint64)    Version
0x08        1 (uint8)     CryptoSchemeId
0x09        7             Reserved (padding)
0x10        K             SignerPublicKey
0x10+K      S             Signature
```

| スキーム | Cosignature Size |
|---|---|
| Ed25519 | **112** bytes |
| ML-DSA-65 | **5,277** bytes |

---

## V1 バイナリ互換性

V2 フォーマットで `CryptoSchemeId = 0x00` (Ed25519) を使用した場合：

- **全フィールドオフセットが V1 と完全一致** (テスト #2, #9, #10 で検証済み)
- V1 の `Reserved1 = 0x00000000` と V2 の `SchemeId=0x00 + Padding=0,0,0` は同一バイト列
- 既存の V1 バッファを `EntityHeaderV2Reader` でそのまま読み取り可能
- V2 `EntityHeaderV2Writer` で生成した Ed25519 バッファは V1 パーサーでも読み取り可能

これにより、**ハードフォーク時に段階的移行** が可能です。

---

## 追加ファイル一覧

### catbuffer スキーマ

| ファイル | 説明 |
|---|---|
| `catbuffer/schemas/symbol/types.cats` | `CryptoSchemeId` 列挙型を追加 |
| `catbuffer/schemas/symbol/entity_v2.cats` | V2 エンティティヘッダー定義 |
| `catbuffer/schemas/symbol/transaction_v2.cats` | V2 トランザクション・Embedded定義 |
| `catbuffer/schemas/symbol/aggregate/cosignature_v2.cats` | V2 コサイン定義 |

### C++ ヘッダー

| ファイル | 説明 |
|---|---|
| `src/catapult/model/EntityHeaderV2.h` | V2 レイアウト計算、Reader、Writer、EmbeddedReader、CosignatureReader |
| `src/catapult/model/EntitySerializerV2.h` | V1⇄V2 変換、V2 エンティティ生成、ハッシュコンポーネント抽出 |

### テスト

| ファイル | 説明 |
|---|---|
| `tests/catapult/model/WireProtocolV2Tests.cpp` | スタンドアロン統合テスト（20テストケース） |

---

## 主要クラス

### EntityHeaderV2Reader

バイトバッファ上の V2 エンティティヘッダーを読み取る。

```cpp
// V1 バッファでもそのまま動作
EntityHeaderV2Reader reader(v1Buffer.data(), v1Buffer.size());
auto scheme = reader.cryptoScheme();      // Ed25519
auto sig = reader.signature();            // RawBuffer {data, 64}
auto key = reader.signerPublicKey();      // RawBuffer {data, 32}
auto headerSize = reader.headerSize();    // 108 (V1と同じ)
```

### EntityHeaderV2Writer

V2 エンティティバッファを構築する。

```cpp
EntityHeaderV2Writer writer(totalSize, CryptoScheme::Ml_Dsa_65);
writer.setSignature(mldsaSig.data(), 3309);
writer.setSignerPublicKey(mldsaKey.data(), 1952);
writer.setVersion(2);
writer.setNetwork(NetworkIdentifier::Mainnet);
writer.setType(EntityType::Transfer);

auto buffer = writer.release();  // std::vector<uint8_t>
```

### EntityHeaderV2Layout

オフセットとサイズの計算ユーティリティ。

```cpp
// ランタイム計算
auto hdrSize = EntityHeaderV2Layout::HeaderSize(CryptoScheme::Ml_Dsa_65);  // 5273

// コンパイル時定数
constexpr auto ed25519Hdr = EntityHeaderV2Layout::Ed25519::Header_Size;    // 108
constexpr auto mldsaHdr = EntityHeaderV2Layout::MlDsa65::Header_Size;      // 5273
```

---

## テスト実行方法

```bash
cd client/catapult/tests/catapult/model
g++ -std=c++17 -O2 -Wall -Wextra -o wire_v2_test WireProtocolV2Tests.cpp
./wire_v2_test
```

### テストケース一覧

| # | テスト | 内容 |
|---|---|---|
| 1 | Ed25519_Layout_Matches_V1 | Header_Size=108, Embedded=44 が V1 と一致 |
| 2 | Ed25519_Field_Offsets_Match_V1 | 全フィールドオフセットが V1 と一致 |
| 3 | MlDsa65_Layout_Sizes | ML-DSA-65 のサイズ計算 |
| 4 | MlDsa65_Field_Offsets | ML-DSA-65 のオフセット計算 |
| 5-6 | Writer_Reader_RoundTrip | Ed25519/ML-DSA-65 の書き込み→読み取り往復 |
| 7-8 | Rejects_Wrong_Size | サイズ不一致の署名/鍵の拒否 |
| 9 | V1_Buffer_Is_Valid_V2 | V1 バッファを V2 Reader で正常解析 |
| 10 | V2_Produces_V1_Compatible_Bytes | V2 Writer 出力が V1 レイアウトと一致 |
| 11-12 | Embedded_Reader | Ed25519/ML-DSA-65 の Embedded ヘッダー解析 |
| 13-14 | Cosignature_Reader | Ed25519/ML-DSA-65 のコサイン解析 |
| 15-16 | DataBuffer_Extraction | 署名対象データバッファの抽出 |
| 17 | Buffer_Too_Small | バッファ不足時の例外発生 |
| 18 | Full_Transaction_V2 | MaxFee/Deadline 込みのトランザクション生成 |
| 19 | Size_Impact_Analysis | Ed25519 vs ML-DSA-65 サイズ比較レポート |
| 20 | Write_Beyond_Buffer | バッファ境界外書き込みの拒否 |

---

## Phase 1 → Phase 2 → Phase 3 の関係

```
Phase 1 (暗号抽象化)          Phase 2 (ワイヤープロトコル)       Phase 3 (コア移植)
┌──────────────────┐         ┌──────────────────────┐         ┌─────────────────┐
│ CryptoProvider   │         │ EntityHeaderV2Layout │         │ Signer.cpp を   │
│ Registry         │────────▶│ EntityHeaderV2Reader │────────▶│ Registry 経由に │
│ SignatureProvider│         │ EntityHeaderV2Writer │         │ 切り替え        │
│ Ed25519Provider  │         │ EntitySerializerV2   │         │                 │
│ MlDsa65Provider  │         │ catbuffer V2 schemas │         │ V1→V2 移行処理  │
└──────────────────┘         └──────────────────────┘         └─────────────────┘
```

---

## 実装日

2026年4月8日
