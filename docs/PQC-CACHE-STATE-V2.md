# Phase 4: Cache & State V2 — 通知・検証・状態管理パイプライン

## 概要

Phase 3 で完成した V2 署名/検証/ハッシュ API を、catapult のブロック処理パイプライン（通知システム → バリデーター → バッチ検証 → アカウント状態管理）に統合する拡張レイヤーです。

**設計原則**: V1 コードは一切変更しない。V2 コンポーネントは V1 と並行して動作し、エンティティの `CryptoSchemeId` に基づいて V1/V2 パスを分岐する。

---

## アーキテクチャ

```
  エンティティ受信
       │
       ▼
  CryptoSchemeId チェック
       │
  ┌────┴────────────────────┐
  │ 0x00: Ed25519           │ 0x01+: PQC
  │ ┌─────────────────┐     │ ┌──────────────────────┐
  │ │ V1 パス (既存)  │     │ │ V2 パス (新規)       │
  │ │ SignatureNotif   │     │ │ SignatureNotifV2     │
  │ │ SignatureValid   │     │ │ SignatureValidV2     │
  │ │ BatchVerify      │     │ │ BatchVerifyV2        │
  │ │ (multi-scalar)   │     │ │ (per-signature)      │
  │ └─────────────────┘     │ └──────────────────────┘
  └────┬────────────────────┘
       │
       ▼
  AccountState
  (Ed25519: PublicKey 32B)
  (PQC: PublicKey hash 32B + V2Extension with full key)
```

---

## 新規ファイル

### 1. `src/catapult/model/NotificationsV2.h`

V2 通知型の定義。V1 の `SignatureNotification`（固定長 `const Key&` + `const Signature&`）に対して、可変長の `RawBuffer` を使用。

| 構造体 | 説明 |
|--------|------|
| `SignatureNotificationV2` | CryptoScheme + 可変長 SignerPublicKey/Signature/Data |
| `AccountPublicKeyNotificationV2` | CryptoScheme + 可変長 PublicKey |

**V1 との主要な違い**:

```
V1: const Key& SignerPublicKey        → 32B 固定、エンティティ構造体のフィールド参照
V2: RawBuffer SignerPublicKey          → 可変長、V2 バッファ上のバイト列参照（ゼロコピー）

V1: const Signature& Signature         → 64B 固定
V2: RawBuffer Signature                → 可変長（Ed25519=64B, ML-DSA-65=3309B）
```

**通知タイプ ID**:
- `Core_Signature_V2_Notification` = `0x0017` (V1 は `0x0007`)
- `Core_Register_Account_Public_Key_V2_Notification` = `0x0018` (V1 は `0x0002`)

### 2. `src/catapult/model/NotificationPublisherV2.h`

V2 エンティティバッファから V2 通知を生成するユーティリティ。

| 関数 | 説明 |
|------|------|
| `CreateBlockSignatureNotification(reader)` | ブロック署名通知（リプレイ保護なし） |
| `CreateTransactionSignatureNotification(reader, dataBuffer)` | トランザクション署名通知（リプレイ保護あり） |
| `CreateAccountPublicKeyNotification(reader)` | アカウント公開鍵通知 |
| `IsV2Entity(pBuffer, size)` | CryptoSchemeId ≠ 0x00 かチェック |
| `GetCryptoScheme(pBuffer, size)` | CryptoSchemeId 取得 |

**統合パス**: `NotificationPublisher.cpp` の `publishBlock()` / `publishTransactionPostCustom()` で V1/V2 を分岐:

```cpp
if (NotificationPublisherV2::IsV2Entity(entityData, entitySize)) {
    EntityHeaderV2Reader reader(entityData, entitySize);
    sub.notify(NotificationPublisherV2::CreateBlockSignatureNotification(reader));
} else {
    sub.notify(SignatureNotification(block.SignerPublicKey, block.Signature, ...));
}
```

### 3. `src/catapult/validators/SignatureValidatorV2.h`

`CryptoProviderRegistry` 経由で V2 署名を検証するバリデーター。

**検証フロー**:
1. `CryptoScheme` がレジストリに登録済みか確認
2. 公開鍵サイズがプロバイダーの期待値と一致するか確認
3. 署名サイズがプロバイダーの期待値と一致するか確認
4. `CryptoProviderRegistry::signatureProvider(scheme).verify()` で暗号検証

**リプレイ保護**: `ReplayProtectionMode::Enabled` の場合、`GenerationHashSeed || Data` を検証対象とする（V1 と同じロジック）。

### 4. `src/catapult/consumers/BatchSignatureConsumerV2.h`

V2 バッチ署名検証。V1 の `BatchSignatureConsumer.cpp` の V2 対応版。

| クラス/関数 | 説明 |
|------------|------|
| `SignatureCapturingNotificationSubscriberV2` | 通知ストリームから V2 署名をキャプチャ |
| `BatchVerifyV2(registry, inputs)` | バッチ検証（全結果返却） |
| `BatchVerifyV2ShortCircuit(registry, inputs)` | 最初の失敗で停止 |

**V1 との主要な違い**:
- V1: Ed25519 の `VerifyMulti()` はバッチ検証（マルチスカラー乗算）で高速化
- V2: PQC スキームはバッチ数学をサポートしないため、署名ごとに個別検証
- V2: ただしスレッド並列化は可能（V1 と同じ `ParallelForPartition` パターン）

### 5. `src/catapult/state/AccountStateV2.h`

アカウント状態の V2 拡張。`AccountState::PublicKey`（32B 固定）を維持しつつ、PQC アカウント用に可変長公開鍵を格納。

| 構造体/関数 | 説明 |
|------------|------|
| `AccountStateV2Extension` | CryptoScheme + FullPublicKey（可変長） |
| `ComputePublicKeyHash(key, scheme)` | 32B ルックアップキー計算 |
| `SerializeV2Extension(ext)` | バイト列へのシリアライズ |
| `DeserializeV2Extension(data, size)` | バイト列からのデシリアライズ |

**キャッシュ互換性設計**:

```
Ed25519 アカウント:
  AccountState.PublicKey = 32B 公開鍵（そのまま）
  V2Extension = なし（オーバーヘッドゼロ）

ML-DSA-65 アカウント:
  AccountState.PublicKey = SHA3-256(1952B公開鍵)[0..31]（ルックアップハッシュ）
  V2Extension = { CryptoScheme::Ml_Dsa_65, 1952B 完全公開鍵 }
```

これにより:
- **Address → AccountState** プライマリルックアップ: 変更なし
- **Key → Address** セカンダリルックアップ: 32B ハッシュをルックアップキーとして使用、変更なし
- **Patricia Tree**: Ed25519 アカウントは完全に後方互換
- **シリアライズ**: V2 拡張は追加フィールドとして保存（State_Version = 2）

**V2 拡張シリアライズフォーマット**:
```
[CryptoScheme: 1 byte] [KeySize: 4 bytes (uint32)] [FullPublicKey: KeySize bytes]
```

### 6. `src/catapult/model/NotificationType.h` (変更)

V2 通知タイプ定数を追加:
- `DEFINE_CORE_NOTIFICATION(Signature_V2, 0x0017, Validator)`
- `DEFINE_CORE_NOTIFICATION(Register_Account_Public_Key_V2, 0x0018, All)`

---

## テスト

### `tests/catapult/model/CacheStateV2Tests.cpp` — 20 テスト全パス

| # | テスト | 内容 |
|---|--------|------|
| 1 | NotificationV2_CreateFromEntity | V2 エンティティから通知生成 |
| 2 | NotificationV2_ZeroCopyReferences | 通知がバッファ内データをゼロコピー参照 |
| 3 | ValidatorV2_ValidSignature_Accepted | 有効な ML-DSA-65 署名が承認 |
| 4 | ValidatorV2_TamperedData_Rejected | 改ざんデータの署名が拒否 |
| 5 | ValidatorV2_WrongKeySize_Rejected | 不正な鍵サイズが拒否 |
| 6 | ValidatorV2_UnknownScheme_Rejected | 未登録スキームが拒否 |
| 7 | ValidatorV2_TransactionWithReplayProtection | リプレイ保護付きトランザクション検証 |
| 8 | BatchConsumerV2_CaptureNotifications | 通知キャプチャとエンティティインデックスマッピング |
| 9 | BatchConsumerV2_BatchVerify_AllValid | 5 件バッチ検証（全有効） |
| 10 | BatchConsumerV2_BatchVerify_WithTampered | バッチ内 1 件不正の検出 |
| 11 | BatchConsumerV2_ShortCircuit | ショートサーキット検証 |
| 12 | AccountStateV2_MlDsa65_KeyStorage | ML-DSA-65 鍵格納 |
| 13 | AccountStateV2_ComputePublicKeyHash | 公開鍵ハッシュ計算（決定性・一意性） |
| 14 | AccountStateV2_Serialization_RoundTrip | シリアライズ往復 |
| 15 | AccountStateV2_Deserialization_TruncatedBuffer | 短縮バッファの拒否 |
| 16 | AccountStateV2_Deserialization_RejectsOversizedKey | 巨大鍵の拒否（>64KB） |
| 17 | NotificationPublisherV2_IsV2Entity | V2 エンティティ検出 |
| 18 | NotificationPublisherV2_GetCryptoScheme | CryptoSchemeId 取得 |
| 19 | EndToEnd_EntityToNotificationToValidatorToState | E2E パイプライン |
| 20 | Performance_BatchVerify_Throughput | 50 件バッチ検証ベンチマーク |

### ビルド＆実行

```bash
cd client/catapult
g++ -std=c++17 -O2 -I/usr/local/include \
    -o cache_v2_test tests/catapult/model/CacheStateV2Tests.cpp \
    -L/usr/local/lib -loqs
LD_LIBRARY_PATH=/usr/local/lib ./cache_v2_test
```

### パフォーマンス

| 指標 | 結果 |
|------|------|
| ML-DSA-65 バッチ検証 (50件) | ~1880 µs total |
| ML-DSA-65 検証/件 | ~37 µs/verify |

---

## 7 つのアーキテクチャボトルネックと対応状況

| # | ボトルネック | Phase 4 対応 | 残作業 |
|---|-------------|-------------|--------|
| 1 | 型システム (Key=32B, Signature=64B) | `CryptoBuffer` で可変長化済み (Phase 1) | — |
| 2 | ワイヤーフォーマット | `EntityHeaderV2Reader/Writer` 済み (Phase 2) | — |
| 3 | **SignatureNotification 固定参照** | **SignatureNotificationV2** ✅ | NotificationPublisher.cpp 統合 |
| 4 | **SignatureValidator 固定呼出** | **SignatureValidatorV2** ✅ | プラグイン登録 |
| 5 | **AccountState 固定 Key** | **AccountStateV2Extension** ✅ | キャッシュデルタ統合 |
| 6 | AccountState シリアライズ | **SerializeV2Extension** ✅ | AccountStateSerializer 統合 |
| 7 | **バッチ検証** | **BatchVerifyV2** ✅ | BlockchainSyncConsumer 統合 |

---

## Phase 1 → 2 → 3 → 4 の関係

```
Phase 1                Phase 2              Phase 3              Phase 4
暗号抽象化             ワイヤープロトコル    コア関数V2           パイプライン統合
┌──────────────┐      ┌────────────────┐   ┌──────────────┐    ┌──────────────────┐
│ CryptoProvider│      │ EntityHeaderV2 │   │ SignerV2     │    │ NotificationsV2  │
│ Registry     │─────▶│ Layout/Reader  │──▶│ EntityHashV2 │───▶│ ValidatorV2      │
│ Ed25519Prov  │      │ Writer/Serial  │   │ BlockUtilsV2 │    │ BatchConsumerV2  │
│ MlDsa65Prov  │      │ catbuffer V2   │   │ AddressV2    │    │ AccountStateV2   │
└──────────────┘      └────────────────┘   └──────────────┘    │ NotifPublisherV2 │
                                                                └──────────────────┘
```

---

## 実装日

2026年4月8日
