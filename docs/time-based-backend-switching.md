# ReverSSH 時間帯ベース backend 切替 実装方針

## 1. 目的

Blossom 上で Heralding、Cowrie、Beelzebub の各コンテナを常時稼働させたまま、時間帯によって SSH の振る舞いを切り替える。

目的は、同じ攻撃元に対して honeypot の構成を時間帯ごとに変更し、各構成が収集する認証情報・コマンド・セッション特性の違いを比較できるようにすることである。

対象とする構成は次の3つとする。

| モード | 認証観測 | 通常の対話 backend | セッション中の追加切替 |
| --- | --- | --- | --- |
| `heralding-cowrie` | Heralding | Cowrie | なし |
| `heralding-beelzebub` | Heralding | Beelzebub | なし |
| `heralding-cowrie-beelzebub` | Heralding | Cowrie または Beelzebub | コマンドルールで切替 |

Heralding は対話用 backend ではなく、認証試行を観測する credential backend として扱う。

## 2. 必須条件

- Docker コンテナの停止・起動・再起動を行わない。
- Cowrie、Beelzebub、Heralding は常時起動しておく。
- 時刻の経過だけで有効なモードが変化する。
- モード変更は ReversSSH のプロセス内で完結させる。
- 新規 SSH セッションは、その接続時点のモードで開始する。
- 既存 SSH セッションは、原則として開始時のモードと backend を維持する。
- 現在のモード、選択された backend、切替理由をログから識別できる。

## 3. Sakura の既存方式から取り入れる考え方

Sakura には `DISPATCHER_MODE=rotate` と `ROTATE_INTERVAL` によって、現在時刻からモードを決定する実装がある。次の計算方式は ReverSSH でも利用できる。

```text
current_slot = floor((current_time - epoch) / interval)
mode = sequence[current_slot % sequence.len()]
```

ただし、Sakura の Launcher はモード変更時に Docker サービスを起動・停止する。ReverSSH ではこの部分を導入しない。

ReverSSH のモード変更は次のルーティング操作だけに限定する。

```text
現在時刻を評価
  -> 有効な RoutingProfile を選択
  -> 新規セッションの初期 backend を決定
```

backend の lifecycle はモード管理の責務から分離する。

## 4. 推奨アーキテクチャ

```text
AppConfig
  ├─ backends: Heralding / Cowrie / Beelzebub
  ├─ routing profiles
  └─ time schedule

ModeResolver
  └─ 現在時刻 -> 有効な profile

RoutingTable
  └─ profile + 認証情報 + コマンド -> backend

Session
  ├─ mode_at_start
  ├─ initial_backend
  └─ current_backend
```

時間帯判定とコマンド判定を同じ Detector に詰め込まない。ModeResolver が profile を選択し、ProfileRouter がその profile 内の認証・コマンドルールを評価する。

## 5. 設定案

既存の `default.toml` と `routing.toml` を拡張する。backend 定義は `default.toml\)、モードとルールは `routing.toml` に置く。

### 5.1 backend 定義

```toml
[[backends]]
name = "heralding"
hostname = "heralding"
port = 22
type = "credential"
auth_type = "password"
default = true

[[backends]]
name = "cowrie"
hostname = "cowrie"
port = 2222
type = "interaction"
auth_type = "password"

[[backends]]
name = "beelzebub"
hostname = "beelzebub"
port = 2222
type = "interaction"
auth_type = "password"
```

### 5.2 時間ローテーション

固定間隔ローテーションを第一候補とする。

```toml
[schedule]
enabled = true
timezone = "Asia/Tokyo"
interval_seconds = 900
sequence = [
    "heralding-cowrie",
    "heralding-beelzebub",
    "heralding-cowrie-beelzebub",
]
```

`interval_seconds = 900` の場合、15分ごとに次の profile へ移る。切替境界はプロセス起動時刻ではなく、固定 epoch と現在時刻から算出する。ReversSSH を再起動してもローテーション周期はずれない。

各 profile は対話用の `default_backend` と、認証失敗を観測する `credential_backend` を持つ。現在の3 profile はすべて `credential_backend = "heralding"` とし、将来 Cowrie 単体で運用する場合は `credential_backend = "cowrie"` に変更する。認証成功は profile の interaction backend に接続し、認証失敗は credential backend に転送する。

最初から interval と時刻表の両方を実装せず、固定間隔を先に実装する。収集実験の再現性を優先するためである。将来、時刻表が必要になった場合は `start`、`end`、`profile` を持つ windows 形式を追加する。

## 6. セッションのライフサイクル

### 6.1 新規セッション

SSH 認証成功後、セッション作成時に以下を保存する。

```text
session.mode_at_start = ModeResolver::current_profile()
session.initial_backend = profile.initial_backend()
session.current_backend = session.initial_backend
```

以後の backend 選択では、原則として `session.mode_at_start` を使う。各コマンドのたびに時刻を再評価して既存セッションを別モードへ移さない。

### 6.2 既存セッションを移行しない理由

時間境界で既存セッションを強制移行すると、次の問題が起きる。

- Cowrie と Beelzebub のシェル状態が混在する。
- 攻撃者から見た prompt や filesystem の一貫性が崩れる。
- 1セッションの収集データが複数 honeypot の統計に重複計上される。
- モード変更時の切替タイミングによって実験結果が変わる。

したがって、モード境界は「新規接続に適用する境界」とする。

### 6.3 mode C のセッション内切替

`heralding-cowrie-beelzebub` だけは、既存のコマンドルールによる session 内 migration を許可する。

```text
セッション開始
  -> Cowrie
  -> コマンドルールを検出
  -> Beelzebub に接続
  -> CWD を復元
  -> 以後のコマンドを Beelzebub で実行
```

時間境界による切替とコマンドルールによる切替はログ上で区別する。

- `reason = schedule`
- `reason = command_rule`

## 7. Heralding の扱い

Heralding は全モードで常時有効とする。

- 認証失敗は Heralding に転送する。
- 必要であれば認証成功時の情報も ReversSSH の監査ログに記録する。
- Heralding を interaction backend の切替先にはしない。
- Heralding のログには ReversSSH 側の session ID を関連付ける。

「Heralding と Cowrie を同時運用する」とは、同じ SSH 接続に対して2つの対話 backend を直列接続することではない。ReversSSH が認証観測を Heralding に、対話処理を Cowrie に分担させる意味とする。

## 8. Rust 実装方針

### 8.1 設定型

`src/config/app.rs` に次の概念を追加する。

```rust
pub struct ScheduleConfig {
    pub enabled: bool,
    pub timezone: String,
    pub interval_seconds: u64,
    pub sequence: Vec<String>,
}
```

profile は意味のある構成として定義する。

```rust
pub struct RoutingProfileConfig {
    pub name: String,
    pub default_interaction_backend: String,
    pub command_rules: Vec<CommandRuleConfig>,
}
```

### 8.2 ModeResolver

`src/router/mode.rs` を追加し、次の責務だけを持たせる。

- 設定の妥当性検証
- 現在時刻から profile 名を計算
- profile の切替境界を計算
- 現在の profile と次回切替時刻を返す

各リクエストで時刻を読むだけの実装にすれば、専用のバックグラウンドスレッドは必須ではない。共有 mutable state の同期ずれを避けられる。

現在モードの変更を一度だけログ出力したい場合だけ、`Arc<RwLock<ModeSnapshot>>` を使用する。ルーティングテーブル自体は不変にし、モード判定結果を時刻から算出する設計を推奨する。

### 8.3 ClientPool との統合

現在の `ClientPool` は default interaction backend を1つ保持している。これを、セッション作成時に解決した profile の default backend から受け取るようにする。

最小変更では、`ProxyServer::create_session_for_channel` の前で profile の default backend を決定し、既存の `create_connection` に backend 名を渡す。

将来的には次の値を導入する。

```rust
pub struct RoutingDecision {
    pub profile: String,
    pub backend: String,
    pub reason: RoutingReason,
}
```

## 9. Blossom 側の運用方針

Blossom の `compose/ssh.yml` では、次の3サービスを常時起動する。

- `heralding`
- `cowrie`
- `beelzebub`

ReversSSH はそれらに SSH 接続するだけにし、モード切替時に Docker socket、Launcher、Compose API を呼び出さない。

設定は read-only mount する。

```yaml
volumes:
  - \${BLOSSOM_DEFAULT_CONFIG_PATH}:/config/default.toml:ro
  - \${BLOSSOM_ROUTING_CONFIG_PATH}:/config/routing.toml:ro
```

backend の一時的な接続失敗に備え、ReversSSH には次を実装する。

- 接続 timeout
- 新 backend 接続成功後に現在 backend を置き換える
- 新 backend 接続失敗時は現在 backend を維持する
- backend 不在時の明示的な error log
- health check 結果を mode log と区別する

## 10. ログとデータ分析

モード差を比較するため、イベントに次のフィールドを追加する。

```json
{
  "mode": "heralding-cowrie-beelzebub",
  "session_mode": "heralding-cowrie-beelzebub",
  "backend": "beelzebub",
  "route_reason": "command_rule",
  "schedule_slot": 12
}
```

最低限、認証試行、セッション開始、コマンド入力、backend migration、セッション終了で mode と backend を記録する。

比較対象は次の通り。

- 時間帯別の接続数
- 時間帯別の認証情報
- 時間帯別のコマンド数
- backend 別のセッション時間
- mode C における Cowrie -> Beelzebub の移行数
- 同一攻撃元 IP の mode 間行動差

## 11. テスト方針

### 単体テスト

- interval が正しく slot に変換される。
- sequence が空の場合に設定エラーになる。
- 未知の profile 名・backend 名を拒否する。
- schedule 境界の直前・直後で profile が変わる。
- 起動時刻を変えても固定 epoch に対する slot が変わらない。
- 同じ時刻では常に同じ profile が返る。
- disabled の場合は固定 default profile を返す。

### ReverSSH E2E テスト

全 backend コンテナを同時起動した状態で、次を検証する。

1. `heralding-cowrie` で新規接続し、Cowrie の応答を確認する。
2. test config の interval を数秒に設定する。
3. コンテナを再起動せずに次の slot へ進むことを確認する。
4. 新規接続が Beelzebub に接続されることを確認する。
5. 既存接続が元の backend を維持することを確認する。
6. mode C の command rule で Cowrie/Beelzebub が切り替わることを確認する。
7. Heralding の認証観測が全モードで継続することを確認する。
8. mode と backend がログに記録されることを確認する。

## 12. 実装フェーズ

### Phase 1: 時刻判定のみ

- `ScheduleConfig` を追加
- `ModeResolver` を追加
- 固定 interval と sequence を実装
- 単体テストを追加
- 現在 profile をログ出力

### Phase 2: セッション初期 backend への統合

- セッション開始時に profile を固定
- profile の default interaction backend を選択
- mode と profile を session logger に追加
- 3構成を E2E で検証

### Phase 3: mode C の統合

- profile ごとの command rules を追加
- 既存 migration を mode C だけで有効化
- `route_reason` を追加
- backend migration の失敗時処理を強化

### Phase 4: Blossom 運用統合

- 3 backend を常時起動する `compose/ssh.yml` に統合
- ReversSSH の schedule 設定を read-only mount
- Docker 操作を行わないことを確認
- mode 別の Elastic 集計を追加

### Phase 5: 必要な場合のみ runtime 制御を追加

時間間隔そのものを運用中に変更する必要が出た場合のみ、Unix socket または内部 admin API を追加する。時間ローテーション自体は Phase 1 で再起動なしに実現できるため、最初から管理 API を導入しない。

## 13. 採用しない方式

### backend コンテナの停止・起動による切替

今回の目的に反するため採用しない。起動遅延、初回接続の欠落、ログの連続性低下が発生する。

### Compose profile の切替

Compose profile はデプロイ時の構成選択には使えるが、プロセス稼働中の時間帯切替には使わない。

### 既存セッションの強制 backend 移行

収集データの帰属が曖昧になり、攻撃者から見たセッションの一貫性も壊れるため、初期実装では採用しない。

### Sakura Launcher の直接利用

Sakura の Launcher は Docker サービス lifecycle 管理を目的としている。時間判定の考え方だけを参考にし、ReversSSH の routing は ReversSSH 内に置く。

## 14. 完了条件

- 3つの profile が設定で表現できる。
- Heralding、Cowrie、Beelzebub が常時稼働している。
- ReversSSH の再起動なしで profile が時間帯に応じて変化する。
- モード境界後の新規接続が新しい profile を使用する。
- 既存接続の backend が意図せず変更されない。
- mode C だけ、ルールに従って Cowrie と Beelzebub を session 内で切り替えられる。
- 認証観測が全 profile で継続する。
- mode、backend、切替理由を Elasticsearch で集計できる。
- backend の接続失敗時にも ReversSSH が不必要に停止しない。
- E2E テストでコンテナの再起動が発生していないことを確認できる。




