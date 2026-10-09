# 管理コンソール

`crates/mdmd/src/admin/` に、mdmd と同一オリジンで配信する管理コンソールを置いています。Rust のテンプレートエンジンや外部 CDN は使わず、`index.html`、`admin.css`、`admin.js` の静的ファイルだけで動作します。実行時の依存はブラウザ標準 API です。

## 配信と認証

サーバーは `/admin` を `index.html`、`/admin.css` と `/admin.js` をそれぞれの静的アセットとして配信します。アセットは同一オリジンから取得し、HTML の CSP とサーバーの CSP ヘッダーで `default-src 'self'`、`script-src 'self'`、`style-src 'self'`、`connect-src 'self'` を維持します。インラインスクリプト、インラインイベントハンドラ、外部 CDN は使用しません。

画面上部に管理 API の Bearer トークンを入力して接続します。トークンはページが開いている間だけ JavaScript のメモリに保持し、`localStorage`、`sessionStorage`、Cookie、IndexedDB には保存しません。ページを閉じるか再読み込みすると消えます。読み取り操作は read token、登録・配信・割当などの変更操作は admin token を使用する構成を推奨します。

## 端末操作

端末一覧は `GET /v1/enrollments` の `enrollments` を表示します。新規登録は `POST /v1/enrollments` に空 JSON (`{}`) を送り、返却された `profile` を一時 Blob として `.mobileconfig` にダウンロードします。ダウンロード後のプロファイル内容は画面やブラウザへ保存しません。

選択した端末には次のコマンドを送れます。すべてのコマンドは `POST /v1/enrollments/{id}/commands` に `{ "idempotency_key": "…", "command": { … } }` として送信します。画面内では同じ操作内容の再送に同じキーを使い、操作内容を変えると新しいキーを生成します。

冪等キーはブラウザのメモリにだけ保持します。送信前の通信失敗や、結果が `outcome_unknown` のままのコマンドではキーを保持し、結果を知らずに同じ変更を再実行しないようにします。サーバーで `completed`、`failed`、または `cancelled` と確認できたコマンドはキーを解放するため、同じ端末情報・アプリ一覧の取得や、次の意図した操作で新しい受付を作れます。ADE プロファイル登録は同じ JSON から同じ成果物を重複作成しないよう成功後も同じキーを維持します。ADE の割当・解除と VPP の割当・解除は成功した受付後にキーを解放し、解除後の再割当など新しい操作を妨げません。

| 画面操作 | `command.type` | 内容 |
| --- | --- | --- |
| 端末情報 | `device_information` | DeviceName、OSVersion、SerialNumber、ModelName、UDID、IsSupervised を要求 |
| インストール済みアプリ | `installed_application_list` | 全アプリを要求 |
| 管理対象アプリ | `managed_application_list` | 管理対象アプリの状態を要求 |
| App Store アプリ | `install_application` | `source: {"AppStore":{"itunes_store_id":数値,"purchase_method":1}}`（デバイスベースライセンスのみ） |
| Enterprise アプリ | `install_application` | `source: {"Enterprise":{"manifest_url":"https://…"}}` |
| アプリ削除 | `remove_application` | Bundle ID を指定 |
| 利用可能な OS | `available_os_updates` | 旧来の更新一覧を要求 |
| OS 状態 | `os_update_status` | 旧来の更新状態を要求 |
| OS 更新予約 | `schedule_os_update` | ProductKey または ProductVersion と `Default` / `DownloadOnly` / `InstallASAP` を指定 |
| ロック | `device_lock` | メッセージと電話番号を任意指定。現在のサーバー操作ポリシーでは PIN は送信しない |

キオスク操作は `POST /v1/enrollments/{id}/kiosk` (`bundle_id` と `idempotency_key`) と `POST /v1/enrollments/{id}/kiosk/release` (`idempotency_key`) を使います。監視対象の根拠がない端末ではサーバー側の eligibility policy により拒否されます。

消去は意図的に二段階です。`POST /v1/enrollments/{id}/erase-intents` で返る `id`、`token`、`serial_number`、`expires_at` を画面のメモリに保持し、表示されたシリアル番号と一致する入力がなければ `POST /v1/enrollments/{id}/erase` を送れません。実行時の body は `intent_id`、`token`、`confirm_serial`、`idempotency_key` です。意図の有効期限、対象端末、監査記録はサーバー側でも検証されます。

## 実行状況と実機観測

コマンドの受付後、画面は `GET /v1/commands/{id}` を一定間隔で取得します。端末を選択すると `GET /v1/enrollments/{id}/commands?after=…` から永続化済みの履歴も読み込みます。次の状態を分けて表示します。

- **送信受付済み / 配信待ち**: 管理 API が要求を受け、outbox の配送を待っている状態。
- **端末応答待ち**: 端末へ配信し、MDM 応答を待っている状態。
- **ACK 済み（反映未確認）**: 端末が ACK またはエラーを返した状態。アプリのインストール完了を意味しません。
- **実機反映確認（観測済み）**: `GET /v1/enrollments/{id}/observations` の `observations` に同じ `command_id` があり、Device Information やアプリ一覧などの観測で照合できた状態。
- **結果不明・要確認**: 変更系コマンドの配送タイムアウトなど、実行結果を安全に推測できない状態。

ACK を受け取っただけで「アプリ installed」や「OS 更新完了」とは表示しません。結果は監査ログ (`GET /v1/audit?after=0`) と実機観測の両方で確認してください。

## ADE、VPP、DDM

ADE は `GET /v1/ade/devices`、`POST /v1/ade/sync`、`POST /v1/ade/profiles`、`POST /v1/ade/assign`、`POST /v1/ade/unassign` を使います。割当・解除は入力した `profile_uuid` とシリアル番号一覧を同じ body に含めます。プロファイル JSON は画面で parse してから送信します。

VPP は `POST /v1/apps/licenses` に `adam_id`、`serial_number`、`assign`、`idempotency_key` を送り、`GET /v1/apps/licenses/{adam_id}?serial=…` でイベントの状態を取得します。Apple 側の非同期イベント状態は persisted event の結果であり、取得時点のライセンス反映を画面だけで断定しません。

DDM は `GET /v1/declarations` で宣言一覧を読み、`POST /v1/enrollments/{id}/ddm/enable` と `GET /v1/enrollments/{id}/ddm/status?after=0` で選択端末の有効化・状態確認を行います。宣言本文や ServerToken は一覧にそのまま表示せず、監査と status の応答で確認します。

Apple 連携の設定状態は `GET /v1/integrations/apple` で確認します。ここで表示される設定済み状態は疎通成功や端末上の反映を保証しません。

## 取り扱い上の注意

この画面は API の受付とサーバー状態を確認するためのものです。実機への配信、ACK、アプリのインストール結果、OS 更新、消去完了は別の事実です。実機テストはこの静的画面では実施していないため、導入時はテスト端末で各操作と監査・観測結果を確認してください。

管理 API と `/admin` は TLS 終端済みの信頼できる接続からだけ公開してください。管理トークンは短い共有 URL や画面キャプチャに含めず、作業終了時はページを閉じてメモリから破棄します。

この管理画面の追加コードはプロジェクトの MIT License の範囲で扱います。
