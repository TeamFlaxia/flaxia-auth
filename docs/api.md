# 認証 API

Base URL: `https://auth.flaxia.app`

この文書はリポジトリの実装を記載しています。未デプロイの変更がある場合、本番のAPIとは異なります。

ブラウザからのリクエストは `credentials: 'include'` を指定します。許可するOriginは `https://auth.flaxia.app` と `https://flaxia.app` です。POSTには許可された `Origin` が必要です。レスポンスの認証Cookieは `__Host-flaxia_session`、`Secure`、`HttpOnly`、`SameSite=Lax` で、有効期間は7日です。

リクエストとレスポンスはJSONです。SRPではパスワードを送信せず、クライアントでSRPの値を計算します。旧方式の初回ログインのみ例外です。文字列のバイナリ値は標準Base64です。SRPの計算は `src/srp.ts` を参照してください。新規の検証子には `srp_group: "2048"` と `srp_kdf: "pbkdf2-600k-v2"` を使用します。

| Method | Path | 用途 |
| --- | --- | --- |
| GET | `/health` | 稼働確認 |
| POST | `/api/auth/register` | アカウント登録 |
| POST | `/api/auth/login/start` | SRPログインの開始 |
| POST | `/api/auth/login/verify` | SRP証明の検証とセッション発行 |
| POST | `/api/auth/login/legacy` | 旧方式のログインとSRPへの移行 |
| GET | `/api/auth/me` | 現在のユーザー取得 |
| POST | `/api/auth/logout` | セッション削除 |
| POST | `/api/auth/reauth/start` | 現在のユーザーの再認証を開始 |
| POST | `/api/auth/reauth/verify` | 再認証の証明を検証 |
| POST | `/api/auth/upgrade-srp` | 本人確認後にSRP情報を更新 |

## 登録

`POST /api/auth/register`

```json
{
  "username": "example_user",
  "display_name": "Example",
  "srp_salt": "<Base64の16バイトのsalt>",
  "srp_verifier": "<Base64の256バイトのverifier>",
  "srp_group": "2048",
  "srp_kdf": "pbkdf2-600k-v2"
}
```

`username` は半角英数字と `_` の1〜20文字で、大文字と小文字を区別せずに一意です。`display_name` は省略でき、指定する場合は1〜50文字です。成功時はHTTP 201で `{ "user": { "id", "username", "display_name" } }` を返し、セッションCookieを発行します。重複時は409です。

## ログイン

1. `POST /api/auth/login/start` に `{ "username": "example_user" }` を送ります。成功時は `challenge_id`、`salt`、`B`、`srp_kdf` と `srp: true` を返します。
2. クライアントは指定されたKDFで `A` と `M1` を計算し、`POST /api/auth/login/verify` に `{ "challenge_id", "A", "M1" }` を送ります。
3. 成功時は `{ "user", "M2" }` とセッションCookieを返します。クライアントは `M2` を検証してください。

チャレンジは5分間有効で、検証時に消費されます。認証失敗時は401です。凍結アカウントの正しい証明には403と `{ "error": "account_frozen", "username", "M2" }` を返します。

## セッションと再認証

`GET /api/auth/me` は `{ "user": { "id", "username", "display_name" } }` を返し、セッションがなければ401です。`POST /api/auth/logout` はセッションを削除し、Cookieを消去します。

`POST /api/auth/reauth/start` はログイン済みユーザーに `challenge_id`、`salt`、`B`、`srp_kdf` を返します。`POST /api/auth/reauth/verify` へ `{ "challenge_id", "A", "M1" }` を送り、`{ "valid": true | false }` を受け取ります。チャレンジは一度だけ使えます。

`POST /api/auth/upgrade-srp` は新しい `srp_salt`、`srp_verifier`、`srp_group`、`srp_kdf` と、再認証で得た `{ "challenge_id", "A", "M1" }` を `current_srp` として受け取ります。成功時は `{ "success": true }` を返します。

Vaultが有効なアカウントでは、同じリクエストに `vault_kek` が必要です。`vault_kek` は新しいパスワードから導出したKEKでVKをラップし直した `{ "salt", "kdf_params", "wrapped_vk", "vk_version" }` です。`vk_version` が現在の封筒と一致しない場合は409 `vault_key_version_conflict`、省略した場合は409 `vault_rewrap_required` を返し、検証子も封筒も変更しません。Authは検証子と封筒を同じD1トランザクションで更新します。

## Personal Vault

Vaultの暗号化はすべてブラウザで行います。Authが保存するのはラップ済みのVK、復旧用ブロブ、アイテム鍵、暗号文だけです。パスワード、KEK、REK、VK、アイテム鍵、復旧フレーズは送信しません。

| Method | Path | 用途 |
| --- | --- | --- |
| GET | `/api/vault/keys` | 封筒と端末一覧。未作成時は `{ "enabled": false }` |
| POST | `/api/vault/keys` | Vaultの有効化。`current_srp` が必要 |
| PUT | `/api/vault/keys` | 封筒の更新。`current_srp` と `vk_version` が必要 |
| GET | `/api/vault/items[?kind=...]` | アイテム一覧。`kind` 指定時のみ `payload` を含む |
| PUT | `/api/vault/items/:id` | アイテムの作成・更新。`vk_version` は楽観ロック |
| DELETE | `/api/vault/items/:id?vk_version=...` | アイテムの削除 |
| DELETE | `/api/vault/items?kind=...&vk_version=...` | 指定kindの一括削除 |
| POST | `/api/vault/keys/revoke-device` | 端末失効とVKローテーション。`current_srp`、`vk_version`、全アイテム鍵が必要 |
| POST | `/api/vault/devices` | ペアリング開始。`{ "label", "peer_pub", "ttl_seconds"? }` |
| GET | `/api/vault/devices` | 端末一覧 |
| GET | `/api/vault/devices/:id` | ペアリング状態（`pending` / `active` / `expired`） |
| POST | `/api/vault/devices/:id/approve` | `{ "approved_pub", "peer_pub", "wrapped_vk" }` で承認 |
| DELETE | `/api/vault/devices/:id` | 保留中のペアリングのみ取り消し |

アイテムは1アカウント200件、暗号文は1件128KB、合計5MBまでです。`kind` は `post_autosave`、`post_draft`、`private_note`、`personal_setting` のいずれかです。`vk_version` が古い書き込みは409で拒否します。

FlaxiaはService Bindingの `POST /api/flaxia/vault` に `{ "grant", "user_id", "method", "path", "query"?, "body"? }` を送ることで、同じVault APIを利用できます。`current_srp` はグラントに紐づく再認証チャレンジで検証されます。

Flaxia D1に残る移行前のVault行は、初回のVaultアクセス時にFlaxiaが `POST /api/flaxia/vault/import` へ一度だけコピーします。本文は `{ "grant", "user_id", "keys", "devices", "items" }` で、`keys` は封筒、`devices` と `items` は行の配列です。すべてクライアントが生成したラップ済みの値で、サーバーは形状と件数だけを検証します。同じ封筒の再送は `{ "success": true, "imported": false }` を返し、異なる封筒で既存Vaultを置き換えようとすると409 `vault_import_conflict` になります。

## 制限と旧方式

認証APIはリクエスト元IPごとに各パスで毎分20回、SRPログイン開始と旧方式ログインはそれぞれユーザーごとに毎分5回までです。超過時は429を返します。

`/api/auth/login/start` が `{ "srp": false }` を返した場合に限り、旧方式のアカウントとして `POST /api/auth/login/legacy` に次を送ります。

```json
{
  "username": "example_user",
  "password": "現在のパスワード",
  "srp_salt": "<Base64の16バイトのsalt>",
  "srp_verifier": "<Base64の256バイトのverifier>",
  "srp_group": "2048",
  "srp_kdf": "pbkdf2-600k-v2"
}
```

`srp_salt` と `srp_verifier` はブラウザ側で現在のパスワードから計算します。Cloudflare Workers の WebCrypto は PBKDF2 の反復回数が100,000回以下のため、サーバー側では600,000回のv2検証子を計算できません。サーバーは旧パスワードを検証したうえで、受け取った検証子を保存し、旧ハッシュを削除してセッションを発行します。以後はSRPログインを使ってください。既にSRPへ移行済みのアカウントはこのエンドポイントを使えません。
