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

## 制限と旧方式

認証APIはリクエスト元IPごとに各パスで毎分20回、SRPログイン開始と旧方式ログインはそれぞれユーザーごとに毎分5回までです。超過時は429を返します。

`/api/auth/login/start` が `{ "srp": false }` を返した場合に限り、旧方式のアカウントとして `POST /api/auth/login/legacy` に `{ "username", "password" }` を送り、初回のみ既存パスワードでログインします。成功すると同じパスワードのSRP検証子を作成し、旧ハッシュを削除してセッションを発行します。以後はSRPログインを使ってください。既にSRPへ移行済みのアカウントはこのエンドポイントを使えません。
