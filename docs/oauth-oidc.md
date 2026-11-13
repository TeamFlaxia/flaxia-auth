# OAuth 2.0 / OpenID Connect

Flaxia Auth は OAuth 2.0 認可サーバーかつ OpenID Connect (OIDC) プロバイダーとして動作します。RP（Relying Party）は Flaxia のアカウントでユーザーを認証し、ID トークンと UserInfo からユーザー識別子とプロフィールを取得できます。

イシュアーは `https://auth.flaxia.app` です。ディスカバリ ドキュメントで確認できます。

```sh
curl https://auth.flaxia.app/.well-known/openid-configuration
```

## エンドポイント

| Method | Path | 用途 |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | OIDC ディスカバリ |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 メタデータ |
| GET | `/oauth/jwks` | 公開鍵セット（RS256） |
| GET | `/oauth/authorize` | 認可エンドポイント |
| POST | `/oauth/token` | トークンエンドポイント |
| GET | `/oauth/userinfo` | UserInfo |
| POST | `/oauth/revoke` | トークン失効（RFC 7009） |

OAuth のエンドポイントはブラウザのクロスオリジン Ajax ではなく、トップレベルリダイレクト（認可）とサーバー間通信（トークン・UserInfo・失効）で利用します。CORS は提供しません。

## クライアント登録

クライアントは Flaxia 本体の Service Binding から登録します。公開の動的クライアント登録（RFC 7591）は未提供です。

```http
POST /api/flaxia/oauth/clients
Content-Type: application/json

{
  "client_id": "optional-custom-id",
  "client_name": "Example App",
  "redirect_uris": ["https://app.example/auth/callback"],
  "is_confidential": true,
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

- `client_id` を省略するとランダムなIDを発行します。
- `is_confidential: true` の場合、`client_secret` を発行して一度だけ返します。機密クライアントは `client_secret_basic` または `client_secret_post` で認証できます。
- `is_confidential: false`（デフォルト）のパブリッククライアントはシークレットを持ちません。PKCE が必須です。
- `redirect_uris` は完全一致のみ許可します。フラグメントを含みません。`http://localhost` と `http://127.0.0.1` のみ開発用途で HTTP を許可します。
- `grant_types` は `authorization_code` と `refresh_token` のみ指定できます。

クライアントの失効は `POST /api/flaxia/oauth/clients/revoke` に `{ "client_id": "..." }` を送ります。失効すると、そのクライアントのコードとトークンがすべて削除されます。

## 認可コードフロー

1. RP はブラウザを認可エンドポイントにリダイレクトします。

   ```text
   GET /oauth/authorize
     ?client_id=<id>
     &redirect_uri=<registered-uri>
     &response_type=code
     &scope=openid%20profile%20email%20offline_access
     &state=<random>
     &nonce=<random>
     &code_challenge=<S256-challenge>
     &code_challenge_method=S256
   ```

   `openid` スコープは必須です。PKCE は全クライアントで必須です（`plain` は非対応）。ユーザーが Auth のセッションを持たない場合は、`error=login_required` を redirect_uri に返します。

2. 成功すると `code` と `state` を redirect_uri にリダイレクトします。

3. RP はトークンエンドポイントでコードを交換します。

   ```http
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=<code>
   &redirect_uri=<registered-uri>
   &client_id=<id>
   &client_secret=<secret>
   &code_verifier=<verifier>
   ```

   成功時のレスポンス:

   ```json
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "...",
     "id_token": "...",
     "scope": "openid profile email offline_access"
   }
   ```

   `offline_access` を要求しなかった場合、`refresh_token` は返りません。

## トークン

| 種別 | 有効期限 | 保存方法 |
| --- | --- | --- |
| 認可コード | 60秒 | SHA-256 ハッシュ、一度限り |
| アクセストークン | 1時間 | SHA-256 ハッシュ |
| リフレッシュトークン | 30日 | SHA-256 ハッシュ、ローテーション |
| ID トークン | 1時間 | RS256 JWT |

- 認可コードは `consumed_at` を原子的に設定して一度だけ消費します。
- リフレッシュトークンは使用するたびに新しいものを発行し、古いものとそのアクセストークンを失効します。失効済みのリフレッシュトークンの再使用を検知した場合は、同じクライアント・ユーザー・セッションのトークンファミリーをすべて失効します。
- トークンは Auth セッションに紐付きます。ログアウトやアカウント削除でセッションが消えると、トークンも失効します。
- 失効は `POST /oauth/revoke` に `token` を送ります。RFC 7009 に従い、未知のトークンでも 200 を返します。

## ID トークン

ID トークンは RS256 の JWT です。`GET /oauth/jwks` の公開鍵で検証できます。

| クレーム | 内容 |
| --- | --- |
| `iss` | `https://auth.flaxia.app` |
| `sub` | Auth のユーザーID（全クライアントで共通） |
| `aud` | クライアントID |
| `iat` | 発行時刻 |
| `exp` | 失効時刻 |
| `nonce` | 認可リクエストの `nonce`（指定時） |

## UserInfo

`GET /oauth/userinfo` に `Authorization: Bearer <access_token>` を送ります。`sub` は必ず返ります。それ以外のクレームはスコープに応じて返ります。

| スコープ | クレーム |
| --- | --- |
| `openid` | `sub`（必須） |
| `profile` | `preferred_username`, `name` |
| `email` | `email`, `email_verified` |
| `offline_access` | リフレッシュトークン発行 |

`email` は未検証のため、`email_verified` は常に `false` です。

## エラー

認可エンドポイントは、redirect_uri が有効な場合は `error` と `error_description` をリダイレクトで返します。client_id が不明、redirect_uri が未登録の場合はリダイレクトせずに 400 を返します。

| エラー | 意味 |
| --- | --- |
| `invalid_request` | 必須パラメーターの欠落や不正な値 |
| `invalid_client` | クライアント認証の失敗 |
| `unauthorized_client` | クライアントがそのグラントタイプを利用不可 |
| `unsupported_response_type` | `response_type=code` 以外 |
| `invalid_scope` | スコープが未対応またはクライアントに未許可 |
| `login_required` | セッションが必要 |
| `invalid_grant` | コード・リフレッシュトークンが無効または失効 |
| `invalid_token` | アクセストークンが無効または失効 |
| `insufficient_scope` | 必要なスコープが不足 |

## 署名鍵

署名鍵は最初の ID トークン発行時に自動生成され、D1 に保存されます。`POST /api/flaxia/oauth/keys/rotate` で新しい鍵を発行すると、以降の ID トークンは新しい鍵で署名されます。旧鍵は `POST /api/flaxia/oauth/keys/revoke` で JWKS から取り除くまで残ります。

## セキュリティ

- PKCE（S256）を全クライアントに必須にしています。
- 認可コードは60秒で失効し、原子的に一度だけ消費します。
- トークン・コード・クライアントシークレットはハッシュのみ保存します。
- redirect_uri は登録値との完全一致のみ許可し、未登録URIにはリダイレクトしません。
- トークンは Auth セッションに紐付き、ログアウト・削除で失効します。
- リフレッシュトークンはローテーションし、再使用を検知した場合はファミリーを失効します。
- 認可・トークン・UserInfo には IP ごとのレート制限を適用します。
- 署名秘密鍵は D1 に保存します。D1 は Cloudflare により保存時に暗号化されますが、DB への読み取りアクセスを持つ者による署名が可能になる点に注意してください。
- 同意画面は未提供です。クライアント登録は信頼済みの Flaxia Service Binding に限定されているため、第一者クライアント向けのフェーズ1としています。

## 未実装

- 動的クライアント登録（RFC 7591）と管理 UI
- トークンイントロスペクション（RFC 7662）
- `max_age` / `acr` / `prompt=consent` / 同意画面
- OpenID Connect RP-Initiated Logout
- クレームのマッピング設定
