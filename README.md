# Flaxia Auth

Flaxia向けの認証サービスです。Cloudflare Workers、Hono、TypeScript、D1で動作し、パスワードをサーバーへ送信しないSRP-6a認証を実装しています。Flaxia本体とはService Bindingで連携し、認証情報、セッション、復旧、アカウント削除の権限を持ちます。

> [!WARNING]
> 開発中です。独立したセキュリティレビューと本番移行の運用確認が完了するまで、実アカウントや本番データには使用しないでください。既知の課題とリリース条件は[Auth migration security review](docs/auth-migration-security-review.md)にまとめています。

## 実装状況

- SRP-6a（2048-bit group、SHA-256）による登録、ログイン、再認証
- PBKDF2-SHA256 600,000回の検証子と、旧方式アカウントの初回ログイン時移行
- `HttpOnly` / `Secure` / `SameSite=Lax` のセッションCookie、ログアウト、Origin検証、レート制限
- ブラウザ生成の復旧コードによるアカウント復旧
- FlaxiaとのService Binding連携（プロビジョニング、セッション交換、グラント失効、パスワード・メール変更、凍結、削除）
- 期限切れのセッション、認可コード、レガシーフィンガープリント、削除キャンセル、メール変更記録の毎時クリーンアップ

WebAuthn / パスキー、Personal Vault統合、OIDC / Sign in with Flaxia、SDKは未実装です。

## 構成

```text
src/index.ts   認証APIとFlaxia連携エンドポイント
src/srp.ts     SRP-6aとKDFの実装
src/origin.ts  許可するOriginの定義
migrations/    D1スキーマとマイグレーション
docs/          API、移行設計、セキュリティレビュー
tests/         認証・移行・競合のテスト
```

## 開発

Node.js 22とnpmを使います。

```sh
npm ci
npm run dev
```

`http://localhost:8787/health` がWorkerの動作確認用エンドポイントです。

```sh
npm test           # 認証・移行・競合テスト
npm run typecheck  # 型定義の確認とTypeScriptの型チェック
```

`wrangler.jsonc` を変更した場合は、`npm run cf-typegen` でWorkerの型定義を更新してください。mainブランチへのpushでは、GitHub Actionsが型チェックとテストを実行した後に本番へデプロイします。

## D1

`wrangler.jsonc` は本番用D1 `flaxia-auth-prod` に接続しています。スキーマは `migrations/` で管理します。

```sh
# ローカル開発用
npx wrangler d1 migrations apply flaxia-auth-prod --local

# 本番用（デプロイ時にCIからも実行されます）
npx wrangler d1 migrations apply flaxia-auth-prod --remote
```

## API

ブラウザ向けの認証APIは `/api/auth/*` です。

| Method | Path | 用途 |
| --- | --- | --- |
| GET | `/health` | 稼働確認 |
| POST | `/api/auth/register` | SRP検証子を使ったアカウント登録 |
| POST | `/api/auth/login/start` | SRPログインの開始 |
| POST | `/api/auth/login/verify` | SRP証明の検証とセッション発行 |
| POST | `/api/auth/login/legacy` | 旧方式アカウントの初回ログインとSRPへの移行 |
| POST | `/api/auth/recovery/start` | 復旧コードによる復旧の開始 |
| POST | `/api/auth/recovery/verify` | 復旧コードの検証とセッション発行 |
| POST | `/api/auth/flaxia/authorize` | Flaxia向けの一時認可コード発行 |
| GET | `/api/auth/me` | 現在のユーザー取得 |
| POST | `/api/auth/reauth/start` | ログイン済みユーザーの再認証を開始 |
| POST | `/api/auth/reauth/verify` | 再認証の証明を検証 |
| POST | `/api/auth/upgrade-srp` | 本人確認後にSRP情報を更新 |
| POST | `/api/auth/logout` | セッション削除 |

Flaxiaからの信頼済みリクエストは、公開ルートではなく `FlaxiaBridge` のService Bindingで受けます。プロビジョニング、セッション交換、グラント失効、認証情報・メール変更、復旧コード登録、削除、凍結などのエンドポイントは `/api/flaxia/*` にあります。

SRPの計算と主要な認証フローは[docs/api.md](docs/api.md)を参照してください。

## セキュリティと移行

- パスワードはSRPの検証子としてのみ保存し、サーバーへ平文を送信しません。例外は旧方式アカウントの初回移行だけです。
- 復旧コードとVaultの復旧フレーズはブラウザで生成し、AuthやFlaxiaへ送信しません。Authは復旧コードのSRP検証子だけを保存します。
- 旧方式のパスワード由来フィンガープリントは90日で失効し、連携完了、認証情報変更、アカウント削除時に削除されます。
- Flaxia向けの変更はService Binding経由に限定し、ブラウザからの認証APIは許可Origin、リクエストサイズ、レート制限で保護します。
- 本番移行では、全対象アカウントの連携状況、復旧コード登録、バックアップの保持期間、独立したセキュリティレビューを確認してください。移行後のロールバックでFlaxiaローカルの認証情報を再び受け入れないでください。

移行手順とロールバックの注意事項は[docs/flaxia-migration.md](docs/flaxia-migration.md)を参照してください。脆弱性は公開Issueに書かず、[SECURITY.md](SECURITY.md)の手順で報告してください。

## ライセンス

[AGPL-3.0](LICENSE)
