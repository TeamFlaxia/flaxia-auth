# Flaxia Auth

Flaxia向けの認証サービスです。Cloudflare Workers、Hono、TypeScriptで開発しています。

## 開発状況

開発初期です。現在はヘルスチェックだけを提供し、登録、ログイン、パスキー、Vault、OIDCは実装していません。実アカウントや本番データには使用しないでください。

## 開発

Node.js 22とnpmを使います。

```sh
npm ci
npm run dev
```

`http://localhost:8787/health` がWorkerの動作確認用エンドポイントです。型チェックは `npm run typecheck` で実行できます。

`wrangler.jsonc` を変更した場合は、`npm run cf-typegen` でWorkerの型定義を更新してください。

## D1

`wrangler.jsonc` は本番用D1 `flaxia-auth-prod` に接続しています。データベースのスキーマとマイグレーションは、認証データの設計後に追加します。

## デプロイ

ローカルから手動デプロイする場合は、`npx wrangler login` で認証してから `npm run deploy` を実行してください。

`main` へのpushでは、型チェックが成功した後にGitHub Actionsが自動デプロイします。Pull Requestでは型チェックのみ実行し、`main` からの手動実行もできます。GitHub ActionsのSecretに `CLOUDFLARE_API_TOKEN`、Variableに `CLOUDFLARE_ACCOUNT_ID` を登録してください。
