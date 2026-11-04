# ログイン UI を Auth に移す

## 目的

Flaxia 本体（`flaxia.app`）が持っていたログイン・登録・復旧（リカバリ）の画面を
`auth.flaxia.app` に移し、Flaxia は「認証画面へのリダイレクト」と「セッションの
有効性確認」だけを担当する。パスワードを扱うコードをアプリ本体から無くし、
認証の責務を単一のオリジンに集約する。

## 全体の流れ

```
Flaxia /login
  └─ GET /api/auth/start
       ├─ verifier / challenge(S256) / state を生成
       ├─ HttpOnly Cookie "flaxia_oauth" (SameSite=Lax, 10分) に保存
       └─ 302 -> auth.flaxia.app/login?code_challenge=...&state=...&return_uri=...

auth.flaxia.app /login
  ├─ ユーザー名 + パスワードで SRP-6a ログイン（旧方式・リカバリも同じ画面）
  ├─ POST /api/auth/flaxia/authorize { challenge }
  └─ 302 -> return_uri?code=...&state=...

Flaxia /api/auth/callback
  ├─ Cookie の state と照合（不一致なら /login へ）
  ├─ AUTH_SERVICE binding で /api/flaxia/exchange を呼び、grant を取得
  ├─ プロフィール作成・リンク・旧資格情報の削除（既存 /flaxia/exchange と同じ処理）
  ├─ Set-Cookie: session=<grant>
  └─ 302 -> return_to（既定 /home）
```

## なぜリダイレクト方式か

- パスワードと SRP の実装が `auth.flaxia.app` にだけ存在する。Flaxia 側には
  パスワード入力欄も SRP クライアントも残らない。
- 認証成功後は既存の「grant（43文字）をセッション Cookie にする」方式をそのまま
  使う。Flaxia は毎リクエスト `introspectAuthGrant` で Auth に問い合わせるため、
  セッションの有効性は常に Auth が決める。
- 画面遷移だけなので、iframe や `postMessage` のブリッジを増やさない。

## セッション有効性の確認

`functions/lib/auth.ts` の `getSession` / `getMeWithSession` は、43文字の
セッショントークンを Auth の grant とみなし、`introspectAuthGrant`
（`functions/lib/flaxia-auth.ts`）で Auth に照会する。Auth が失効・凍結・
credential stamp の変化を返せば Flaxia 側は即座に未認証として扱う。
`isSessionAuthorized` は D1 セッション（移行期間）向けの追加チェックで、
Auth セッションでは上記の introspect が同じ役割を果たす。

## リダイレクト先の制限

`src/origin.ts` の `RETURN_URIS` に完全一致する URL だけを許可する。

- `https://flaxia.app/api/auth/callback`
- ローカル開発用 `http://localhost:{3000,8787,8788}/api/auth/callback`
- ネイティブアプリ用 `flaxia://auth/callback`

Flaxia 側の `/api/auth/callback` も、`return_to` に相対パスだけを許可して
オープンリダイレクトを防ぐ。

## ネイティブアプリ

WebView のオリジン（`capacitor://localhost` / `tauri://localhost`）は
`flaxia.app` ではないため、`return_uri=https://flaxia.app/...` へ戻すと
ネイティブシェルから外れてしまう。ネイティブでは次の経路を使う。

1. アプリが verifier / state を端末内に保存し、Auth のログイン画面を
   システムブラウザで開く（`return_uri=flaxia://auth/callback`）。
2. ログイン後、Auth が `flaxia://auth/callback?code=...&state=...` へ 302。
3. OS がアプリを起動し、アプリが URL を受け取る。
4. アプリが native fetch で `POST https://flaxia.app/api/auth/flaxia/exchange`
   に `code` と `verifier` を送り、grant をネイティブの Cookie ジャーに保存する。

`flaxia://` スキームの登録と URL 受信は Tauri / Capacitor のネイティブ設定で行う。

## ロールアウト

1. このリポジトリを先にデプロイする（`/login` と `/api/auth/recovery/enroll` は
   追加のみで後方互換）。
2. Flaxia 本体をデプロイし、ログイン画面をリダイレクトへ切り替える。
3. 問題があれば Flaxia 側だけを戻せる。Auth 側の変更は残っていても無害。
