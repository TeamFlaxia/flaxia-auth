// The OIDC consent page.
//
// The page is rendered by the Worker so it can show the registered client
// name, the redirect host and the exact scopes without a client-side build.
// It contains no scripts: the only action is a same-origin form POST back to
// /oauth/authorize.

export type ConsentLanguage = 'en' | 'ja';

export interface ConsentPageOptions {
  language: ConsentLanguage;
  clientName: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  username: string;
  displayName: string | null;
  requestId: string;
  theme?: string | null;
}

const LABELS: Record<ConsentLanguage, Record<string, string>> = {
  en: {
    title: 'Authorize access · Flaxia',
    heading: 'Continue to {client}',
    subtitle: 'This application wants to use your Flaxia account.',
    signedInAs: 'Signed in as',
    redirect: 'You will return to {host}',
    scopesHeading: 'This application will be able to:',
    scope_openid: 'Verify your identity',
    scope_profile: 'Read your username, display name and profile',
    scope_email: 'Read your email address',
    scope_offline_access: 'Stay connected after you leave',
    approve: 'Allow',
    deny: 'Deny',
    cancelHint: 'You can deny access and return to the application.',
    footer: 'Only share access with applications you trust.',
  },
  ja: {
    title: 'アクセスを許可 · Flaxia',
    heading: '{client} へ移動',
    subtitle: 'このアプリケーションはFlaxiaアカウントの利用を求めています。',
    signedInAs: 'ログイン中',
    redirect: '{host} に戻ります',
    scopesHeading: 'このアプリケーションに許可する内容:',
    scope_openid: '本人確認',
    scope_profile: 'ユーザー名・表示名・プロフィールの読み取り',
    scope_email: 'メールアドレスの読み取り',
    scope_offline_access: '離席後も接続を維持',
    approve: '許可',
    deny: '拒否',
    cancelHint: '拒否するとアプリケーションへ戻ります。',
    footer: '信頼できるアプリケーションにだけ許可してください。',
  },
};

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const format = (template: string, values: Record<string, string>): string =>
  template.replace(/\{(\w+)\}/g, (_, key: string) => values[key] ?? '');

export function detectConsentLanguage(value: string | null | undefined, acceptLanguage: string | null | undefined): ConsentLanguage {
  if (value === 'ja' || value === 'en') return value;
  if (value?.startsWith('ja')) return 'ja';
  if (acceptLanguage?.toLowerCase().includes('ja')) return 'ja';
  return 'en';
}

function scopeLabel(language: ConsentLanguage, scope: string): string {
  return LABELS[language][`scope_${scope}`] ?? scope;
}

export function renderConsentPage(options: ConsentPageOptions): string {
  const language = options.language;
  const labels = LABELS[language];
  const host = (() => {
    try {
      return new URL(options.redirectUri).host;
    } catch {
      return options.redirectUri;
    }
  })();
  const values = { client: options.clientName, host, username: options.username };
  const theme = options.theme === 'dark' || options.theme === 'light' ? options.theme : '';
  const scopeItems = [...new Set(options.scopes)]
    .map(scope => `<li>${escapeHtml(scopeLabel(language, scope))}</li>`)
    .join('');

  return `<!doctype html>
<html lang="${language}"${theme ? ` data-theme="${theme}"` : ''}>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex" />
    <title>${escapeHtml(labels.title)}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0; --text: #0f172a;
        --muted: #64748b; --primary: #10b981; --primary-fg: #022c22;
        --danger: #dc2626; --danger-border: #fecaca; --chip: #f1f5f9;
      }
      :root[data-theme="dark"] {
        color-scheme: dark;
        --bg: #111827; --card: #181d28; --border: #2e374d; --text: #f8fafc;
        --muted: #94a3b8; --primary: #10b981; --primary-fg: #022c22;
        --danger: #fca5a5; --danger-border: #7f1d1d; --chip: #212736;
      }
      @media (prefers-color-scheme: dark) {
        :root:not([data-theme="light"]) {
          color-scheme: dark;
          --bg: #111827; --card: #181d28; --border: #2e374d; --text: #f8fafc;
          --muted: #94a3b8; --primary: #10b981; --primary-fg: #022c22;
          --danger: #fca5a5; --danger-border: #7f1d1d; --chip: #212736;
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0; min-height: 100vh; display: grid; place-items: center;
        padding: 2rem 1rem; background: var(--bg); color: var(--text);
        font-family: "Noto Sans JP", system-ui, -apple-system, "Segoe UI", sans-serif;
        font-size: 15px; line-height: 1.7;
      }
      main {
        width: 100%; max-width: 440px; padding: 28px; background: var(--card);
        border: 1px solid var(--border); border-radius: 12px;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
      }
      .brand { color: var(--primary); font-weight: 700; letter-spacing: -0.02em; }
      h1 { margin: 8px 0 4px; font-size: 20px; line-height: 1.4; }
      p { margin: 0 0 12px; }
      .muted { color: var(--muted); font-size: 13px; }
      .account {
        display: flex; align-items: center; gap: 10px; margin: 18px 0;
        padding: 10px 12px; background: var(--chip); border-radius: 8px;
      }
      .avatar {
        width: 32px; height: 32px; border-radius: 50%; display: grid;
        place-items: center; background: var(--primary); color: var(--primary-fg);
        font-weight: 700;
      }
      ul { margin: 8px 0 20px; padding-left: 20px; }
      li { margin: 4px 0; }
      .actions { display: grid; gap: 8px; }
      button {
        width: 100%; height: 40px; border-radius: 8px; font: inherit;
        font-weight: 600; cursor: pointer;
      }
      .approve { border: 1px solid var(--primary); background: var(--primary); color: var(--primary-fg); }
      .deny { border: 1px solid var(--danger-border); background: transparent; color: var(--danger); }
      .deny:hover { background: rgba(239, 68, 68, 0.08); }
      .footer { margin-top: 16px; text-align: center; }
    </style>
  </head>
  <body>
    <main>
      <div class="brand">Flaxia</div>
      <h1>${escapeHtml(format(labels.heading, values))}</h1>
      <p class="muted">${escapeHtml(labels.subtitle)}</p>
      <div class="account">
        <div class="avatar">${escapeHtml((options.displayName || options.username).charAt(0).toUpperCase())}</div>
        <div>
          <div>${escapeHtml(labels.signedInAs)} <strong>@${escapeHtml(options.username)}</strong></div>
          <div class="muted">${escapeHtml(format(labels.redirect, values))}</div>
        </div>
      </div>
      <p><strong>${escapeHtml(labels.scopesHeading)}</strong></p>
      <ul>${scopeItems}</ul>
      <form method="post" action="/oauth/authorize" class="actions">
        <input type="hidden" name="request_id" value="${escapeHtml(options.requestId)}" />
        <button class="approve" type="submit" name="decision" value="approve">${escapeHtml(labels.approve)}</button>
        <button class="deny" type="submit" name="decision" value="deny">${escapeHtml(labels.deny)}</button>
      </form>
      <p class="muted footer">${escapeHtml(labels.footer)}</p>
    </main>
  </body>
</html>`;
}
