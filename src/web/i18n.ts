// Small translation layer for the Auth login UI. Flaxia passes its current
// locale as `lang` so the Auth page uses the same language as the app.
export type Language = 'en' | 'ja';

const en = {
  'meta.title': 'Sign in · Flaxia',
  'auth.back': 'Back',
  'login.heading': 'Sign in to Flaxia',
  'login.username_placeholder': 'Username or email',
  'login.username_hint': 'Enter your username or email address.',
  'login.password_placeholder': 'Password',
  'login.recovery_code_placeholder': 'Account recovery code',
  'login.use_recovery_code': 'Sign in with an account recovery code',
  'login.submit': 'Sign in',
  'login.submit_recovery': 'Recover account',
  'login.submitting': 'Signing in…',
  'login.recovering': 'Recovering…',
  'login.register_link': 'Don\'t have an account? <a href="/register" data-switch="register">Register</a>',
  'login.agree_terms':
    'By logging in, you agree to our <a href="https://flaxia.app/terms" target="_blank" rel="noopener noreferrer" class="legal-notice-link">Terms of Service</a> and <a href="https://flaxia.app/privacy" target="_blank" rel="noopener noreferrer" class="legal-notice-link">Privacy Policy</a>.',
  'login.error_fill_all': 'Please fill in all fields.',
  'login.error_username_invalid': 'Invalid username.',
  'login.error_username_or_password': 'Invalid username or password.',
  'login.error_recovery_invalid':
    'The username or account recovery code is incorrect, or recovery has not been set up.',
  'login.error_recovery_unavailable': 'Recovery is not available for this account.',
  'login.error_account_frozen': 'This account is frozen ({username}).',
  'login.error_network': 'Failed to connect. Please try again.',
  'login.error_server_verify': 'The server could not be verified. Try again.',
  'login.error_invalid_link': 'This sign-in link is invalid or has expired. Return to Flaxia and try again.',
  'login.error_unsupported_kdf': 'Unsupported password algorithm.',
  'login.error_current_password': 'Could not confirm the current password.',
  'login.error_complete': 'Could not complete sign-in.',
  'register.heading': 'Create your account',
  'register.username_placeholder': 'Username',
  'register.username_hint': 'Letters, numbers, underscores. Max 20 chars.',
  'register.email_placeholder': 'Email (optional)',
  'register.display_name_placeholder': 'Display name',
  'register.password_placeholder': 'Password',
  'register.confirm_password_placeholder': 'Confirm password',
  'register.agree_terms':
    'I agree to the <a href="https://flaxia.app/terms" target="_blank" rel="noopener noreferrer" class="consent-link">Terms of Service</a> and <a href="https://flaxia.app/privacy" target="_blank" rel="noopener noreferrer" class="consent-link">Privacy Policy</a>.',
  'register.submit': 'Create account',
  'register.submitting': 'Creating account…',
  'register.login_link': 'Already have an account? <a href="/login" data-switch="login">Sign in</a>',
  'register.error_username_required': 'Username is required.',
  'register.error_username_invalid': 'Invalid username format.',
  'register.error_display_name_required': 'Display name is required.',
  'register.error_display_name_length': 'Display name must be 50 characters or fewer.',
  'register.error_password_required': 'Password is required.',
  'register.error_password_length': 'Password must be 8–128 characters.',
  'register.error_confirm_password': 'Please confirm your password.',
  'register.error_password_mismatch': 'Passwords do not match.',
  'register.error_email_invalid': 'Enter a valid email address.',
  'register.error_consent_required': 'Please agree to the Terms of Service and Privacy Policy.',
  'register.error_general': 'Registration failed.',
  'register.recovery_heading': 'Save your recovery code',
  'register.recovery_description':
    'Save this recovery code. It is the only way to recover the account if you forget the password.',
  'register.recovery_saved': 'I have saved this recovery code somewhere safe.',
  'register.recovery_continue': 'Continue',
  'register.recovery_finishing': 'Finishing…',
  'register.recovery_required': 'Save the recovery code before continuing.',
  'register.recovery_failed': 'Could not save the recovery code.',
  'common.error_too_many_requests': 'Too many attempts. Try again in a minute.',
  'common.error_invalid_request': 'Invalid request.',
  'common.error_session_expired': 'Your session has expired. Try again.',
} as const;

export type MessageKey = keyof typeof en;

const ja: Record<MessageKey, string> = {
  'meta.title': 'ログイン · Flaxia',
  'auth.back': '戻る',
  'login.heading': 'Flaxiaにログイン',
  'login.username_placeholder': 'ユーザー名またはメールアドレス',
  'login.username_hint': 'ユーザー名またはメールアドレスを入力してください。',
  'login.password_placeholder': 'パスワード',
  'login.recovery_code_placeholder': 'アカウント復旧コード',
  'login.use_recovery_code': 'アカウント復旧コードでログイン',
  'login.submit': 'ログイン',
  'login.submit_recovery': 'アカウントを復旧',
  'login.submitting': 'ログイン中...',
  'login.recovering': '復旧中...',
  'login.register_link': 'アカウントをお持ちでない方は <a href="/register" data-switch="register">登録</a>',
  'login.agree_terms':
    'ログインすることで、<a href="https://flaxia.app/terms" target="_blank" rel="noopener noreferrer" class="legal-notice-link">利用規約</a>と<a href="https://flaxia.app/privacy" target="_blank" rel="noopener noreferrer" class="legal-notice-link">プライバシーポリシー</a>に同意したことになります。',
  'login.error_fill_all': 'すべての項目を入力してください。',
  'login.error_username_invalid': 'ユーザー名の形式が正しくありません。',
  'login.error_username_or_password': 'ユーザー名またはパスワードが正しくありません。',
  'login.error_recovery_invalid':
    'ユーザー名またはアカウント復旧コードが正しくないか、復旧コードが設定されていません。',
  'login.error_recovery_unavailable': 'このアカウントでは復旧を利用できません。',
  'login.error_account_frozen': 'このアカウントは凍結されています（{username}）。',
  'login.error_network': '接続に失敗しました。もう一度お試しください。',
  'login.error_server_verify': 'サーバーを確認できませんでした。もう一度お試しください。',
  'login.error_invalid_link':
    'このログインリンクは無効か、有効期限が切れています。Flaxiaに戻ってやり直してください。',
  'login.error_unsupported_kdf': 'サポートされていないパスワード方式です。',
  'login.error_current_password': '現在のパスワードを確認できませんでした。',
  'login.error_complete': 'ログインを完了できませんでした。',
  'register.heading': 'アカウントを作成',
  'register.username_placeholder': 'ユーザー名',
  'register.username_hint': '英字、数字、アンダースコア。最大20文字。',
  'register.email_placeholder': 'メールアドレス（任意）',
  'register.display_name_placeholder': '表示名',
  'register.password_placeholder': 'パスワード',
  'register.confirm_password_placeholder': 'パスワード（確認）',
  'register.agree_terms':
    '<a href="https://flaxia.app/terms" target="_blank" rel="noopener noreferrer" class="consent-link">利用規約</a>と<a href="https://flaxia.app/privacy" target="_blank" rel="noopener noreferrer" class="consent-link">プライバシーポリシー</a>に同意します。',
  'register.submit': 'アカウントを作成',
  'register.submitting': 'アカウントを作成中...',
  'register.login_link': 'すでにアカウントをお持ちの方は <a href="/login" data-switch="login">ログイン</a>',
  'register.error_username_required': 'ユーザー名が必要です。',
  'register.error_username_invalid': 'ユーザー名の形式が正しくありません。',
  'register.error_display_name_required': '表示名が必要です。',
  'register.error_display_name_length': '表示名は50文字以内である必要があります。',
  'register.error_password_required': 'パスワードが必要です。',
  'register.error_password_length': 'パスワードは8〜128文字である必要があります。',
  'register.error_confirm_password': 'パスワード（確認）を入力してください。',
  'register.error_password_mismatch': 'パスワードが一致しません。',
  'register.error_email_invalid': '有効なメールアドレスを入力してください。',
  'register.error_consent_required': '利用規約とプライバシーポリシーに同意してください。',
  'register.error_general': '登録に失敗しました。',
  'register.recovery_heading': '復旧コードを保存',
  'register.recovery_description':
    'この復旧コードを保存してください。パスワードを忘れた場合、アカウントを復旧する唯一の方法です。',
  'register.recovery_saved': '復旧コードを安全な場所に保存しました。',
  'register.recovery_continue': '続ける',
  'register.recovery_finishing': '完了中...',
  'register.recovery_required': '続行する前に復旧コードを保存してください。',
  'register.recovery_failed': '復旧コードを保存できませんでした。',
  'common.error_too_many_requests': '試行回数が多すぎます。1分後にもう一度お試しください。',
  'common.error_invalid_request': 'リクエストが正しくありません。',
  'common.error_session_expired': 'セッションの有効期限が切れました。もう一度お試しください。',
};

const dictionaries: Record<Language, Record<MessageKey, string>> = { en, ja };
const SUPPORTED: readonly Language[] = ['en', 'ja'];
const STORAGE_KEY = 'flaxia_auth_locale';

let language: Language = 'en';

export function isLanguage(value: unknown): value is Language {
  return typeof value === 'string' && (SUPPORTED as readonly string[]).includes(value);
}

/** Prefer Flaxia's explicit `lang`, then a previous choice, then the browser. */
export function detectLanguage(param: string | null): Language {
  if (isLanguage(param)) return param;
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (isLanguage(stored)) return stored;
  } catch {
    /* storage can be unavailable */
  }
  const initial = (navigator.languages?.[0] ?? navigator.language ?? 'en').toLowerCase();
  return initial.startsWith('ja') ? 'ja' : 'en';
}

export function setLanguage(next: Language): void {
  language = next;
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    /* ignore */
  }
  document.documentElement.lang = next;
}

export function getLanguage(): Language {
  return language;
}

export function t(key: MessageKey, params?: Record<string, string | number>): string {
  let value = dictionaries[language][key] ?? en[key];
  if (params) {
    for (const [name, replacement] of Object.entries(params)) {
      value = value.replaceAll(`{${name}}`, String(replacement));
    }
  }
  return value;
}

/** Translate every `data-i18n*` element below `root`. */
export function applyTranslations(root: ParentNode = document): void {
  for (const element of root.querySelectorAll<HTMLElement>('[data-i18n]')) {
    const key = element.dataset.i18n as MessageKey | undefined;
    if (key) element.textContent = t(key);
  }
  for (const element of root.querySelectorAll<HTMLElement>('[data-i18n-html]')) {
    const key = element.dataset.i18nHtml as MessageKey | undefined;
    if (key) element.innerHTML = t(key);
  }
  for (const element of root.querySelectorAll<HTMLElement>('[data-i18n-placeholder]')) {
    const key = element.dataset.i18nPlaceholder as MessageKey | undefined;
    if (key) (element as HTMLInputElement).placeholder = t(key);
  }
  document.title = t('meta.title');
}
