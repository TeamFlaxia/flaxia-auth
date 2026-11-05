// Browser client for the Flaxia Auth login UI.
//
// The page is served from auth.flaxia.app and is the only place credentials are
// entered. It never sends a password: registration and login run the SRP-6a
// handshake locally, then the resulting Auth session is exchanged for a
// one-time code bound to the caller's PKCE challenge.
import {
  clientStep1,
  clientStep2,
  computeVerifier,
  DEFAULT_SRP_KDF,
  generateSalt,
  isSupportedSrpKdf,
  verifyServerProof,
} from '../srp.ts';
import { returnUriAllowed } from '../origin.ts';
import { applyTranslations, detectLanguage, type MessageKey, setLanguage, t } from './i18n.ts';

const enc = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
const dec = (value: string): Uint8Array => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
const base64url = (bytes: Uint8Array): string =>
  enc(bytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const randomCode = (bytes = 32): string => base64url(crypto.getRandomValues(new Uint8Array(bytes)));

interface ApiResult {
  status: number;
  ok: boolean;
  body: Record<string, unknown>;
}

async function post(path: string, body: unknown): Promise<ApiResult> {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const parsed = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: response.status, ok: response.ok, body: parsed };
}

// Server errors are stable English identifiers. Translate known ones locally so
// the UI stays in the language Flaxia passed down.
const SERVER_MESSAGES: Record<string, MessageKey> = {
  'Invalid credentials': 'login.error_username_or_password',
  'Invalid request': 'common.error_invalid_request',
  'Too many requests': 'common.error_too_many_requests',
  'Registration failed': 'register.error_general',
  'Invalid registration': 'register.error_general',
  'Invalid email': 'register.error_email_invalid',
  'Invalid display name': 'register.error_display_name_length',
  'Recovery unavailable': 'login.error_recovery_invalid',
  'Invalid proof': 'login.error_username_or_password',
  'Current password is incorrect': 'login.error_current_password',
  'Credentials or session changed': 'common.error_session_expired',
  Unauthenticated: 'common.error_session_expired',
  'Invalid recovery verifier': 'register.recovery_failed',
};

const message = (body: Record<string, unknown>, fallback: MessageKey): string => {
  const error = typeof body.error === 'string' ? body.error : '';
  return t(SERVER_MESSAGES[error] ?? fallback);
};

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element #${id}`);
  return element as T;
}

function showError(text: string): void {
  const box = byId('error');
  box.textContent = text;
  box.hidden = text === '';
}

function showFieldError(id: string, text: string): void {
  const box = byId(id);
  box.textContent = text;
  box.hidden = text === '';
}

function clearRegisterErrors(): void {
  for (const id of [
    'register-username-error',
    'register-display-error',
    'register-email-error',
    'register-password-error',
    'register-confirm-error',
  ])
    showFieldError(id, '');
}

function setBusy(form: HTMLFormElement, busy: boolean, label: string, idle: string): void {
  const button = form.querySelector<HTMLButtonElement>('button[type="submit"]');
  if (!button) return;
  button.disabled = busy;
  button.textContent = busy ? label : idle;
}

const params = new URLSearchParams(window.location.search);
const returnUri = params.get('return_uri');
const challenge = params.get('code_challenge');
const state = params.get('state');

setLanguage(detectLanguage(params.get('lang')));
applyTranslations();

function fatal(key: MessageKey): void {
  showError(t(key));
  for (const element of document.querySelectorAll<HTMLElement>('form, #recovery-step, .auth-footer'))
    element.hidden = true;
}

if (!returnUri || !returnUriAllowed(returnUri) || !challenge || !state) {
  fatal('login.error_invalid_link');
} else {
  void start();
}

async function signIn(username: string, password: string): Promise<void> {
  const start = await post('/api/auth/login/start', { username });
  if (!start.ok) throw new Error(message(start.body, 'login.error_username_or_password'));

  if (start.body.srp === false) {
    // Pre-SRP account: the browser derives the replacement verifier because
    // Workers WebCrypto cannot run the 600k PBKDF2 KDF server-side.
    const salt = generateSalt();
    const verifier = await computeVerifier(password, salt, DEFAULT_SRP_KDF);
    const legacy = await post('/api/auth/login/legacy', {
      username,
      password,
      srp_salt: enc(salt),
      srp_verifier: enc(verifier),
      srp_group: '2048',
      srp_kdf: DEFAULT_SRP_KDF,
    });
    if (legacy.status === 403 && legacy.body.error === 'account_frozen')
      throw new Error(
        t('login.error_account_frozen', { username: String(legacy.body.username ?? username) }),
      );
    if (!legacy.ok) throw new Error(message(legacy.body, 'login.error_username_or_password'));
    return;
  }

  const salt = dec(String(start.body.salt));
  const serverPublic = dec(String(start.body.B));
  const kdf = start.body.srp_kdf;
  if (!isSupportedSrpKdf(kdf)) throw new Error(t('login.error_unsupported_kdf'));
  const first = await clientStep1(password, salt);
  const proof = await clientStep2(password, salt, first.a, serverPublic, kdf);
  const verify = await post('/api/auth/login/verify', {
    challenge_id: start.body.challenge_id,
    A: enc(proof.A),
    M1: enc(proof.M1),
  });
  if (verify.status === 403 && verify.body.error === 'account_frozen')
    throw new Error(t('login.error_account_frozen', { username: String(verify.body.username ?? username) }));
  if (!verify.ok) throw new Error(message(verify.body, 'login.error_username_or_password'));
  if (typeof verify.body.M2 !== 'string' || !(await verifyServerProof(proof.A, proof.M1, proof.K, dec(verify.body.M2))))
    throw new Error(t('login.error_server_verify'));
}

async function signInWithRecovery(username: string, recoveryCode: string): Promise<void> {
  const start = await post('/api/auth/recovery/start', { username });
  if (!start.ok) throw new Error(t('login.error_recovery_unavailable'));
  const salt = dec(String(start.body.salt));
  const kdf = start.body.srp_kdf;
  if (!isSupportedSrpKdf(kdf)) throw new Error(t('login.error_unsupported_kdf'));
  const first = await clientStep1(recoveryCode, salt);
  const proof = await clientStep2(recoveryCode, salt, first.a, dec(String(start.body.B)), kdf);
  const verify = await post('/api/auth/recovery/verify', {
    challenge_id: start.body.challenge_id,
    A: enc(proof.A),
    M1: enc(proof.M1),
  });
  if (!verify.ok) throw new Error(t('login.error_recovery_invalid'));
  if (typeof verify.body.M2 !== 'string' || !(await verifyServerProof(proof.A, proof.M1, proof.K, dec(verify.body.M2))))
    throw new Error(t('login.error_server_verify'));
}

async function currentPasswordProof(password: string): Promise<Record<string, string>> {
  const start = await post('/api/auth/reauth/start', {});
  if (!start.ok) throw new Error(t('login.error_current_password'));
  const salt = dec(String(start.body.salt));
  const kdf = start.body.srp_kdf;
  if (!isSupportedSrpKdf(kdf)) throw new Error(t('login.error_unsupported_kdf'));
  const first = await clientStep1(password, salt);
  const proof = await clientStep2(password, salt, first.a, dec(String(start.body.B)), kdf);
  return { challenge_id: String(start.body.challenge_id), A: enc(proof.A), M1: enc(proof.M1) };
}

async function registerAccount(username: string, displayName: string, password: string, email: string): Promise<void> {
  const salt = generateSalt();
  const verifier = await computeVerifier(password, salt, DEFAULT_SRP_KDF);
  const response = await post('/api/auth/register', {
    username,
    display_name: displayName,
    ...(email ? { email } : {}),
    srp_salt: enc(salt),
    srp_verifier: enc(verifier),
    srp_group: '2048',
    srp_kdf: DEFAULT_SRP_KDF,
  });
  if (!response.ok) throw new Error(message(response.body, 'register.error_general'));
}

async function enrollRecovery(password: string, recoveryCode: string): Promise<void> {
  const salt = generateSalt();
  const verifier = await computeVerifier(recoveryCode, salt, DEFAULT_SRP_KDF);
  const response = await post('/api/auth/recovery/enroll', {
    salt: enc(salt),
    verifier: enc(verifier),
    kdf: DEFAULT_SRP_KDF,
    current_srp: await currentPasswordProof(password),
  });
  if (!response.ok) throw new Error(message(response.body, 'register.recovery_failed'));
}

async function finish(): Promise<void> {
  const authorize = await post('/api/auth/flaxia/authorize', { challenge });
  if (!authorize.ok || typeof authorize.body.code !== 'string')
    throw new Error(message(authorize.body, 'login.error_complete'));
  const target = new URL(returnUri as string);
  target.searchParams.set('code', authorize.body.code);
  target.searchParams.set('state', state as string);
  window.location.assign(target.href);
}

type View = 'login' | 'register';

function configureBack(): void {
  const back = byId<HTMLButtonElement>('auth-back');
  if (!returnUri) {
    back.hidden = true;
    return;
  }
  let target: URL | null = null;
  try {
    const url = new URL(returnUri);
    if (url.protocol === 'http:' || url.protocol === 'https:') target = new URL('/', url);
  } catch {
    target = null;
  }
  if (!target) {
    back.hidden = true;
    return;
  }
  back.addEventListener('click', () => window.location.assign(target.href));
}

async function start(): Promise<void> {
  configureBack();

  const heading = byId('heading');
  const loginForm = byId<HTMLFormElement>('login-form');
  const registerForm = byId<HTMLFormElement>('register-form');
  const recoveryStep = byId('recovery-step');
  const loginFooter = byId('login-footer');
  const registerFooter = byId('register-footer');
  const passwordInput = byId<HTMLInputElement>('login-password');
  const recoveryCheckbox = byId<HTMLInputElement>('login-recovery');

  const setRecoveryMode = (enabled: boolean): void => {
    passwordInput.placeholder = t(enabled ? 'login.recovery_code_placeholder' : 'login.password_placeholder');
    passwordInput.autocomplete = enabled ? 'off' : 'current-password';
    const button = loginForm.querySelector<HTMLButtonElement>('button[type="submit"]');
    if (button && !button.disabled)
      button.textContent = t(enabled ? 'login.submit_recovery' : 'login.submit');
  };

  const showView = (view: View): void => {
    loginForm.hidden = view !== 'login';
    registerForm.hidden = view !== 'register';
    recoveryStep.hidden = true;
    loginFooter.hidden = view !== 'login';
    registerFooter.hidden = view !== 'register';
    heading.dataset.i18n = view === 'login' ? 'login.heading' : 'register.heading';
    applyTranslations();
    showError('');
    setRecoveryMode(view === 'login' && recoveryCheckbox.checked);
  };

  document.addEventListener('click', (event) => {
    const link = (event.target as HTMLElement).closest<HTMLElement>('[data-switch]');
    if (!link) return;
    const view = link.dataset.switch;
    if (view !== 'login' && view !== 'register') return;
    event.preventDefault();
    window.history.replaceState({}, '', `/${view}`);
    showView(view);
  });

  recoveryCheckbox.addEventListener('change', () => {
    setRecoveryMode(recoveryCheckbox.checked);
    showError('');
  });

  showView(params.get('mode') === 'register' || window.location.pathname === '/register' ? 'register' : 'login');

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    const recovery = recoveryCheckbox.checked;
    const username = byId<HTMLInputElement>('login-username').value.trim();
    const secret = recovery
      ? byId<HTMLInputElement>('login-password').value.trim()
      : byId<HTMLInputElement>('login-password').value;
    if (!username || !secret) {
      showError(t('login.error_fill_all'));
      return;
    }
    const busy = t(recovery ? 'login.recovering' : 'login.submitting');
    const idle = t(recovery ? 'login.submit_recovery' : 'login.submit');
    setBusy(loginForm, true, busy, idle);
    try {
      if (recovery) await signInWithRecovery(username, secret);
      else await signIn(username, secret);
      await finish();
    } catch (error) {
      showError((error as Error).message);
      setBusy(loginForm, false, busy, idle);
    }
  });

  let pending: { username: string; password: string } | null = null;
  registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    clearRegisterErrors();
    const username = byId<HTMLInputElement>('register-username').value.trim();
    const displayName = byId<HTMLInputElement>('register-display').value.trim();
    const email = byId<HTMLInputElement>('register-email').value.trim();
    const password = byId<HTMLInputElement>('register-password').value;
    const confirmation = byId<HTMLInputElement>('register-confirm').value;
    const consent = byId<HTMLInputElement>('register-consent');

    let firstError: string | null = null;
    const fieldError = (id: string, text: string): void => {
      showFieldError(id, text);
      firstError ??= text;
    };

    if (!username) fieldError('register-username-error', t('register.error_username_required'));
    else if (!/^[a-zA-Z0-9_]{1,20}$/.test(username))
      fieldError('register-username-error', t('register.error_username_invalid'));
    if (!displayName) fieldError('register-display-error', t('register.error_display_name_required'));
    else if (displayName.length > 50)
      fieldError('register-display-error', t('register.error_display_name_length'));
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      fieldError('register-email-error', t('register.error_email_invalid'));
    if (!password) fieldError('register-password-error', t('register.error_password_required'));
    else if (password.length < 8 || password.length > 128)
      fieldError('register-password-error', t('register.error_password_length'));
    if (!confirmation) fieldError('register-confirm-error', t('register.error_confirm_password'));
    else if (password !== confirmation)
      fieldError('register-confirm-error', t('register.error_password_mismatch'));
    if (!consent.checked) firstError ??= t('register.error_consent_required');

    if (firstError) {
      showError(firstError);
      return;
    }

    const busy = t('register.submitting');
    const idle = t('register.submit');
    setBusy(registerForm, true, busy, idle);
    try {
      await registerAccount(username, displayName, password, email);
      pending = { username, password };
      byId('recovery-code').textContent = randomCode();
      heading.dataset.i18n = 'register.recovery_heading';
      applyTranslations();
      loginForm.hidden = true;
      registerForm.hidden = true;
      loginFooter.hidden = true;
      registerFooter.hidden = true;
      recoveryStep.hidden = false;
      showError('');
    } catch (error) {
      showError((error as Error).message);
      setBusy(registerForm, false, busy, idle);
    }
  });

  byId<HTMLButtonElement>('recovery-continue').addEventListener('click', async () => {
    showError('');
    if (!pending) return;
    const saved = byId<HTMLInputElement>('recovery-saved');
    if (!saved.checked) {
      showError(t('register.recovery_required'));
      return;
    }
    const button = byId<HTMLButtonElement>('recovery-continue');
    button.disabled = true;
    button.textContent = t('register.recovery_finishing');
    try {
      await enrollRecovery(pending.password, byId('recovery-code').textContent ?? '');
      await finish();
    } catch (error) {
      showError((error as Error).message);
      button.disabled = false;
      button.textContent = t('register.recovery_continue');
    }
  });
}
