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

const message = (body: Record<string, unknown>, fallback: string): string =>
  typeof body.error === 'string' ? body.error : fallback;

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

function setBusy(form: HTMLFormElement, busy: boolean, label: string, idle: string): void {
  const button = form.querySelector<HTMLButtonElement>('button[type="submit"]');
  if (!button) return;
  button.disabled = busy;
  button.textContent = busy ? label : idle;
}

function showTab(tab: 'login' | 'register' | 'recover'): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-tab]')) {
    button.setAttribute('aria-selected', String(button.dataset.tab === tab));
  }
  for (const panel of document.querySelectorAll<HTMLElement>('[data-panel]')) {
    panel.hidden = panel.dataset.panel !== tab;
  }
  showError('');
}

const params = new URLSearchParams(window.location.search);
const returnUri = params.get('return_uri');
const challenge = params.get('code_challenge');
const state = params.get('state');

function fatal(text: string): void {
  showError(text);
  for (const form of document.querySelectorAll('form')) (form as HTMLFormElement).hidden = true;
}

if (!returnUri || !returnUriAllowed(returnUri) || !challenge || !state) {
  fatal('This sign-in link is invalid or has expired. Return to Flaxia and try again.');
} else {
  void start();
}

async function signIn(username: string, password: string): Promise<void> {
  const start = await post('/api/auth/login/start', { username });
  if (!start.ok) throw new Error(message(start.body, 'Invalid username or password.'));

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
      throw new Error(`This account is frozen (${String(legacy.body.username ?? username)}).`);
    if (!legacy.ok) throw new Error(message(legacy.body, 'Invalid username or password.'));
    return;
  }

  const salt = dec(String(start.body.salt));
  const serverPublic = dec(String(start.body.B));
  const kdf = start.body.srp_kdf;
  if (!isSupportedSrpKdf(kdf)) throw new Error('Unsupported password algorithm.');
  const first = await clientStep1(password, salt);
  const proof = await clientStep2(password, salt, first.a, serverPublic, kdf);
  const verify = await post('/api/auth/login/verify', {
    challenge_id: start.body.challenge_id,
    A: enc(proof.A),
    M1: enc(proof.M1),
  });
  if (verify.status === 403 && verify.body.error === 'account_frozen')
    throw new Error(`This account is frozen (${String(verify.body.username ?? username)}).`);
  if (!verify.ok) throw new Error(message(verify.body, 'Invalid username or password.'));
  if (typeof verify.body.M2 !== 'string' || !(await verifyServerProof(proof.A, proof.M1, proof.K, dec(verify.body.M2))))
    throw new Error('The server could not be verified. Try again.');
}

async function signInWithRecovery(username: string, recoveryCode: string): Promise<void> {
  const start = await post('/api/auth/recovery/start', { username });
  if (!start.ok) throw new Error('Recovery is not available for this account.');
  const salt = dec(String(start.body.salt));
  const kdf = start.body.srp_kdf;
  if (!isSupportedSrpKdf(kdf)) throw new Error('Unsupported password algorithm.');
  const first = await clientStep1(recoveryCode, salt);
  const proof = await clientStep2(recoveryCode, salt, first.a, dec(String(start.body.B)), kdf);
  const verify = await post('/api/auth/recovery/verify', {
    challenge_id: start.body.challenge_id,
    A: enc(proof.A),
    M1: enc(proof.M1),
  });
  if (!verify.ok) throw new Error('That recovery code is not valid.');
  if (typeof verify.body.M2 !== 'string' || !(await verifyServerProof(proof.A, proof.M1, proof.K, dec(verify.body.M2))))
    throw new Error('The server could not be verified. Try again.');
}

async function currentPasswordProof(password: string): Promise<Record<string, string>> {
  const start = await post('/api/auth/reauth/start', {});
  if (!start.ok) throw new Error('Could not confirm the current password.');
  const salt = dec(String(start.body.salt));
  const kdf = start.body.srp_kdf;
  if (!isSupportedSrpKdf(kdf)) throw new Error('Unsupported password algorithm.');
  const first = await clientStep1(password, salt);
  const proof = await clientStep2(password, salt, first.a, dec(String(start.body.B)), kdf);
  return { challenge_id: String(start.body.challenge_id), A: enc(proof.A), M1: enc(proof.M1) };
}

async function registerAccount(username: string, displayName: string, password: string): Promise<void> {
  const salt = generateSalt();
  const verifier = await computeVerifier(password, salt, DEFAULT_SRP_KDF);
  const response = await post('/api/auth/register', {
    username,
    display_name: displayName,
    srp_salt: enc(salt),
    srp_verifier: enc(verifier),
    srp_group: '2048',
    srp_kdf: DEFAULT_SRP_KDF,
  });
  if (!response.ok) throw new Error(message(response.body, 'Registration failed.'));
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
  if (!response.ok) throw new Error(message(response.body, 'Could not save the recovery code.'));
}

async function finish(): Promise<void> {
  const authorize = await post('/api/auth/flaxia/authorize', { challenge });
  if (!authorize.ok || typeof authorize.body.code !== 'string')
    throw new Error(message(authorize.body, 'Could not complete sign-in.'));
  const target = new URL(returnUri as string);
  target.searchParams.set('code', authorize.body.code);
  target.searchParams.set('state', state as string);
  window.location.assign(target.href);
}

async function start(): Promise<void> {
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-tab]')) {
    button.addEventListener('click', () => showTab(button.dataset.tab as 'login' | 'register' | 'recover'));
  }
  showTab(params.get('mode') === 'register' || window.location.pathname === '/register' ? 'register' : 'login');

  const loginForm = byId<HTMLFormElement>('login-form');
  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    const username = byId<HTMLInputElement>('login-username').value.trim();
    const password = byId<HTMLInputElement>('login-password').value;
    setBusy(loginForm, true, 'Signing in…', 'Sign in');
    try {
      await signIn(username, password);
      await finish();
    } catch (error) {
      showError((error as Error).message);
      setBusy(loginForm, false, 'Signing in…', 'Sign in');
    }
  });

  const recoveryForm = byId<HTMLFormElement>('recover-form');
  recoveryForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    const username = byId<HTMLInputElement>('recover-username').value.trim();
    const recoveryCode = byId<HTMLInputElement>('recover-code').value.trim();
    setBusy(recoveryForm, true, 'Recovering…', 'Recover account');
    try {
      await signInWithRecovery(username, recoveryCode);
      await finish();
    } catch (error) {
      showError((error as Error).message);
      setBusy(recoveryForm, false, 'Recovering…', 'Recover account');
    }
  });

  const registerForm = byId<HTMLFormElement>('register-form');
  let pending: { username: string; password: string } | null = null;
  registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    const username = byId<HTMLInputElement>('register-username').value.trim();
    const displayName = byId<HTMLInputElement>('register-display').value.trim();
    const password = byId<HTMLInputElement>('register-password').value;
    const confirmation = byId<HTMLInputElement>('register-confirm').value;
    if (password !== confirmation) {
      showError('The passwords do not match.');
      return;
    }
    setBusy(registerForm, true, 'Creating account…', 'Create account');
    try {
      await registerAccount(username, displayName, password);
      pending = { username, password };
      const code = randomCode();
      byId('recovery-code').textContent = code;
      byId('recovery-step').hidden = false;
      registerForm.hidden = true;
    } catch (error) {
      showError((error as Error).message);
      setBusy(registerForm, false, 'Creating account…', 'Create account');
    }
  });

  byId<HTMLButtonElement>('recovery-continue').addEventListener('click', async () => {
    showError('');
    if (!pending) return;
    const saved = byId<HTMLInputElement>('recovery-saved');
    if (!saved.checked) {
      showError('Save the recovery code before continuing.');
      return;
    }
    const button = byId<HTMLButtonElement>('recovery-continue');
    button.disabled = true;
    button.textContent = 'Finishing…';
    try {
      await enrollRecovery(pending.password, byId('recovery-code').textContent ?? '');
      await finish();
    } catch (error) {
      showError((error as Error).message);
      button.disabled = false;
      button.textContent = 'Continue';
    }
  });
}
