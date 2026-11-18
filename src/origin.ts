export const originAllowed = (origin: string | undefined): boolean =>
  origin === 'https://auth.flaxia.app' ||
  origin === 'https://flaxia.app' ||
  origin === 'https://studio.flaxia.app' ||
  // Studio development servers (Vite dev/preview and the dist smoke test).
  origin === 'http://localhost:4173' ||
  origin === 'http://127.0.0.1:4173' ||
  origin === 'http://localhost:4174' ||
  origin === 'http://127.0.0.1:4174';

// Where the login UI may send the user after a successful sign-in. Every entry
// is an exact match; the browser is never redirected to an arbitrary origin.
export const RETURN_URIS = [
  'https://flaxia.app/api/auth/callback',
  'http://localhost:8787/api/auth/callback',
  'http://localhost:8788/api/auth/callback',
  'http://localhost:3000/api/auth/callback',
  // Flaxia Studio is a separate first-party origin. It shares the Auth session
  // (same site), so the login UI only has to return to its callback; Studio
  // verifies the state and uses the session cookie for the API calls.
  'https://studio.flaxia.app/',
  'https://studio.flaxia.app/auth/callback',
  'http://localhost:4173/',
  'http://localhost:4173/auth/callback',
  'http://127.0.0.1:4173/',
  'http://127.0.0.1:4173/auth/callback',
  'http://localhost:4174/',
  'http://localhost:4174/auth/callback',
  'http://127.0.0.1:4174/',
  'http://127.0.0.1:4174/auth/callback',
  // Native apps return through a custom scheme, then redeem the code with the
  // native HTTP transport.
  'flaxia://auth/callback',
] as const;

export const returnUriAllowed = (uri: string | null | undefined): uri is string =>
  uri !== null && uri !== undefined && (RETURN_URIS as readonly string[]).includes(uri);
