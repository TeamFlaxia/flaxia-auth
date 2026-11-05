export const originAllowed = (origin: string | undefined): boolean =>
  origin === 'https://auth.flaxia.app' || origin === 'https://flaxia.app';

// Where the login UI may send the user after a successful sign-in. Every entry
// is an exact match; the browser is never redirected to an arbitrary origin.
export const RETURN_URIS = [
  'https://flaxia.app/api/auth/callback',
  'http://localhost:8787/api/auth/callback',
  'http://localhost:8788/api/auth/callback',
  'http://localhost:3000/api/auth/callback',
  // Native apps return through a custom scheme, then redeem the code with the
  // native HTTP transport.
  'flaxia://auth/callback',
] as const;

export const returnUriAllowed = (uri: string | null | undefined): uri is string =>
  uri !== null && uri !== undefined && (RETURN_URIS as readonly string[]).includes(uri);
