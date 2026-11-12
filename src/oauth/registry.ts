// OAuth providers Flaxia can connect to.
//
// The `mode` of a provider is not a design preference. It is decided by two
// measured facts about the provider's token endpoint:
//
//   client          The browser can call the token endpoint itself (it sends
//                   CORS headers for our origin) and the flow needs no client
//                   secret. The browser therefore receives the token and
//                   encrypts it into the Vault. Auth never sees it.
//
//   server_exchange The token endpoint refuses cross-origin calls, or the flow
//                   needs a client secret a browser cannot keep. Auth
//                   performs the exchange and hands the result back sealed
//                   to a client public key, so the plaintext is never stored.
//
// The CORS behaviour was measured on 2026-11-12 against
// `Origin: https://flaxia.app`. Do not change a mode without re-measuring:
//   microsoft  ACAO: *            slack    ACAO: *
//   discord    ACAO: <origin>     google   ACAO: <origin>
//   line       ACAO: *            openai   ACAO: *
//   github     no CORS header     x        no CORS header
//   opencode   ACAO: https://opencode.ai (fixed)

export type OAuthMode = 'client' | 'server_exchange';

export interface OAuthProvider {
  id: string;
  label: string;
  mode: OAuthMode;
  authorizeUrl: string;
  tokenUrl: string;
  revokeUrl?: string;
  scopes: string[];
  /** Whether the flow requires a client secret the browser cannot hold. */
  requiresClientSecret: boolean;
  /**
   * A well-known public client id, for providers whose client is not
   * registered per deployment (the OpenCode device flow is public).
   */
  publicClientId?: string;
  /** Wrangler secret name holding the client id, when the provider needs one. */
  clientIdEnv?: string;
  /** Wrangler secret name holding the client secret, when one is required. */
  clientSecretEnv?: string;
  /** Extra authorization parameters, e.g. Google's offline access hint. */
  extraAuthParams?: Record<string, string>;
}

const PROVIDERS: Record<string, OAuthProvider> = {
  google: {
    id: 'google',
    label: 'Google',
    mode: 'client',
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    revokeUrl: 'https://oauth2.googleapis.com/revoke',
    scopes: ['calendar.readonly', 'gmail.readonly'],
    requiresClientSecret: false,
    clientIdEnv: 'GOOGLE_OAUTH_CLIENT_ID',
    extraAuthParams: { access_type: 'offline', prompt: 'consent' },
  },
  microsoft: {
    id: 'microsoft',
    label: 'Microsoft',
    mode: 'client',
    authorizeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    revokeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/revoke',
    scopes: ['openid', 'profile', 'offline_access', 'User.Read', 'Calendars.Read', 'Mail.Read'],
    requiresClientSecret: false,
    clientIdEnv: 'MICROSOFT_OAUTH_CLIENT_ID',
  },
  slack: {
    id: 'slack',
    label: 'Slack',
    mode: 'client',
    authorizeUrl: 'https://slack.com/oauth/v2/authorize',
    tokenUrl: 'https://slack.com/api/oauth.v2.access',
    scopes: ['channels:read', 'channels:history', 'chat:write', 'groups:read', 'im:history', 'users:read'],
    requiresClientSecret: false,
    clientIdEnv: 'SLACK_OAUTH_CLIENT_ID',
  },
  discord: {
    id: 'discord',
    label: 'Discord',
    mode: 'client',
    authorizeUrl: 'https://discord.com/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    revokeUrl: 'https://discord.com/api/oauth2/token/revoke',
    scopes: ['identify', 'email'],
    requiresClientSecret: false,
    clientIdEnv: 'DISCORD_OAUTH_CLIENT_ID',
  },
  line: {
    id: 'line',
    label: 'LINE',
    mode: 'server_exchange',
    authorizeUrl: 'https://access.line.me/oauth2/v2.1/authorize',
    tokenUrl: 'https://api.line.me/oauth2/v2.1/token',
    scopes: ['profile', 'openid'],
    requiresClientSecret: true,
    clientIdEnv: 'LINE_OAUTH_CLIENT_ID',
    clientSecretEnv: 'LINE_OAUTH_CLIENT_SECRET',
  },
  openai: {
    id: 'openai',
    label: 'OpenAI',
    mode: 'client',
    authorizeUrl: 'https://auth.openai.com/api/accounts/authorize',
    tokenUrl: 'https://auth.openai.com/api/accounts/oauth/token',
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    requiresClientSecret: false,
    clientIdEnv: 'OPENAI_OAUTH_CLIENT_ID',
  },
  opencode: {
    id: 'opencode',
    label: 'OpenCode',
    mode: 'server_exchange',
    authorizeUrl: 'https://console.opencode.ai/console/device',
    tokenUrl: 'https://console.opencode.ai/auth/device/token',
    scopes: ['inference'],
    // The device flow is a public client, but the Console answers with a
    // fixed `Access-Control-Allow-Origin: https://opencode.ai`, so a browser
    // on our origin cannot poll for the token.
    requiresClientSecret: false,
    publicClientId: 'opencode-cli',
  },
  github: {
    id: 'github',
    label: 'GitHub',
    mode: 'server_exchange',
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scopes: ['read:user', 'user:email'],
    requiresClientSecret: true,
    clientIdEnv: 'GITHUB_OAUTH_CLIENT_ID',
    clientSecretEnv: 'GITHUB_OAUTH_CLIENT_SECRET',
  },
  x: {
    id: 'x',
    label: 'X',
    mode: 'server_exchange',
    authorizeUrl: 'https://x.com/i/oauth2/authorize',
    tokenUrl: 'https://api.x.com/2/oauth2/token',
    revokeUrl: 'https://api.x.com/2/oauth2/revoke',
    scopes: ['tweet.read', 'users.read', 'offline.access'],
    requiresClientSecret: true,
    clientIdEnv: 'X_OAUTH_CLIENT_ID',
    clientSecretEnv: 'X_OAUTH_CLIENT_SECRET',
  },
};

export const PROVIDER_IDS = Object.freeze(Object.keys(PROVIDERS));

export const listProviders = (): OAuthProvider[] =>
  PROVIDER_IDS.map(id => PROVIDERS[id] as OAuthProvider);

export const getProvider = (id: string | null | undefined): OAuthProvider | null => {
  if (typeof id !== 'string' || id.length === 0) return null;
  // Only an exact key matches. A provider id is never derived from a path
  // segment, so "google/../slack" must not resolve to Slack.
  return Object.prototype.hasOwnProperty.call(PROVIDERS, id) ? PROVIDERS[id] as OAuthProvider : null;
};

export const providerMode = (id: string): OAuthMode | null => getProvider(id)?.mode ?? null;

export const providerScopes = (id: string): string[] => getProvider(id)?.scopes ?? [];

export interface AuthorizeUrlOptions {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scopes: string[];
  extra?: Record<string, string>;
}

/**
 * Build the provider authorization URL. The redirect is fixed to the Auth
 * origin: a caller cannot point the provider somewhere else, because that
 * would leak the authorization code to a third party.
 */
export const buildAuthorizeUrl = (providerId: string, options: AuthorizeUrlOptions): string => {
  const provider = getProvider(providerId);
  if (!provider) throw new Error('Unknown OAuth provider');
  if (!options.redirectUri.startsWith('https://auth.flaxia.app/')) {
    throw new Error('OAuth redirect must stay on the Auth origin');
  }
  const url = new URL(provider.authorizeUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', options.clientId);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('state', options.state);
  url.searchParams.set('code_challenge', options.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (options.scopes.length > 0) url.searchParams.set('scope', options.scopes.join(' '));
  for (const [key, value] of Object.entries({ ...provider.extraAuthParams, ...options.extra })) {
    url.searchParams.set(key, value);
  }
  return url.toString();
};
