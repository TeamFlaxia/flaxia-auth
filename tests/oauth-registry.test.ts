import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildAuthorizeUrl,
  getProvider,
  listProviders,
  providerMode,
  providerScopes,
  PROVIDER_IDS,
} from '../src/oauth/registry.ts';

// The provider set is decided by measured CORS behaviour of each token
// endpoint, not by documentation. A provider is only listed as "client" when
// the browser can call the token endpoint itself and the flow needs no
// client secret.
test('every listed provider is known and every known provider is listed', () => {
  const listed = listProviders().map(entry => entry.id).sort();
  assert.deepEqual(listed, [...PROVIDER_IDS].sort());
  for (const id of PROVIDER_IDS) {
    const provider = getProvider(id);
    assert.ok(provider, id);
    assert.equal(provider.id, id);
  }
});

test('unknown providers are rejected instead of guessed', () => {
  assert.equal(getProvider('nope'), null);
  assert.equal(getProvider(''), null);
  assert.equal(getProvider('google '), null);
  assert.equal(getProvider('GOOGLE'), null);
  // Path traversal must not reach a provider definition.
  assert.equal(getProvider('../../etc/passwd'), null);
  assert.equal(getProvider('google/../slack'), null);
});

test('client-mode providers need no client secret', () => {
  // A browser cannot keep a secret, so a client-mode provider must not carry
  // one. If a provider ever needs a secret it has to be server-exchange.
  for (const id of PROVIDER_IDS) {
    const provider = getProvider(id)!;
    if (provider.mode === 'client') {
      assert.equal(provider.clientSecretEnv, undefined, id);
      assert.equal(provider.requiresClientSecret, false, id);
    }
  }
});

test('server-exchange providers are the ones a browser cannot drive', () => {
  const server = PROVIDER_IDS.filter(id => providerMode(id) === 'server_exchange');
  assert.deepEqual(server.sort(), ['github', 'line', 'opencode', 'x']);
});

test('a provider that needs a secret says so and names the secret', () => {
  for (const id of PROVIDER_IDS) {
    const provider = getProvider(id)!;
    if (provider.requiresClientSecret) {
      assert.equal(provider.mode, 'server_exchange', id);
      assert.ok(provider.clientSecretEnv, id);
    }
  }
  // A server exchange without a secret is only possible because the provider
  // refuses cross-origin calls, and then the client id is public.
  for (const id of PROVIDER_IDS) {
    const provider = getProvider(id)!;
    if (provider.mode === 'server_exchange' && !provider.requiresClientSecret) {
      assert.ok(provider.publicClientId || provider.clientIdEnv, id);
    }
  }
});

test('only providers a browser can actually reach are client mode', () => {
  // Measured on 2026-11-12 against `Origin: https://flaxia.app`. Two facts
  // decide the mode, and a provider is browser-drivable only when both hold:
  //
  //   reachable  the token endpoint answers with `Access-Control-Allow-Origin`
  //              that matches our origin. A header naming a *different*
  //              origin is as unusable as no header at all, because the
  //              browser compares the value with its own origin.
  //   secretFree the flow needs no client secret, which a browser cannot keep.
  const measured = {
    microsoft: { reachable: true, secretFree: true },
    slack: { reachable: true, secretFree: true },
    discord: { reachable: true, secretFree: true },
    google: { reachable: true, secretFree: true },
    // Reachable, but LINE requires the channel secret.
    line: { reachable: true, secretFree: false },
    openai: { reachable: true, secretFree: true },
    // No CORS header at all on the token endpoint.
    github: { reachable: false, secretFree: false },
    x: { reachable: false, secretFree: false },
    // The Console answers with a fixed `Access-Control-Allow-Origin:
    // https://opencode.ai`, which is not our origin.
    opencode: { reachable: false, secretFree: true },
  } as const;
  for (const [id, facts] of Object.entries(measured)) {
    const provider = getProvider(id);
    assert.ok(provider, id);
    assert.equal(provider.requiresClientSecret, !facts.secretFree, `${id}: secret requirement`);
    assert.equal(
      provider.mode,
      facts.reachable && facts.secretFree ? 'client' : 'server_exchange',
      `${id}: ${JSON.stringify(facts)}`,
    );
  }
});

test('scopes are non-empty strings without duplicates', () => {
  for (const id of PROVIDER_IDS) {
    const scopes = providerScopes(id);
    assert.ok(scopes.length > 0, id);
    assert.equal(new Set(scopes).size, scopes.length, id);
    for (const scope of scopes) {
      assert.equal(typeof scope, 'string');
      assert.ok(scope.length > 0 && scope.length <= 64, `${id}: ${scope}`);
      assert.ok(!/[\s"']/.test(scope), `${id}: ${scope}`);
    }
  }
});

test('authorize URLs are absolute HTTPS endpoints', () => {
  for (const id of PROVIDER_IDS) {
    const provider = getProvider(id)!;
    const url = new URL(provider.authorizeUrl);
    assert.equal(url.protocol, 'https:', id);
    assert.ok(url.hostname.length > 0, id);
  }
});

test('buildAuthorizeUrl carries PKCE, state and the exact redirect', () => {
  const url = new URL(buildAuthorizeUrl('google', {
    clientId: 'client-id.apps.googleusercontent.com',
    redirectUri: 'https://auth.flaxia.app/api/connections/google/callback',
    state: 'state-value',
    codeChallenge: 'challenge-value',
    scopes: [
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/gmail.readonly',
    ],
    extra: { access_type: 'offline', prompt: 'consent' },
  }));
  assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('client_id'), 'client-id.apps.googleusercontent.com');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://auth.flaxia.app/api/connections/google/callback');
  assert.equal(url.searchParams.get('state'), 'state-value');
  assert.equal(url.searchParams.get('code_challenge'), 'challenge-value');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(
    url.searchParams.get('scope'),
    'https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/gmail.readonly',
  );
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('prompt'), 'consent');
  // The challenge must never travel in the query as a secret.
  assert.ok(!url.search.includes('code_verifier'));
});

test('buildAuthorizeUrl keeps provider specific extras separate', () => {
  const url = new URL(buildAuthorizeUrl('x', {
    clientId: 'x-client',
    redirectUri: 'https://auth.flaxia.app/api/connections/x/callback',
    state: 's',
    codeChallenge: 'c',
    scopes: ['tweet.read'],
  }));
  assert.equal(url.origin + url.pathname, 'https://x.com/i/oauth2/authorize');
  assert.equal(url.searchParams.get('scope'), 'tweet.read');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
});

test('buildAuthorizeUrl uses the scope separator of the provider', () => {
  const url = new URL(buildAuthorizeUrl('slack', {
    clientId: 'slack-client',
    redirectUri: 'https://auth.flaxia.app/api/connections/slack/callback',
    state: 's',
    codeChallenge: 'c',
    scopes: ['channels:read', 'chat:write'],
  }));
  assert.equal(url.searchParams.get('scope'), 'channels:read,chat:write');
});

test('buildAuthorizeUrl refuses a redirect that is not the Auth origin', () => {
  assert.throws(
    () => buildAuthorizeUrl('google', {
      clientId: 'c',
      redirectUri: 'https://evil.example/callback',
      state: 's',
      codeChallenge: 'c',
      scopes: ['a'],
    }),
    /redirect/i,
  );
});
