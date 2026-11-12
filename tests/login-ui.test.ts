import assert from 'node:assert/strict';
import { test } from 'node:test';
import { returnUriAllowed, RETURN_URIS } from '../src/origin.ts';

test('only known application callbacks are accepted', () => {
  for (const uri of RETURN_URIS) assert.equal(returnUriAllowed(uri), true, uri);
  for (const uri of [
    'https://evil.example/api/auth/callback',
    'https://flaxia.app.evil.example/api/auth/callback',
    'javascript:alert(1)',
    'flaxia://auth/callback/extra',
    '',
    null,
    undefined,
  ]) {
    assert.equal(returnUriAllowed(uri), false, String(uri));
  }
});
