import assert from 'node:assert/strict';
import { test } from 'node:test';
import { openSealed, sealTo } from '../src/oauth/seal.ts';

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const unb64 = (value: string) => new Uint8Array(Buffer.from(value, 'base64'));

test('a sealed payload opens only with the matching private key', async () => {
  const client = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = b64(new Uint8Array(await crypto.subtle.exportKey('spki', client.publicKey)));
  const secret = new TextEncoder().encode('{"access_token":"secret-token"}');

  const sealed = await sealTo(secret, publicKey);
  assert.notEqual(sealed.ciphertext, b64(secret));
  assert.ok(!sealed.ciphertext.includes('secret-token'));
  assert.ok(!JSON.stringify(sealed).includes('secret-token'));

  const opened = await openSealed(sealed, client.privateKey);
  assert.deepEqual(Array.from(opened), Array.from(secret));
});

test('sealing is not deterministic, so equal payloads differ on the wire', async () => {
  const client = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = b64(new Uint8Array(await crypto.subtle.exportKey('spki', client.publicKey)));
  const secret = new TextEncoder().encode('same input');
  const first = await sealTo(secret, publicKey);
  const second = await sealTo(secret, publicKey);
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert.notEqual(first.iv, second.iv);
  assert.deepEqual(
    Array.from(await openSealed(first, client.privateKey)),
    Array.from(await openSealed(second, client.privateKey)),
  );
});

test('a different private key cannot open the payload', async () => {
  const client = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const other = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = b64(new Uint8Array(await crypto.subtle.exportKey('spki', client.publicKey)));
  const sealed = await sealTo(new TextEncoder().encode('private'), publicKey);
  await assert.rejects(() => openSealed(sealed, other.privateKey));
});

test('tampered ciphertext fails authentication instead of returning garbage', async () => {
  const client = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = b64(new Uint8Array(await crypto.subtle.exportKey('spki', client.publicKey)));
  const sealed = await sealTo(new TextEncoder().encode('tamper me'), publicKey);
  const bytes = unb64(sealed.ciphertext);
  bytes[0] ^= 0xff;
  await assert.rejects(() => openSealed({ ...sealed, ciphertext: b64(bytes) }, client.privateKey));
});

test('a malformed envelope is rejected before any crypto runs', async () => {
  const client = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const valid = {
    ephemeralPublicKey: b64(new Uint8Array(32)),
    iv: b64(new Uint8Array(12)),
    ciphertext: b64(new Uint8Array(32)),
  };
  for (const broken of [
    { ...valid, ephemeralPublicKey: 'not base64!!' },
    { ...valid, iv: b64(new Uint8Array(3)) },
    { ...valid, ciphertext: '' },
    { ...valid, ephemeralPublicKey: '' },
  ]) {
    await assert.rejects(() => openSealed(broken, client.privateKey));
  }
});

test('sealing refuses a public key that is not a P-256 point', async () => {
  await assert.rejects(() => sealTo(new TextEncoder().encode('x'), 'not-a-key'));
  await assert.rejects(() => sealTo(new TextEncoder().encode('x'), b64(new Uint8Array(31))));
});
