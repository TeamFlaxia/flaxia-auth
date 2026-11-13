// Sealing an OAuth token to a client public key.
//
// Some providers refuse a cross-origin token request, so Auth has to perform
// the code exchange itself. That would normally make Auth the custodian of
// the token, which the application design forbids: a server-held key was
// deleted once already and must not come back.
//
// Instead Auth seals the result to an ephemeral ECDH key derived from the
// client's public key. The browser holds the private half and opens the
// envelope. Auth sees the plaintext exactly once, in memory, and stores
// nothing it could read again.
//
//   client public key ─┐
//                      ├─ECDH P-256─► shared secret ─HKDF─► AES-GCM key
//   ephemeral public ──┘                                   │
//                                       sealed box = {epk, iv, ciphertext}
//
// The envelope carries the ephemeral public key, so the reader can derive the
// same shared secret. The ciphertext is bound to the envelope by the GCM tag,
// so a swapped or edited envelope fails to open instead of yielding garbage.

const CURVE = 'ECDH';
const NAMED_CURVE = 'P-256';
const IV_LENGTH = 12;
const KEY_LENGTH = 256;
const HKDF_INFO = 'flaxia.oauth.seal.v1';

export interface SealedEnvelope {
  /** SPKI of the ephemeral public key, base64. */
  ephemeralPublicKey: string;
  /** AES-GCM nonce, base64. */
  iv: string;
  /** Ciphertext with the GCM tag, base64. */
  ciphertext: string;
}

// Standard base64, matching the encoding the Vault primitives already use.
const encode = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));

const decode = (value: string): Uint8Array =>
  Uint8Array.from(atob(value), character => character.charCodeAt(0));

const isBase64 = (value: unknown, expectedLength?: number): value is string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  let bytes: Uint8Array;
  try {
    bytes = decode(value);
  } catch {
    return false;
  }
  return expectedLength === undefined ? bytes.length > 0 : bytes.length === expectedLength;
};

/** Derive the AES-GCM key from an ECDH shared secret. */
async function deriveKey(sharedSecret: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', sharedSecret as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(HKDF_INFO) },
    material,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt'],
  );
}

// The Cloudflare type definitions do not describe the ECDH derive parameters,
// so the algorithm object is stated explicitly here.
interface EcdhDeriveParams {
  name: 'ECDH';
  public: CryptoKey;
}

async function sharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  const algorithm: EcdhDeriveParams = { name: 'ECDH', public: publicKey };
  const bits = await crypto.subtle.deriveBits(
    algorithm as unknown as SubtleCryptoDeriveKeyAlgorithm,
    privateKey,
    KEY_LENGTH,
  );
  return new Uint8Array(bits);
}

/**
 * Seal a payload to a client's public key. The public key is an SPKI
 * base64url string, as exported by the browser.
 */
export async function sealTo(payload: Uint8Array, clientPublicKey: string): Promise<SealedEnvelope> {
  if (!isBase64(clientPublicKey)) throw new Error('Invalid client public key');
  let clientKey: CryptoKey;
  try {
    clientKey = await crypto.subtle.importKey(
      'spki',
      decode(clientPublicKey) as BufferSource,
      { name: CURVE, namedCurve: NAMED_CURVE },
      false,
      [],
    );
  } catch {
    throw new Error('Invalid client public key');
  }
  const ephemeral = (await crypto.subtle.generateKey(
    { name: CURVE, namedCurve: NAMED_CURVE },
    true,
    ['deriveBits'],
  )) as CryptoKeyPair;
  const key = await deriveKey(await sharedSecret(ephemeral.privateKey, clientKey));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, payload as BufferSource),
  );
  const exported = await crypto.subtle.exportKey('spki', ephemeral.publicKey);
  const ephemeralPublicKey = new Uint8Array(exported as ArrayBuffer);
  return {
    ephemeralPublicKey: encode(ephemeralPublicKey),
    iv: encode(iv),
    ciphertext: encode(ciphertext),
  };
}

/**
 * Open a sealed envelope with the client's private key. Any tampering with
 * the envelope fails the GCM tag check and throws.
 */
export async function openSealed(envelope: SealedEnvelope, privateKey: CryptoKey): Promise<Uint8Array> {
  if (!envelope || typeof envelope !== 'object') throw new Error('Invalid sealed envelope');
  const { ephemeralPublicKey, iv, ciphertext } = envelope as Partial<SealedEnvelope>;
  if (!isBase64(ephemeralPublicKey) || !isBase64(iv, IV_LENGTH) || !isBase64(ciphertext)) {
    throw new Error('Invalid sealed envelope');
  }
  let ephemeralKey: CryptoKey;
  try {
    ephemeralKey = await crypto.subtle.importKey(
      'spki',
      decode(ephemeralPublicKey) as BufferSource,
      { name: CURVE, namedCurve: NAMED_CURVE },
      false,
      [],
    );
  } catch {
    throw new Error('Invalid sealed envelope');
  }
  const key = await deriveKey(await sharedSecret(privateKey, ephemeralKey));
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: decode(iv) as BufferSource },
    key,
    decode(ciphertext) as BufferSource,
  );
  return new Uint8Array(plaintext);
}
