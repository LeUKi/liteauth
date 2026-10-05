const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export type EncryptedSecret = {
  ciphertext: string;
  iv: string;
  key_version: 1;
};

export function randomId(prefix = ''): string {
  return prefix + crypto.randomUUID().replaceAll('-', '');
}

export function base64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function unbase64(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !value) throw new TypeError('Invalid base64 value');
  const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  if (base64(bytes) !== value) throw new TypeError('Invalid base64 value');
  return bytes;
}

export async function hash(value: string): Promise<string> {
  return base64(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}

async function credentialKey(keyBase64: string, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const bytes = unbase64(keyBase64);
  if (bytes.byteLength !== 32) throw new TypeError('Credential encryption key must contain 32 bytes');
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, [usage]);
}

function additionalData(context: string): Uint8Array {
  if (typeof context !== 'string' || !context.trim()) {
    throw new TypeError('Credential encryption requires a nonblank context');
  }
  return encoder.encode(context);
}

export async function encryptSecret(secret: string, keyBase64: string, context: string): Promise<EncryptedSecret> {
  if (typeof secret !== 'string') throw new TypeError('Credential secret must be a string');
  const aad = additionalData(context);
  const key = await credentialKey(keyBase64, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    encoder.encode(secret),
  );
  return { ciphertext: base64(new Uint8Array(ciphertext)), iv: base64(iv), key_version: 1 };
}

export async function decryptSecret(envelope: EncryptedSecret, keyBase64: string, context: string): Promise<string> {
  if (!envelope || typeof envelope !== 'object') throw new TypeError('Invalid encrypted secret envelope');
  if (envelope.key_version !== 1) throw new Error('Unsupported encrypted secret key version');
  const aad = additionalData(context);
  const iv = unbase64(envelope.iv);
  const ciphertext = unbase64(envelope.ciphertext);
  if (iv.byteLength !== 12) throw new TypeError('Credential encryption IV must contain 12 bytes');
  if (ciphertext.byteLength < 16) throw new TypeError('Invalid encrypted secret ciphertext');
  const key = await credentialKey(keyBase64, 'decrypt');
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    ciphertext,
  );
  return decoder.decode(decrypted);
}
