import { describe, expect, it } from 'vitest';
import { base64, decryptSecret, encryptSecret, hash, randomId, unbase64, type EncryptedSecret } from '../src/crypto';

const key = base64(Uint8Array.from({ length: 32 }, (_, index) => index));
const otherKey = base64(Uint8Array.from({ length: 32 }, (_, index) => index + 1));
const context = 'credential:fixture-record:version:1';
const secret = '\uFEFFconnect-secret-中文-🔐\u0000\n';

describe('credential encryption', () => {
  it('round-trips an exact secret through a serializable versioned envelope', async () => {
    const envelope = await encryptSecret(secret, key, context);
    expect(envelope.key_version).toBe(1);
    expect(unbase64(envelope.iv)).toHaveLength(12);
    expect(await decryptSecret(JSON.parse(JSON.stringify(envelope)) as EncryptedSecret, key, context)).toBe(secret);
  });

  it('uses a fresh IV for repeated encryption', async () => {
    const first = await encryptSecret(secret, key, context);
    const second = await encryptSecret(secret, key, context);
    expect(first.iv).not.toBe(second.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(await decryptSecret(second, key, context)).toBe(secret);
  });

  it.each([
    'credential:another-record:version:1',
    'credential:fixture-record:version:2',
    ` ${context}`,
  ])('rejects ciphertext moved to a different context: %s', async (changedContext) => {
    const envelope = await encryptSecret(secret, key, context);
    await expect(decryptSecret(envelope, key, changedContext)).rejects.toThrow();
  });

  it('rejects a different valid encryption key', async () => {
    const envelope = await encryptSecret(secret, key, context);
    await expect(decryptSecret(envelope, otherKey, context)).rejects.toThrow();
  });

  it.each(['ciphertext', 'iv'] as const)('rejects a changed %s', async (field) => {
    const envelope = await encryptSecret(secret, key, context);
    const changed = unbase64(envelope[field]);
    changed[0] ^= 1;
    await expect(decryptSecret({ ...envelope, [field]: base64(changed) }, key, context)).rejects.toThrow();
  });

  it.each([0, 2, '1', undefined])('rejects unsupported key version %s', async (version) => {
    const envelope = await encryptSecret(secret, key, context);
    await expect(decryptSecret({ ...envelope, key_version: version } as EncryptedSecret, key, context)).rejects.toThrow('Unsupported encrypted secret key version');
  });

  it.each([0, 16, 24, 31, 33])('rejects %s-byte keys on both paths', async (length) => {
    const invalidKey = base64(new Uint8Array(length));
    const envelope = await encryptSecret(secret, key, context);
    await expect(encryptSecret(secret, invalidKey, context)).rejects.toThrow();
    await expect(decryptSecret(envelope, invalidKey, context)).rejects.toThrow();
  });

  it.each(['invalid!', `${key}\n`, key.slice(0, -1), base64(new Uint8Array(32).fill(255)).replaceAll('/', '_')])('rejects malformed or noncanonical key encoding', async (invalidKey) => {
    const envelope = await encryptSecret(secret, key, context);
    await expect(encryptSecret(secret, invalidKey, context)).rejects.toThrow();
    await expect(decryptSecret(envelope, invalidKey, context)).rejects.toThrow();
  });

  it.each(['', ' ', '\t\n'])('requires a nonblank context on both paths', async (invalidContext) => {
    const envelope = await encryptSecret(secret, key, context);
    await expect(encryptSecret(secret, key, invalidContext)).rejects.toThrow('nonblank context');
    await expect(decryptSecret(envelope, key, invalidContext)).rejects.toThrow('nonblank context');
  });

  it.each([
    { iv: base64(new Uint8Array(8)) },
    { iv: base64(new Uint8Array(16)) },
    { iv: 'invalid!' },
    { ciphertext: base64(new Uint8Array(15)) },
    { ciphertext: 'invalid!' },
    { ciphertext: '' },
  ])('rejects an invalid encrypted envelope field', async (changes) => {
    const envelope = await encryptSecret(secret, key, context);
    await expect(decryptSecret({ ...envelope, ...changes }, key, context)).rejects.toThrow();
  });

  it('rejects missing envelopes instead of coercing them', async () => {
    await expect(decryptSecret(null as unknown as EncryptedSecret, key, context)).rejects.toThrow('Invalid encrypted secret envelope');
  });
});

describe('shared crypto helpers', () => {
  it('preserves standard base64 including all byte values', () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
    expect(unbase64(base64(bytes))).toEqual(bytes);
  });

  it('keeps SHA-256 hashes compatible with the adapter token identifiers', async () => {
    expect(await hash('abc')).toBe('ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=');
  });

  it('preserves the random identifier prefix', () => {
    expect(randomId('fixture_')).toMatch(/^fixture_[0-9a-f]{32}$/);
  });
});
