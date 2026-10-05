import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { createAppSecretCapture, decryptAppSecret } from '../src/app-secrets';
import { hash } from '../src/crypto';

const nativeHash = async (value: string) => (await hash(value)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

describe('downstream secret encryption capture', () => {
  it('keeps concurrent generated secrets bound to the matching provider hash', async () => {
    const capture = createAppSecretCapture(env);
    const first = capture.generateClientSecret();
    const second = capture.generateClientSecret();
    const [firstHash, secondHash] = await Promise.all([nativeHash(first), nativeHash(second)]);
    const [secondEnvelope, firstEnvelope] = await Promise.all([
      capture.seal('second-client', secondHash), capture.seal('first-client', firstHash),
    ]);
    expect(firstEnvelope).not.toContain(first);
    expect(secondEnvelope).not.toContain(second);
    expect(await decryptAppSecret(env, 'first-client', firstHash, firstEnvelope)).toBe(first);
    expect(await decryptAppSecret(env, 'second-client', secondHash, secondEnvelope)).toBe(second);
    await expect(capture.seal('first-client', firstHash)).rejects.toThrow('not captured');
  });

  it('fails closed when the native hash has no matching generated plaintext', async () => {
    const capture = createAppSecretCapture(env);
    capture.generateClientSecret();
    await expect(capture.seal('client', await nativeHash('unknown-secret'))).rejects.toThrow('not captured');
  });

  it('rejects an encrypted copy moved to another client or another native hash', async () => {
    const capture = createAppSecretCapture(env);
    const secret = capture.generateClientSecret();
    const digest = await nativeHash(secret);
    const envelope = await capture.seal('client', digest);
    await expect(decryptAppSecret(env, 'other-client', digest, envelope)).rejects.toThrow();
    await expect(decryptAppSecret(env, 'client', await nativeHash('other-secret'), envelope)).rejects.toThrow();
    await expect(decryptAppSecret(env, 'client', digest, '{}')).rejects.toThrow();
  });
});
