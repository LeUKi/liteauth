import { generateRandomString } from 'better-auth/crypto';
import { decryptSecret, encryptSecret, hash, type EncryptedSecret } from './crypto';
import type { Env } from './env';

type EncryptionEnv = Pick<Env, 'CREDENTIAL_ENCRYPTION_KEY'>;

function context(clientId: string, nativeHash: string): string {
  if (!clientId || !nativeHash) throw new TypeError('Client secret encryption requires its client and hash');
  return JSON.stringify(['liteauth', 'downstream-client-secret', clientId, nativeHash]);
}

/** Matches OAuth Provider 1.7.7's native hashed-secret representation. */
async function nativeSecretHash(secret: string): Promise<string> {
  return (await hash(secret)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export type AppSecretCapture = {
  generateClientSecret: () => string;
  seal: (clientId: string, nativeHash: string) => Promise<string>;
};

/** One capture belongs to one auth instance, so concurrent requests never share plaintext. */
export function createAppSecretCapture(env: EncryptionEnv): AppSecretCapture {
  const generated = new Map<string, Promise<string>>();
  return {
    generateClientSecret() {
      const secret = generateRandomString(32, 'a-z', 'A-Z');
      generated.set(secret, nativeSecretHash(secret));
      return secret;
    },
    async seal(clientId, nativeHash) {
      for (const [secret, digest] of generated) {
        if (await digest !== nativeHash) continue;
        if (!generated.delete(secret)) continue;
        return JSON.stringify(await encryptSecret(secret, env.CREDENTIAL_ENCRYPTION_KEY, context(clientId, nativeHash)));
      }
      throw new Error('Generated client secret was not captured');
    },
  };
}

export async function decryptAppSecret(env: EncryptionEnv, clientId: string, nativeHash: string, envelopeJson: string): Promise<string> {
  const secret = await decryptSecret(JSON.parse(envelopeJson) as EncryptedSecret, env.CREDENTIAL_ENCRYPTION_KEY, context(clientId, nativeHash));
  if (await nativeSecretHash(secret) !== nativeHash) throw new Error('Stored client secret does not match its native hash');
  return secret;
}
