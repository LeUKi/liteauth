import { decryptSecret, encryptSecret, type EncryptedSecret } from './crypto';
import type { Env } from './env';

export async function seal(env: Env, value: unknown, context: string) {
  return JSON.stringify(await encryptSecret(JSON.stringify(value), env.CREDENTIAL_ENCRYPTION_KEY, context));
}

export async function open<T>(env: Env, ciphertext: string, context: string): Promise<T> {
  const plaintext = await decryptSecret(JSON.parse(ciphertext) as EncryptedSecret, env.CREDENTIAL_ENCRYPTION_KEY, context);
  return JSON.parse(plaintext) as T;
}
