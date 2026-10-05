export interface Env {
  DB: D1Database;
  APP_ORIGIN: string;
  ENVIRONMENT: 'development' | 'staging' | 'production';
  ADMIN_LINUXDO_ID: string;
  BETTER_AUTH_SECRET: string;
  CREDENTIAL_ENCRYPTION_KEY: string;
  CONNECT_CLIENT_ID: string;
  CONNECT_CLIENT_SECRET: string;
}

export const TRANSACTION_TTL = 10 * 60_000;
export const SESSION_TTL = 7 * 24 * 60 * 60;
export function isConfiguredAdmin(env: Pick<Env, 'ADMIN_LINUXDO_ID'>, linuxdoId: number): boolean {
  const configured = env.ADMIN_LINUXDO_ID;
  return typeof configured === 'string' && /^[1-9]\d*$/.test(configured)
    && Number.isSafeInteger(Number(configured)) && Number(configured) === linuxdoId;
}
export const cookieName = (env: Env, suffix: string) => `${env.APP_ORIGIN.startsWith('https:') ? '__Host-' : ''}liteauth.${suffix}`;
