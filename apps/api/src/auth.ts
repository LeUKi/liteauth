import { getOAuthProviderApi, getOAuthProviderState, oauthProvider, type OAuthProviderExtension } from '@better-auth/oauth-provider';
import { APIError, betterAuth } from 'better-auth';
import { createAuthEndpoint, createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { jwt } from 'better-auth/plugins';
import { z } from 'zod';
import { policyAdapter } from './db/adapter';
import { cookieName, SESSION_TTL, type Env } from './env';
import { finishConnect } from './connect';
import { hash } from './crypto';
import { appEligibility } from './requests';
import { createAppSecretCapture } from './app-secrets';

export type EventRow = { id: string; user_id: string; login_method: string; upstream_client_id: string; trust_level: number | null; profile: string; revoked_at: number | null };
const userInfoSnapshotKey = '__liteauth_userinfo_snapshot';

function definedClaims(claims: Record<string, unknown>) {
  return Object.fromEntries(Object.entries(claims).filter(([, value]) => value !== undefined));
}

function splitDisplayName(name: unknown) {
  if (typeof name !== 'string') return {};
  const parts = name.split(' ').filter(Boolean);
  return parts.length <= 1 ? {} : { given_name: parts.slice(0, -1).join(' '), family_name: parts.at(-1) };
}

export async function eventClaims(env: Env, eventId: unknown, expectedUserId?: string) {
  if (typeof eventId !== 'string') throw new APIError('UNAUTHORIZED', { error: 'invalid_token' });
  const event = await env.DB.prepare(`SELECT e.* FROM auth_event e JOIN user u ON u.id = e.user_id
    WHERE e.id = ? AND e.revoked_at IS NULL AND u.disabled = 0`).bind(eventId).first<EventRow>();
  if (!event || (expectedUserId && event.user_id !== expectedUserId)) throw new APIError('UNAUTHORIZED', { error: 'invalid_token' });
  const profile = JSON.parse(event.profile) as Record<string, unknown>;
  return {
    id: profile.id, username: profile.username, name: profile.name, avatar_url: profile.avatar_url ?? null,
    trust_level: event.trust_level, active: profile.active, silenced: profile.silenced,
    login_method: event.login_method, auth_source: 'linuxdo', upstream_client_id: event.upstream_client_id,
    liteauth_user_id: event.user_id,
  };
}

export async function userInfoSnapshotClaims(env: Env, eventId: unknown, expectedUserId?: string, scopes?: string[], requestedClaims: string[] = []) {
  const claims = await eventClaims(env, eventId, expectedUserId);
  const requested = new Set(requestedClaims);
  const profile = scopes === undefined || scopes.includes('profile');
  const output: Record<string, unknown> = {
    id: claims.id,
    username: claims.username,
    avatar_url: claims.avatar_url ?? null,
    trust_level: claims.trust_level,
    active: claims.active,
    silenced: claims.silenced,
    login_method: claims.login_method,
    auth_source: claims.auth_source,
    upstream_client_id: claims.upstream_client_id,
    liteauth_user_id: claims.liteauth_user_id,
  };
  const addStandard = (name: string, value: unknown) => { if (profile || requested.has(name)) output[name] = value; };
  addStandard('name', claims.name ?? undefined);
  addStandard('picture', claims.avatar_url ?? undefined);
  for (const [name, value] of Object.entries(splitDisplayName(claims.name))) addStandard(name, value);
  return definedClaims(output);
}

export function userInfoSnapshotBody(body: Record<string, unknown>) {
  const snapshot = body[userInfoSnapshotKey];
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return;
  const snapshotClaims = snapshot as Record<string, unknown>;
  const next = { ...body };
  for (const [field, value] of Object.entries(snapshotClaims)) next[field] = value;
  for (const field of ['name', 'picture', 'given_name', 'family_name']) if (!(field in snapshotClaims)) delete next[field];
  delete next[userInfoSnapshotKey];
  return next;
}

export function createAuth(env: Env, flowClientId?: string, requestId?: string) {
  const appSecrets = createAppSecretCapture(env);
  const extension: OAuthProviderExtension = {
    claims: {
      accessToken: async ({ referenceId, user }) => ({ ...await eventClaims(env, referenceId, user?.id), liteauth_auth_event_id: referenceId }),
      idToken: async ({ referenceId, user }) => eventClaims(env, referenceId, user?.id),
      userInfo: async ({ jwt: claims, user }) => eventClaims(env, claims.liteauth_auth_event_id, user.id),
    },
  };
  const provider = oauthProvider({
    loginPage: '/login', consentPage: '/consent', scopes: ['openid', 'profile'], grantTypes: ['authorization_code'],
    // The provider shares this TTL with signed login/consent prompts; the D1 adapter caps actual codes at 2 minutes.
    codeExpiresIn: 600, accessTokenExpiresIn: 3600, idTokenExpiresIn: 600,
    allowDynamicClientRegistration: false, clientRegistrationDefaultScopes: ['openid', 'profile'],
    clientPrivileges: async ({ user }) => Boolean(user && !user.disabled),
    customUserInfoClaims: async ({ jwt, user, scopes, requestedClaims }) => {
      const snapshot = await userInfoSnapshotClaims(env, jwt.liteauth_auth_event_id, user.id, scopes, requestedClaims);
      return { ...snapshot, [userInfoSnapshotKey]: snapshot };
    },
    storeClientSecret: 'hashed', generateClientSecret: appSecrets.generateClientSecret, extensions: [extension],
    postLogin: {
      page: '/login',
      consentReferenceId: async ({ session, user }) => {
        await eventClaims(env, session.authEventId, user.id);
        return String(session.authEventId);
      },
      shouldRedirect: async ({ session, user }) => {
        if (user.disabled) throw new APIError('UNAUTHORIZED');
        const event = await env.DB.prepare('SELECT login_method, trust_level, revoked_at FROM auth_event WHERE id = ? AND user_id = ?')
          .bind(session.authEventId, user.id).first<{ login_method: string; trust_level: number | null; revoked_at: number | null }>();
        if (!event || event.revoked_at !== null) return true;
        if (!flowClientId) return false;
        const settings = await env.DB.prepare('SELECT lite_only, min_trust_level FROM app_settings WHERE client_id = ? AND deleted_at IS NULL')
          .bind(flowClientId).first<{ lite_only: number; min_trust_level: number }>();
        return !settings || !appEligibility(settings, event).allowed;
      },
    },
    advertisedMetadata: { claims_supported: ['sub', 'name', 'picture', 'id', 'username', 'avatar_url', 'trust_level', 'active', 'silenced', 'login_method', 'auth_source', 'upstream_client_id', 'liteauth_user_id'] },
  });

  return betterAuth({
    appName: 'LiteAuth', baseURL: env.APP_ORIGIN, basePath: '/api/auth', secret: env.BETTER_AUTH_SECRET,
    database: policyAdapter(env.DB, requestId, appSecrets), trustedOrigins: [env.APP_ORIGIN],
    logger: { disabled: true },
    emailAndPassword: { enabled: false },
    user: { additionalFields: {
      linuxdoId: { type: 'number', required: true, input: false }, username: { type: 'string', required: true, input: false },
      isAdmin: { type: 'boolean', defaultValue: false, input: false }, disabled: { type: 'boolean', defaultValue: false, input: false },
      credentialEpoch: { type: 'number', defaultValue: 0, input: false },
    } },
    session: {
      expiresIn: SESSION_TTL, disableSessionRefresh: true, cookieCache: { enabled: false },
      additionalFields: { authEventId: { type: 'string', required: true, input: false } },
    },
    advanced: {
      // Better Auth 1.7.7 otherwise prepends __Secure- even to custom __Host- names.
      // Disable only that automatic prefix; HTTPS Secure attributes remain explicit below.
      useSecureCookies: false, cookiePrefix: env.APP_ORIGIN.startsWith('https:') ? '__Host-liteauth' : 'liteauth',
      cookies: { session_token: { name: env.APP_ORIGIN.startsWith('https:') ? '__Host-liteauth.session' : 'liteauth.session', attributes: { path: '/', httpOnly: true, sameSite: 'lax', secure: env.APP_ORIGIN.startsWith('https:') } } },
      defaultCookieAttributes: { path: '/', httpOnly: true, sameSite: 'lax', secure: env.APP_ORIGIN.startsWith('https:') },
    },
    plugins: [
      jwt({ jwks: { keyPairConfig: { alg: 'RS256' } }, jwt: { issuer: `${env.APP_ORIGIN}/api/auth` } }),
      provider,
      { id: 'immutable-userinfo-snapshot', hooks: { after: [{
        matcher: (ctx) => ctx.path === '/oauth2/userinfo',
        handler: createAuthMiddleware(async (ctx) => {
          if (!ctx.context.returned || typeof ctx.context.returned !== 'object' || ctx.context.returned instanceof Response) return;
          const snapshot = userInfoSnapshotBody(ctx.context.returned as Record<string, unknown>);
          if (snapshot) return ctx.json(snapshot);
        }),
      }] } },
      { id: 'downstream-secret-display', schema: { oauthClient: { fields: {
        secretCiphertext: { type: 'string', required: false, input: false, returned: false },
      } } } },
      {
        id: 'linuxdo-connect',
        endpoints: {
          connectResume: createAuthEndpoint('/connect/resume', { method: 'POST', body: z.object({ oauth_query: z.string() }) }, async (ctx) => {
            // The provider's before-hook verifies this exact signed query; its after-hook resumes authorization.
            const state = await getOAuthProviderState();
            const session = await getSessionFromCtx(ctx);
            const browser = ctx.getCookie(cookieName(env, 'browser'));
            const issuedAt = state?.signedQueryIssuedAt?.getTime();
            if (!requestId || !flowClientId || !session || !browser || !issuedAt || new Date(session.session.createdAt).getTime() < issuedAt) {
              throw new APIError('BAD_REQUEST', { error: 'invalid_grant' });
            }
            const valid = await env.DB.prepare(`SELECT r.id FROM authorization_request r
              JOIN auth_event e ON e.id = r.auth_event_id JOIN user u ON u.id = e.user_id
              JOIN oauth_client c ON c.client_id = r.client_id JOIN app_settings a ON a.client_id = r.client_id
              WHERE r.id = ? AND r.client_id = ? AND r.signed_query = ? AND r.browser_hash = ?
              AND r.auth_event_id = ? AND r.stage = 'login' AND r.status = 'pending' AND r.expires_at > ?
              AND e.user_id = ? AND e.created_at >= ? AND e.revoked_at IS NULL AND u.disabled = 0
              AND EXISTS (SELECT 1 FROM connect_transaction t WHERE t.request_id = r.id AND t.status = 'completed'
              AND t.method = e.login_method AND t.client_id = e.upstream_client_id AND t.created_at <= e.created_at)
              AND c.disabled = 0 AND a.deleted_at IS NULL AND (a.lite_only = 0 OR e.login_method = 'lite_self_app')
              AND e.trust_level >= a.min_trust_level`)
              .bind(requestId, flowClientId, ctx.body.oauth_query, await hash(browser), session.session.authEventId,
                Date.now(), session.user.id, issuedAt).first();
            if (!valid) throw new APIError('BAD_REQUEST', { error: 'invalid_grant' });
            // Reissue the existing fresh cookie without minting a session or changing auth_time.
            await setSessionCookie(ctx, session);
            return ctx.json({ ok: true });
          }),
          connectUser: createAuthEndpoint('/connect/user', { method: 'GET' }, async (ctx) => {
            const match = /^Bearer ([^\s]+)$/i.exec(ctx.headers?.get('Authorization') ?? '');
            if (!match) throw new APIError('UNAUTHORIZED', { error: 'invalid_token' }, { 'WWW-Authenticate': 'Bearer' });
            const claims = await getOAuthProviderApi(ctx, provider.options).requireActiveAccessToken(match[1]);
            if (typeof claims.scope !== 'string' || !claims.scope.split(' ').includes('profile')) throw new APIError('FORBIDDEN', { error: 'insufficient_scope' }, { 'WWW-Authenticate': 'Bearer error="insufficient_scope", scope="profile"' });
            return ctx.json({ sub: claims.sub, ...await eventClaims(env, claims.liteauth_auth_event_id, typeof claims.sub === 'string' ? claims.sub : undefined) });
          }),
          connectCallback: createAuthEndpoint('/connect/callback', {
            method: 'GET', query: z.object({ code: z.string().optional(), state: z.string().optional(), error: z.string().optional() }),
          }, async (ctx) => {
            let redirect: string;
            try { redirect = await finishConnect(env, ctx); } catch { redirect = `${env.APP_ORIGIN}/login?error=authorization_failed`; }
            throw ctx.redirect(redirect);
          }),
        },
      },
    ],
  });
}

export type LiteAuth = ReturnType<typeof createAuth>;
export type AuthSession = NonNullable<Awaited<ReturnType<LiteAuth['api']['getSession']>>>;
