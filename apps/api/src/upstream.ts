import * as client from 'openid-client';
import { z } from 'zod';
import { HttpError, invariant } from './errors';

const issuer = 'https://connect.linux.do';
const authorizationEndpoint = `${issuer}/oauth2/authorize`;
const tokenEndpoint = `${issuer}/oauth2/token`;
const profileEndpoint = new URL(`${issuer}/api/user`);

export const connectProfileSchema = z.object({
  id: z.number().int().positive(),
  username: z.string().min(1).refine((value) => Boolean(value.trim()), 'Invalid Connect username'),
  name: z.string().nullable().optional(),
  avatar_url: z.string().nullable().optional(),
  trust_level: z.number().int().min(0).max(4),
  active: z.boolean(),
  silenced: z.boolean(),
}).transform((profile) => ({
  ...profile,
  name: profile.name || profile.username,
  avatar_url: profile.avatar_url ?? null,
}));
export type ConnectProfile = z.infer<typeof connectProfileSchema>;

function configuration(clientId: string, secret: string): client.Configuration {
  invariant(typeof clientId === 'string' && Boolean(clientId.trim()) && typeof secret === 'string' && secret.length > 0,
    400, 'invalid_connect_credentials', '请完整填写 Connect 密钥');
  const config = new client.Configuration({
    issuer,
    authorization_endpoint: authorizationEndpoint,
    token_endpoint: tokenEndpoint,
  }, clientId, secret, client.ClientSecretPost(secret));
  config.timeout = 15;
  return config;
}

function callback(url: string): URL {
  let parsed: URL;
  try { parsed = new URL(url); } catch {
    throw new HttpError(400, 'invalid_connect_callback', '登录回调地址无效');
  }
  invariant(!parsed.username && !parsed.password && !parsed.search && !parsed.hash &&
    (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname))),
  400, 'invalid_connect_callback', '登录回调地址无效');
  return parsed;
}

export async function startUpstream(clientId: string, secret: string, callbackUrl: string): Promise<{
  authorizationUrl: string;
  state: string;
  codeVerifier: string;
}> {
  const redirect = callback(callbackUrl);
  const config = configuration(clientId, secret);
  const state = client.randomState();
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: redirect.href,
    response_type: 'code',
    scope: 'user',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  }).href;
  return { authorizationUrl, state, codeVerifier };
}

export async function finishUpstream(
  clientId: string,
  secret: string,
  callbackUrl: string,
  currentCallbackUrl: string,
  state: string,
  codeVerifier: string,
): Promise<ConnectProfile> {
  const expectedCallback = callback(callbackUrl);
  let current: URL;
  try { current = new URL(currentCallbackUrl); } catch {
    throw new HttpError(400, 'invalid_connect_callback', '登录回调地址无效');
  }
  invariant(current.origin === expectedCallback.origin && current.pathname === expectedCallback.pathname &&
    !current.username && !current.password && !current.hash,
  400, 'invalid_connect_callback', '登录回调地址无效');
  invariant(typeof state === 'string' && Boolean(state.trim()) && typeof codeVerifier === 'string' &&
    /^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier),
  400, 'invalid_connect_transaction', '登录验证已失效，请重试');
  const config = configuration(clientId, secret);
  try {
    const tokens = await client.authorizationCodeGrant(config, current, {
      expectedState: state,
      pkceCodeVerifier: codeVerifier,
      idTokenExpected: false,
    });
    const response = await client.fetchProtectedResource(config, tokens.access_token, profileEndpoint, 'GET');
    if (!response.ok) throw new HttpError(502, 'connect_profile_failed', '无法获取 Linux.do 账号信息，请重试');
    const profile = connectProfileSchema.safeParse(await response.json());
    if (!profile.success) throw new HttpError(502, 'invalid_connect_profile', 'Linux.do 返回的账号信息无效');
    return profile.data;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, 'connect_login_failed', 'Linux.do 登录验证失败，请重试');
  }
}
