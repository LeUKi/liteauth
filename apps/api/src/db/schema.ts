import { sql } from 'drizzle-orm';
import { check, index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';

const timestamp = (name: string) => integer(name, { mode: 'timestamp_ms' });
const boolean = (name: string) => integer(name, { mode: 'boolean' });
// Better Auth serializes SQLite arrays/JSON. Drizzle must not serialize them a second time.
const array = (name: string) => text(name).$type<string[]>();

export const user = sqliteTable('user', {
  id: text('id').primaryKey(), name: text('name').notNull(), email: text('email').notNull().unique(),
  emailVerified: boolean('email_verified').notNull().default(false), image: text('image'),
  createdAt: timestamp('created_at').notNull(), updatedAt: timestamp('updated_at').notNull(),
  linuxdoId: integer('linuxdo_id').notNull().unique(), username: text('username').notNull(),
  isAdmin: boolean('is_admin').notNull().default(false), disabled: boolean('disabled').notNull().default(false),
  credentialEpoch: integer('credential_epoch').notNull().default(0),
  credentialRevision: integer('credential_revision').notNull().default(0),
  lastAuthenticatedAt: timestamp('last_authenticated_at'), lastLoginMethod: text('last_login_method'), lastTrustLevel: integer('last_trust_level'),
  officialVerifiedAt: timestamp('official_verified_at'),
});

export const session = sqliteTable('session', {
  id: text('id').primaryKey(), token: text('token').notNull().unique(), userId: text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  expiresAt: timestamp('expires_at').notNull(), createdAt: timestamp('created_at').notNull(), updatedAt: timestamp('updated_at').notNull(),
  ipAddress: text('ip_address'), userAgent: text('user_agent'), authEventId: text('auth_event_id').notNull(),
}, (table) => [index('session_user_idx').on(table.userId), index('session_auth_event_idx').on(table.authEventId)]);

export const account = sqliteTable('account', {
  id: text('id').primaryKey(), accountId: text('account_id').notNull(), providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  accessToken: text('access_token'), refreshToken: text('refresh_token'), idToken: text('id_token'),
  accessTokenExpiresAt: timestamp('access_token_expires_at'), refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
  scope: text('scope'), password: text('password'), createdAt: timestamp('created_at').notNull(), updatedAt: timestamp('updated_at').notNull(),
});

export const verification = sqliteTable('verification', {
  id: text('id').primaryKey(), identifier: text('identifier').notNull(), value: text('value').notNull(),
  expiresAt: timestamp('expires_at').notNull(), createdAt: timestamp('created_at').notNull(), updatedAt: timestamp('updated_at').notNull(),
}, (table) => [index('verification_identifier_idx').on(table.identifier)]);

export const jwks = sqliteTable('jwks', {
  id: text('id').primaryKey(), publicKey: text('public_key').notNull(), privateKey: text('private_key').notNull(),
  createdAt: timestamp('created_at').notNull(), expiresAt: timestamp('expires_at'), alg: text('alg'), crv: text('crv'),
});

export const oauthClient = sqliteTable('oauth_client', {
  id: text('id').primaryKey(), clientId: text('client_id').notNull().unique(), clientSecret: text('client_secret'),
  secretCiphertext: text('secret_ciphertext'),
  clientDiscoveryId: text('client_discovery_id'), disabled: boolean('disabled').default(false), skipConsent: boolean('skip_consent'),
  enableEndSession: boolean('enable_end_session'), subjectType: text('subject_type'), scopes: array('scopes'),
  clientCredentialsScopes: array('client_credentials_scopes').default([]), userId: text('user_id').references(() => user.id),
  createdAt: timestamp('created_at'), updatedAt: timestamp('updated_at'), name: text('name'), uri: text('uri'), icon: text('icon'),
  contacts: array('contacts'), tos: text('tos'), policy: text('policy'), softwareId: text('software_id'), softwareVersion: text('software_version'),
  softwareStatement: text('software_statement'), redirectUris: array('redirect_uris').notNull(), postLogoutRedirectUris: array('post_logout_redirect_uris'),
  backchannelLogoutUri: text('backchannel_logout_uri'), backchannelLogoutSessionRequired: boolean('backchannel_logout_session_required'),
  tokenEndpointAuthMethod: text('token_endpoint_auth_method'), applicationType: text('application_type'), jwks: text('jwks'), jwksUri: text('jwks_uri'),
  grantTypes: array('grant_types'), responseTypes: array('response_types'), requirePKCE: boolean('require_pkce'),
  dpopBoundAccessTokens: boolean('dpop_bound_access_tokens').default(false), referenceId: text('reference_id'), metadata: text('metadata').$type<Record<string, unknown>>(),
});

export const oauthRefreshToken = sqliteTable('oauth_refresh_token', {
  id: text('id').primaryKey(), token: text('token').notNull().unique(), clientId: text('client_id').notNull().references(() => oauthClient.clientId),
  sessionId: text('session_id').references(() => session.id, { onDelete: 'set null' }), userId: text('user_id').notNull().references(() => user.id),
  referenceId: text('reference_id'), authorizationCodeId: text('authorization_code_id'), resources: array('resources'), requestedUserInfoClaims: array('requested_user_info_claims'),
  expiresAt: timestamp('expires_at').notNull(), createdAt: timestamp('created_at').notNull(), revoked: timestamp('revoked'), rotatedAt: timestamp('rotated_at'),
  rotationReplayResponse: text('rotation_replay_response'), rotationReplayExpiresAt: timestamp('rotation_replay_expires_at'), authTime: timestamp('auth_time'),
  confirmation: text('confirmation'), scopes: array('scopes').notNull(),
});

export const oauthAccessToken = sqliteTable('oauth_access_token', {
  id: text('id').primaryKey(), token: text('token').notNull().unique(), clientId: text('client_id').notNull().references(() => oauthClient.clientId),
  sessionId: text('session_id').references(() => session.id, { onDelete: 'set null' }), userId: text('user_id').references(() => user.id),
  referenceId: text('reference_id'), authorizationCodeId: text('authorization_code_id'), resources: array('resources'), requestedUserInfoClaims: array('requested_user_info_claims'),
  refreshId: text('refresh_id').references(() => oauthRefreshToken.id), expiresAt: timestamp('expires_at').notNull(), createdAt: timestamp('created_at').notNull(),
  revoked: timestamp('revoked'), confirmation: text('confirmation'), scopes: array('scopes').notNull(),
}, (table) => [index('access_token_code_idx').on(table.authorizationCodeId), index('access_token_reference_idx').on(table.referenceId)]);

export const oauthConsent = sqliteTable('oauth_consent', {
  id: text('id').primaryKey(), clientId: text('client_id').notNull().references(() => oauthClient.clientId),
  userId: text('user_id').references(() => user.id), referenceId: text('reference_id'), resources: array('resources'),
  requestedUserInfoClaims: array('requested_user_info_claims'), scopes: array('scopes').notNull(), createdAt: timestamp('created_at').notNull(), updatedAt: timestamp('updated_at').notNull(),
});

export const oauthResource = sqliteTable('oauth_resource', {
  id: text('id').primaryKey(), identifier: text('identifier').notNull().unique(), name: text('name').notNull(),
  accessTokenTtl: integer('access_token_ttl'), refreshTokenTtl: integer('refresh_token_ttl'), signingAlgorithm: text('signing_algorithm'), signingKeyId: text('signing_key_id'),
  allowedScopes: array('allowed_scopes'), customClaims: text('custom_claims'), dpopBoundAccessTokensRequired: boolean('dpop_bound_access_tokens_required').default(false),
  disabled: boolean('disabled').default(false), createdAt: timestamp('created_at'), updatedAt: timestamp('updated_at'), policyVersion: integer('policy_version').default(1), metadata: text('metadata'),
});
export const oauthClientResource = sqliteTable('oauth_client_resource', {
  id: text('id').primaryKey(), clientId: text('client_id').notNull().references(() => oauthClient.clientId), resourceId: text('resource_id').notNull().references(() => oauthResource.identifier),
  metadata: text('metadata'), createdAt: timestamp('created_at'),
}, (table) => [uniqueIndex('client_resource_unique').on(table.clientId, table.resourceId)]);
export const oauthClientAssertion = sqliteTable('oauth_client_assertion', { id: text('id').primaryKey(), expiresAt: timestamp('expires_at').notNull() });

export const appSettings = sqliteTable('app_settings', {
  clientId: text('client_id').primaryKey().references(() => oauthClient.clientId), liteOnly: boolean('lite_only').notNull().default(false),
  minTrustLevel: integer('min_trust_level').notNull().default(0),
  deletedAt: timestamp('deleted_at'),
}, (table) => [check('app_min_trust_level_range', sql`${table.minTrustLevel} BETWEEN 0 AND 4`)]);

export const authEvent = sqliteTable('auth_event', {
  id: text('id').primaryKey(), userId: text('user_id').notNull().references(() => user.id), loginMethod: text('login_method').notNull(),
  upstreamClientId: text('upstream_client_id').notNull(), credentialVersion: integer('credential_version'), profile: text('profile').notNull(),
  trustLevel: integer('trust_level'),
  createdAt: timestamp('created_at').notNull(), revokedAt: timestamp('revoked_at'),
});

export const upstreamCredential = sqliteTable('upstream_credential', {
  clientId: text('client_id').primaryKey(), ownerUserId: text('owner_user_id').references(() => user.id), kind: text('kind').notNull().default('self'),
  ciphertext: text('ciphertext'), version: integer('version').notNull().default(1), status: text('status').notNull().default('active'),
  createdAt: timestamp('created_at').notNull(), updatedAt: timestamp('updated_at').notNull(),
}, (table) => [uniqueIndex('one_active_credential_per_user').on(table.ownerUserId).where(sql`${table.status} = 'active' AND ${table.kind} = 'self'`)]);

export const authorizationRequest = sqliteTable('authorization_request', {
  id: text('id').primaryKey(), clientId: text('client_id').notNull(), signedQuery: text('signed_query').notNull(), browserHash: text('browser_hash').notNull(),
  authEventId: text('auth_event_id'), stage: text('stage').notNull(), status: text('status').notNull().default('pending'),
  createdAt: timestamp('created_at').notNull(), expiresAt: timestamp('expires_at').notNull(),
}, (table) => [index('request_auth_event_idx').on(table.authEventId), index('request_client_idx').on(table.clientId)]);

export const connectTransaction = sqliteTable('connect_transaction', {
  id: text('id').primaryKey(), stateHash: text('state_hash').notNull().unique(), browserHash: text('browser_hash').notNull(),
  requestId: text('request_id'), method: text('method').notNull(), clientId: text('client_id').notNull(), encryptedPayload: text('encrypted_payload'),
  expectedUserId: text('expected_user_id'), expectedLinuxdoId: integer('expected_linuxdo_id'), expectedUsername: text('expected_username'),
  credentialEpoch: integer('credential_epoch'), credentialVersion: integer('credential_version'), candidate: boolean('candidate').notNull().default(false),
  startedCredentialRevision: integer('started_credential_revision'),
  status: text('status').notNull().default('pending'), createdAt: timestamp('created_at').notNull(), expiresAt: timestamp('expires_at').notNull(),
}, (table) => [index('connect_transaction_request_idx').on(table.requestId)]);

export const grantLedger = sqliteTable('grant_ledger', {
  codeId: text('code_id').primaryKey(), clientId: text('client_id').notNull(), authEventId: text('auth_event_id').notNull(),
  requestId: text('request_id'),
  state: text('state').notNull().default('pending'), tokenId: text('token_id'), createdAt: timestamp('created_at').notNull(), expiresAt: timestamp('expires_at').notNull(),
}, (table) => [index('grant_auth_event_idx').on(table.authEventId), index('grant_client_idx').on(table.clientId)]);
export const audit = sqliteTable('audit', {
  id: text('id').primaryKey(), action: text('action').notNull(), actorId: text('actor_id'), targetId: text('target_id'), createdAt: timestamp('created_at').notNull(),
  actorType: text('actor_type').notNull().default('unknown'), actorLinuxdoId: integer('actor_linuxdo_id'), actorUsername: text('actor_username'), actorName: text('actor_name'),
  targetType: text('target_type'), targetName: text('target_name'), clientId: text('client_id'), appName: text('app_name'),
  loginMethod: text('login_method'), trustLevel: integer('trust_level'), result: text('result').notNull().default('success'),
  reason: text('reason'), requestId: text('request_id'), changes: text('changes'), eventKey: text('event_key'),
  subjectUserId: text('subject_user_id'), subjectLinuxdoId: integer('subject_linuxdo_id'), subjectUsername: text('subject_username'),
  upstreamClientId: text('upstream_client_id'), connectTransactionId: text('connect_transaction_id'),
  identityConfirmed: boolean('identity_confirmed').notNull().default(false), verificationPurpose: text('verification_purpose'),
}, (table) => [uniqueIndex('audit_event_key_unique').on(table.eventKey), index('audit_time_idx').on(table.createdAt, table.id), index('audit_client_time_idx').on(table.clientId, table.createdAt, table.id), index('audit_actor_time_idx').on(table.actorId, table.createdAt, table.id), index('audit_subject_time_idx').on(table.subjectUserId, table.createdAt, table.id), index('audit_upstream_time_idx').on(table.upstreamClientId, table.createdAt, table.id)]);
export const credentialClock = sqliteTable('credential_clock', {
  id: integer('id').primaryKey(), revision: integer('revision').notNull().default(0),
}, (table) => [check('credential_clock_singleton', sql`${table.id} = 1`)]);
export const rateLimit = sqliteTable('rate_limit', { key: text('key').primaryKey(), count: integer('count').notNull(), expiresAt: timestamp('expires_at').notNull() });
export const mutationGuard = sqliteTable('mutation_guard', { id: text('id').primaryKey(), ok: integer('ok').notNull() }, (table) => [check('mutation_guard_ok', sql`${table.ok} = 1`)]);
