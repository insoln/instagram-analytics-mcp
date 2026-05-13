import { randomBytes } from 'node:crypto';
import type { Response } from 'express';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { buildMetaAuthorizationUrl, exchangeMetaCode, exchangeForLongLivedToken, isMetaTokenStale, refreshLongLivedToken } from './meta-oauth.js';
import { signAccessToken, verifyAccessToken } from './jwt.js';
import type { SessionStore } from '../session/store.js';
import { logger } from '../utils/logger.js';

const CODE_TTL_MS = 10 * 60 * 1000;
const STATE_TTL_MS = 10 * 60 * 1000;

const DEFAULT_SCOPES = ['instagram', 'facebook'];

// Maps MCP scopes → the minimal set of Meta (Facebook Login) permissions needed.
// 'business_management' is always included so Business Manager pages are discoverable.
const META_PERMISSIONS_BY_MCP_SCOPE: Record<string, string[]> = {
  instagram: ['pages_show_list', 'pages_read_engagement', 'instagram_basic', 'instagram_manage_insights'],
  facebook:  ['pages_show_list', 'pages_read_engagement', 'read_insights'],
};

function mapMcpScopesToMetaPermissions(mcpScopes: string[]): string[] {
  const perms = new Set<string>(['business_management']);
  for (const scope of mcpScopes) {
    for (const perm of META_PERMISSIONS_BY_MCP_SCOPE[scope] ?? []) {
      perms.add(perm);
    }
  }
  return [...perms];
}

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

interface MetaProviderOptions {
  store: SessionStore;
  metaAppId: string;
  metaAppSecret: string;
  metaCallbackUri: string;
  issuerUrl: string;
  serverAudience: string;
  jwtExpiry: string;
  refreshTokenExpirySeconds: number;
}

const MAX_REGISTERED_CLIENTS = 1_000;

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>
  ): OAuthClientInformationFull {
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: randomToken(16),
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    if (this.clients.size >= MAX_REGISTERED_CLIENTS) {
      const evictedId = this.clients.keys().next().value!;
      // Log before eviction so operators can detect capacity issues; previously-
      // registered clients may fail to re-authenticate after being evicted.
      logger.warn('OAuth client store at capacity; evicting oldest registration', {
        evictedClientId: evictedId,
        limit: MAX_REGISTERED_CLIENTS,
      });
      this.clients.delete(evictedId);
    }
    this.clients.set(full.client_id, full);
    return full;
  }
}

export class MetaOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore;
  readonly skipLocalPkceValidation = false;

  private readonly store: SessionStore;
  private readonly opts: MetaProviderOptions;

  constructor(opts: MetaProviderOptions) {
    this.opts = opts;
    this.store = opts.store;
    this.clientsStore = new InMemoryClientsStore();
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const state = randomToken();

    await this.store.setOAuthState(state, {
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      clientId: client.client_id,
      scopes: params.scopes ?? DEFAULT_SCOPES,
      resource: params.resource?.toString(),
      clientState: params.state,
      expiresAt: Date.now() + STATE_TTL_MS,
    });

    res.redirect(buildMetaAuthorizationUrl({
      appId: this.opts.metaAppId,
      redirectUri: this.opts.metaCallbackUri,
      state,
      scopes: mapMcpScopesToMetaPermissions(params.scopes ?? DEFAULT_SCOPES),
    }));
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const record = await this.store.getMcpCode(authorizationCode);
    if (!record) throw new Error('Authorization code not found or expired');
    if (record.clientId !== client.client_id) throw new Error('Authorization code was not issued to this client');
    // Defense-in-depth: reject expired codes regardless of whether the store
    // implementation enforces TTL on reads.
    if (Date.now() > record.expiresAt) throw new Error('Authorization code has expired');
    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const record = await this.store.getMcpCode(authorizationCode);
    if (!record) throw new Error('Authorization code not found or expired');
    if (record.clientId !== client.client_id) throw new Error('Authorization code was not issued to this client');
    // OAuth 2.1 §4.1.3: redirect_uri is always required when included in the
    // authorization request (McpCodeRecord always stores it), and must match exactly.
    if (!redirectUri || redirectUri !== record.redirectUri) throw new Error('redirect_uri is required and must match the authorization request');
    // Validate resource audience if provided.
    if (resource && record.resource && resource.toString() !== record.resource) throw new Error('resource mismatch');
    // Issue tokens before deleting the code so transient JWT/store failures
    // leave the code intact and allow the client to retry the exchange.
    const tokens = await this.issueTokens(record.subject, client.client_id, record.scopes);
    // Best-effort delete: if this throws after tokens are issued, the code
    // remains valid until TTL expiry. Full atomicity requires a transactional
    // store (PR2/Redis). Log the failure but still return the issued tokens so
    // the client isn't left with a successful issueTokens and no tokens.
    try {
      await this.store.deleteMcpCode(authorizationCode);
    } catch (err) {
      logger.warn('Failed to delete MCP authorization code after issuance; it will expire at TTL', {
        error: String(err),
      });
    }
    return tokens;
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string
  ): Promise<OAuthTokens> {
    const stored = await this.store.getRefreshToken(refreshToken);
    if (!stored) throw new Error('Refresh token not found or expired');
    if (stored.clientId !== client.client_id) throw new Error('Refresh token was not issued to this client');

    // Issue new tokens (including new refresh token) before deleting the old one
    // so that transient failures don't leave the client permanently logged out.
    // There is a brief window where both tokens are valid; the old one is deleted
    // immediately after. For full atomicity, use a transactional store (e.g., Redis
    // with a Lua script) in the PR2 session store implementation.

    const session = await this.store.getSession(stored.subject);
    if (session && isMetaTokenStale(session.metaTokenExpiresAt)) {
      try {
        const refreshed = await refreshLongLivedToken({ accessToken: session.metaAccessToken, appId: this.opts.metaAppId, appSecret: this.opts.metaAppSecret });
        await this.store.setSession(stored.subject, {
          ...session,
          metaAccessToken: refreshed.accessToken,
          metaTokenExpiresAt: Date.now() + refreshed.expiresIn * 1000,
        });
      } catch (err) {
        logger.warn('Failed to refresh Meta token during MCP refresh', { subject: stored.subject, error: String(err) });
      }
    }

    const tokens = await this.issueTokens(stored.subject, client.client_id, stored.scopes);
    // Best-effort delete — matches the pattern in exchangeAuthorizationCode.
    // If deletion fails after issuance, the old token remains valid until expiry
    // but the client already has fresh tokens. Full atomicity requires Redis+Lua.
    try {
      await this.store.deleteRefreshToken(refreshToken);
    } catch (err) {
      logger.warn('Failed to delete refresh token after rotation; old token remains valid until expiry', {
        error: String(err),
      });
    }
    return tokens;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    return verifyAccessToken(token, this.opts.serverAudience, this.opts.issuerUrl);
  }

  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    // Access tokens are stateless JWTs and cannot be revoked. For any hint (or
    // none), attempt to revoke as a refresh token — per RFC 7009 §2.1, the hint
    // is advisory only, so we must try regardless of its value.
    // RFC 7009 §2.2 requires HTTP 200 whether or not the token was found.
    const stored = await this.store.getRefreshToken(request.token);
    if (stored && stored.clientId === client.client_id) {
      await this.store.deleteRefreshToken(request.token);
    }
  }

  async handleMetaCallback(code: string, state: string): Promise<string> {
    const stateRecord = await this.store.getOAuthState(state);
    if (!stateRecord) throw new Error('OAuth state not found or expired');

    // Delete the OAuth state in a finally block regardless of outcome.
    // Once exchangeMetaCode is called, the Meta code is consumed and the state
    // cannot be meaningfully retried — Meta will reject the already-spent code.
    // If exchangeMetaCode itself fails, the state is also cleaned up so stale
    // records don't accumulate.
    try {
      const { accessToken: shortToken, userId } = await exchangeMetaCode({
        code,
        appId: this.opts.metaAppId,
        appSecret: this.opts.metaAppSecret,
        redirectUri: this.opts.metaCallbackUri,
      });
      const { accessToken: longToken, expiresIn } = await exchangeForLongLivedToken({
        shortLivedToken: shortToken,
        appId: this.opts.metaAppId,
        appSecret: this.opts.metaAppSecret,
      });

      const subject = `fb_${userId}`;
      await this.store.setSession(subject, {
        subject,
        metaAccessToken: longToken,
        metaTokenExpiresAt: Date.now() + expiresIn * 1000,
        fbUserId: userId,
      });

      const mcpCode = randomToken();
      await this.store.setMcpCode(mcpCode, {
        subject,
        codeChallenge: stateRecord.codeChallenge,
        redirectUri: stateRecord.redirectUri,
        clientId: stateRecord.clientId,
        scopes: stateRecord.scopes,
        resource: stateRecord.resource,
        expiresAt: Date.now() + CODE_TTL_MS,
      });

      const redirectUri = new URL(stateRecord.redirectUri);
      redirectUri.searchParams.set('code', mcpCode);
      if (stateRecord.clientState) redirectUri.searchParams.set('state', stateRecord.clientState);
      return redirectUri.toString();
    } finally {
      // Always consume the state — the Meta code is already spent regardless
      // of whether subsequent operations succeeded.
      await this.store.deleteOAuthState(state);
    }
  }

  private async issueTokens(subject: string, clientId: string, scopes: string[]): Promise<OAuthTokens> {
    const accessToken = await signAccessToken({
      subject,
      audience: this.opts.serverAudience,
      issuer: this.opts.issuerUrl,
      expiresIn: this.opts.jwtExpiry,
      scopes,
    });

    const refreshToken = randomToken();
    const refreshExpiresAt = Date.now() + this.opts.refreshTokenExpirySeconds * 1000;
    await this.store.setRefreshToken(refreshToken, subject, clientId, scopes, refreshExpiresAt);

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: parseExpiryToSeconds(this.opts.jwtExpiry),
      refresh_token: refreshToken,
      scope: scopes.join(' '),
    };
  }
}

function parseExpiryToSeconds(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) throw new Error(`Invalid expiry format "${expiry}". Expected a number followed by s, m, h, or d (e.g. "1h").`);
  const n = parseInt(match[1], 10);
  switch (match[2]) {
    case 's': return n;
    case 'm': return n * 60;
    case 'h': return n * 3600;
    case 'd': return n * 86400;
    default: throw new Error(`Unrecognised expiry unit "${match[2]}"`);
  }
}
