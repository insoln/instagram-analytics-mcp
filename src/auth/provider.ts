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

const CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

interface MetaProviderOptions {
  store: SessionStore;
  metaAppId: string;
  metaAppSecret: string;
  metaCallbackUri: string; // absolute URL: https://host/auth/meta/callback
  serverAudience: string; // canonical MCP resource URI: https://host/mcp
  jwtExpiry: string;
  refreshTokenExpirySeconds: number;
}

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
    this.clients.set(full.client_id, full);
    return full;
  }
}

export class MetaOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore;
  skipLocalPkceValidation = false;

  private readonly store: SessionStore;
  private readonly opts: MetaProviderOptions;

  constructor(opts: MetaProviderOptions) {
    this.opts = opts;
    this.store = opts.store;
    this.clientsStore = new InMemoryClientsStore();
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const state = randomToken();
    const expiresAt = Date.now() + STATE_TTL_MS;

    await this.store.setOAuthState(state, {
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      clientId: client.client_id,
      resource: params.resource?.toString(),
      clientState: params.state,
      expiresAt,
    });

    const metaUrl = buildMetaAuthorizationUrl({
      appId: this.opts.metaAppId,
      redirectUri: this.opts.metaCallbackUri,
      state,
    });

    res.redirect(metaUrl);
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const record = await this.store.getMcpCode(authorizationCode);
    if (!record) throw new Error('Authorization code not found or expired');
    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    _redirectUri?: string,
    _resource?: URL
  ): Promise<OAuthTokens> {
    const record = await this.store.getMcpCode(authorizationCode);
    if (!record) throw new Error('Authorization code not found or expired');
    await this.store.deleteMcpCode(authorizationCode);

    return this.issueTokens(record.subject);
  }

  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string
  ): Promise<OAuthTokens> {
    const subject = await this.store.getRefreshToken(refreshToken);
    if (!subject) throw new Error('Refresh token not found or expired');

    // Rotate: delete old token
    await this.store.deleteRefreshToken(refreshToken);

    // Proactively refresh Meta token if stale
    const session = await this.store.getSession(subject);
    if (session && isMetaTokenStale(session.metaTokenExpiresAt)) {
      try {
        const refreshed = await refreshLongLivedToken(session.metaAccessToken);
        await this.store.setSession(subject, {
          ...session,
          metaAccessToken: refreshed.accessToken,
          metaTokenExpiresAt: Date.now() + refreshed.expiresIn * 1000,
        });
      } catch (err) {
        logger.warn('Failed to refresh Meta token during MCP refresh', { subject, error: String(err) });
      }
    }

    return this.issueTokens(subject);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    return verifyAccessToken(token, this.opts.serverAudience);
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    if (request.token_type_hint === 'refresh_token') {
      await this.store.deleteRefreshToken(request.token);
    }
    // Access tokens are JWTs — they expire naturally; no server-side revocation in PR1.
  }

  // Called by the Meta callback route handler
  async handleMetaCallback(code: string, state: string): Promise<string> {
    const stateRecord = await this.store.getOAuthState(state);
    if (!stateRecord) throw new Error('OAuth state not found or expired');
    await this.store.deleteOAuthState(state);

    // Exchange Meta code for short-lived token
    const { accessToken: shortToken, userId } = await exchangeMetaCode({
      code,
      appId: this.opts.metaAppId,
      appSecret: this.opts.metaAppSecret,
      redirectUri: this.opts.metaCallbackUri,
    });

    // Exchange for long-lived token (~60 days)
    const { accessToken: longToken, expiresIn } = await exchangeForLongLivedToken({
      shortLivedToken: shortToken,
      appSecret: this.opts.metaAppSecret,
    });

    const subject = `ig_${userId}`;
    await this.store.setSession(subject, {
      subject,
      metaAccessToken: longToken,
      metaTokenExpiresAt: Date.now() + expiresIn * 1000,
      igUserId: userId,
    });

    // Issue MCP authorization code
    const mcpCode = randomToken();
    await this.store.setMcpCode(mcpCode, {
      subject,
      codeChallenge: stateRecord.codeChallenge,
      clientId: stateRecord.clientId,
      resource: stateRecord.resource,
      expiresAt: Date.now() + CODE_TTL_MS,
    });

    // Redirect back to MCP client
    const redirectUri = new URL(stateRecord.redirectUri);
    redirectUri.searchParams.set('code', mcpCode);
    if (stateRecord.clientState) redirectUri.searchParams.set('state', stateRecord.clientState);
    return redirectUri.toString();
  }

  private async issueTokens(subject: string): Promise<OAuthTokens> {
    const accessToken = await signAccessToken({
      subject,
      audience: this.opts.serverAudience,
      expiresIn: this.opts.jwtExpiry,
    });

    const refreshToken = randomToken();
    const refreshExpiresAt = Date.now() + this.opts.refreshTokenExpirySeconds * 1000;
    await this.store.setRefreshToken(refreshToken, subject, refreshExpiresAt);

    // Parse expiry from JWT expiry string (e.g. "1h" → 3600)
    const expiresIn = parseExpiryToSeconds(this.opts.jwtExpiry);

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
      scope: 'instagram facebook',
    };
  }
}

function parseExpiryToSeconds(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) return 3600;
  const n = parseInt(match[1], 10);
  switch (match[2]) {
    case 's': return n;
    case 'm': return n * 60;
    case 'h': return n * 3600;
    case 'd': return n * 86400;
    default: return 3600;
  }
}
