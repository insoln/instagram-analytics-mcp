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

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

interface MetaProviderOptions {
  store: SessionStore;
  metaAppId: string;
  metaAppSecret: string;
  metaCallbackUri: string;
  serverAudience: string;
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
    }));
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const record = await this.store.getMcpCode(authorizationCode);
    if (!record) throw new Error('Authorization code not found or expired');
    if (record.clientId !== client.client_id) throw new Error('Authorization code was not issued to this client');
    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    _redirectUri?: string,
    _resource?: URL
  ): Promise<OAuthTokens> {
    const record = await this.store.getMcpCode(authorizationCode);
    if (!record) throw new Error('Authorization code not found or expired');
    if (record.clientId !== client.client_id) throw new Error('Authorization code was not issued to this client');
    await this.store.deleteMcpCode(authorizationCode);

    return this.issueTokens(record.subject, client.client_id, record.scopes);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string
  ): Promise<OAuthTokens> {
    const stored = await this.store.getRefreshToken(refreshToken);
    if (!stored) throw new Error('Refresh token not found or expired');
    if (stored.clientId !== client.client_id) throw new Error('Refresh token was not issued to this client');

    await this.store.deleteRefreshToken(refreshToken);

    const session = await this.store.getSession(stored.subject);
    if (session && isMetaTokenStale(session.metaTokenExpiresAt)) {
      try {
        const refreshed = await refreshLongLivedToken(session.metaAccessToken);
        await this.store.setSession(stored.subject, {
          ...session,
          metaAccessToken: refreshed.accessToken,
          metaTokenExpiresAt: Date.now() + refreshed.expiresIn * 1000,
        });
      } catch (err) {
        logger.warn('Failed to refresh Meta token during MCP refresh', { subject: stored.subject, error: String(err) });
      }
    }

    return this.issueTokens(stored.subject, client.client_id, stored.scopes);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    return verifyAccessToken(token, this.opts.serverAudience);
  }

  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    if (request.token_type_hint === 'refresh_token') {
      const stored = await this.store.getRefreshToken(request.token);
      if (stored && stored.clientId === client.client_id) {
        await this.store.deleteRefreshToken(request.token);
      }
    }
  }

  async handleMetaCallback(code: string, state: string): Promise<string> {
    const stateRecord = await this.store.getOAuthState(state);
    if (!stateRecord) throw new Error('OAuth state not found or expired');
    await this.store.deleteOAuthState(state);

    const { accessToken: shortToken, userId } = await exchangeMetaCode({
      code,
      appId: this.opts.metaAppId,
      appSecret: this.opts.metaAppSecret,
      redirectUri: this.opts.metaCallbackUri,
    });

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

    const mcpCode = randomToken();
    await this.store.setMcpCode(mcpCode, {
      subject,
      codeChallenge: stateRecord.codeChallenge,
      clientId: stateRecord.clientId,
      scopes: stateRecord.scopes,
      resource: stateRecord.resource,
      expiresAt: Date.now() + CODE_TTL_MS,
    });

    const redirectUri = new URL(stateRecord.redirectUri);
    redirectUri.searchParams.set('code', mcpCode);
    if (stateRecord.clientState) redirectUri.searchParams.set('state', stateRecord.clientState);
    return redirectUri.toString();
  }

  private async issueTokens(subject: string, clientId: string, scopes: string[]): Promise<OAuthTokens> {
    const accessToken = await signAccessToken({
      subject,
      audience: this.opts.serverAudience,
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
