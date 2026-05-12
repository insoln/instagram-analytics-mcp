import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InstagramClient } from './platforms/instagram/client.js';
import { FacebookClient } from './platforms/facebook/client.js';
import { isMetaTokenStale, refreshLongLivedToken } from './auth/meta-oauth.js';
import type { SessionRecord } from './session/types.js';
import type { SessionStore } from './session/store.js';
import type { Config } from './config.js';
import { logger } from './utils/logger.js';

export interface SessionContext {
  instagramClient: InstagramClient | null;
  facebookClient: FacebookClient | null;
}

function buildClients(session: SessionRecord, cfg: Config): SessionContext {
  return {
    instagramClient: new InstagramClient({
      accessToken: session.metaAccessToken,
      apiVersion: cfg.instagramApiVersion,
    }),
    facebookClient: new FacebookClient({
      accessToken: session.metaAccessToken,
      defaultApiVersion: cfg.facebookApiVersion,
    }),
  };
}

export async function resolveContext(
  auth: AuthInfo | undefined,
  cfg: Config,
  store: SessionStore | null
): Promise<SessionContext> {
  if (cfg.mode === 'stdio-static' || cfg.mode === 'http-static') {
    return {
      instagramClient: cfg.instagramAccessToken
        ? new InstagramClient({
            accessToken: cfg.instagramAccessToken,
            accountId: cfg.instagramAccountId,
            apiVersion: cfg.instagramApiVersion,
          })
        : null,
      facebookClient: cfg.facebookAccessToken
        ? new FacebookClient({
            accessToken: cfg.facebookAccessToken,
            pageId: cfg.facebookPageId,
            defaultApiVersion: cfg.facebookApiVersion,
          })
        : null,
    };
  }

  // http-oauth: resolve per-session Meta token
  if (!auth || !store) {
    return { instagramClient: null, facebookClient: null };
  }

  // auth.clientId is the JWT `sub` claim, which we set to the session subject ("fb_<userId>").
  let session = await store.getSession(auth.clientId);
  if (!session) {
    // Throw an actionable OAuth-specific message rather than returning null clients
    // (which would surface the misleading "Please set INSTAGRAM_ACCESS_TOKEN" error).
    throw new Error(
      'OAuth session not found. Please complete the authorization flow to connect your Meta account.'
    );
  }

  // Refresh the Meta token proactively when it's within the stale window (7 days
  // of expiry) or has already expired.  This prevents tool calls from failing with
  // Graph API auth errors while the MCP JWT is still valid.
  if (isMetaTokenStale(session.metaTokenExpiresAt) && cfg.metaAppId && cfg.metaAppSecret) {
    try {
      const refreshed = await refreshLongLivedToken({
        accessToken: session.metaAccessToken,
        appId: cfg.metaAppId,
        appSecret: cfg.metaAppSecret,
      });
      session = {
        ...session,
        metaAccessToken: refreshed.accessToken,
        metaTokenExpiresAt: Date.now() + refreshed.expiresIn * 1000,
      };
      await store.setSession(session.subject, session);
      logger.debug('Meta token refreshed in resolveContext', { subject: session.subject });
    } catch (err) {
      logger.warn('Failed to refresh Meta token in resolveContext; using existing token', {
        subject: session.subject,
        expired: Date.now() > session.metaTokenExpiresAt,
        error: String(err),
      });
      if (Date.now() > session.metaTokenExpiresAt) {
        throw new Error(
          'Meta access token has expired and could not be refreshed. Please re-authenticate via the OAuth flow.'
        );
      }
    }
  }

  return buildClients(session, cfg);
}
