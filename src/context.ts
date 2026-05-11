import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InstagramClient } from './platforms/instagram/client.js';
import { FacebookClient } from './platforms/facebook/client.js';
import type { SessionStore } from './session/store.js';
import type { Config } from './config.js';

export interface SessionContext {
  instagramClient: InstagramClient | null;
  facebookClient: FacebookClient | null;
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

  const session = await store.getSession(auth.clientId);
  if (!session) {
    return { instagramClient: null, facebookClient: null };
  }

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
