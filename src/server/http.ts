import { randomUUID, timingSafeEqual, createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import express, { type Request, type Response, type NextFunction } from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { Config } from '../config.js';

// Augment Express Request to include auth info populated by requireBearerAuth.
declare global {
  namespace Express {
    interface Request {
      auth?: AuthInfo;
    }
  }
}

import type { SessionStore } from '../session/store.js';
import { MetaOAuthProvider } from '../auth/provider.js';
import { initJwtKeys, getJwks } from '../auth/jwt.js';
import { resolveContext, type SessionContext } from '../context.js';
import { getAllTools } from '../tools.js';
import { PROMPTS, getPromptContent } from '../prompts.js';
import { handleInstagramTool, handleFacebookTool } from '../handlers.js';
import { logger } from '../utils/logger.js';
import { VERSION } from '../version.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const SESSION_TRANSPORT_MAX = 10_000;
const SESSION_TRANSPORT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Per-request auth propagated via AsyncLocalStorage so concurrent requests on
// the same session don't share mutable state and cross-contaminate each other's
// auth info inside the MCP handler.
const requestAuthStorage = new AsyncLocalStorage<AuthInfo | undefined>();

interface TransportEntry {
  transport: StreamableHTTPServerTransport;
  server: Server;
  // authHolder tracks the session owner for the hijacking check (compares
  // req.auth.clientId against the session-creation identity). It is updated
  // after the check so only the verified identity is remembered.
  // Per-dispatch auth (scopes, resolveContext) is read from requestAuthStorage.
  authHolder: { current: AuthInfo | undefined };
  createdAt: number;
}

export async function startHttpServer(cfg: Config, store: SessionStore): Promise<() => Promise<void>> {
  const app = express();
  app.use(express.json());

  let provider: MetaOAuthProvider | null = null;
  // cfg.serverUrl is guaranteed non-null in http-oauth mode by superRefine; declared
  // here so it can be referenced outside the if block (e.g. resourceMetadataUrl).
  let serverUrl: string | undefined;

  if (cfg.mode === 'http-oauth') {
    // JWT keys are only needed in http-oauth mode; skip in http-static to avoid
    // unnecessary key generation and the ephemeral-key warning.
    await initJwtKeys(cfg.jwtPrivateKeyJwk);
    serverUrl = cfg.serverUrl!;
    const metaCallbackUri = `${serverUrl}${cfg.metaCallbackPath}`;
    const serverAudience = `${serverUrl}/mcp`;

    provider = new MetaOAuthProvider({
      store,
      metaAppId: cfg.metaAppId!,
      metaAppSecret: cfg.metaAppSecret!,
      metaCallbackUri,
      issuerUrl: serverUrl,
      serverAudience,
      jwtExpiry: cfg.jwtExpiry,
      refreshTokenExpirySeconds: cfg.refreshTokenExpirySeconds,
    });

    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: new URL(serverUrl),
        resourceName: 'Social Analytics MCP Server',
        scopesSupported: ['instagram', 'facebook'],
      })
    );

    app.get(cfg.metaCallbackPath, async (req: Request, res: Response) => {
      // Validate that code and state are single strings (not arrays) before use.
      const code = typeof req.query.code === 'string' ? req.query.code : undefined;
      const state = typeof req.query.state === 'string' ? req.query.state : undefined;
      const error = typeof req.query.error === 'string' ? req.query.error : undefined;
      const errorDesc = typeof req.query.error_description === 'string' ? req.query.error_description : undefined;

      if (error) {
        logger.warn('Meta OAuth callback error', { error, error_description: errorDesc });
        // Use text/plain to prevent reflected XSS — these values are user-controlled.
        res.status(400).type('text/plain').send(`Meta authorization failed: ${errorDesc ?? error}`);
        return;
      }

      if (!code || !state) {
        res.status(400).type('text/plain').send('Missing code or state parameter');
        return;
      }

      try {
        const redirectUrl = await provider!.handleMetaCallback(code, state);
        res.redirect(redirectUrl);
      } catch (err) {
        logger.error('Meta callback handling failed', err);
        res.status(400).type('text/plain').send('Authorization failed');
      }
    });

    app.get('/.well-known/jwks.json', (_req: Request, res: Response) => {
      res.json(getJwks());
    });
  }

  const sessions = new Map<string, TransportEntry>();

  function closeAndDelete(id: string, entry: TransportEntry): void {
    sessions.delete(id);
    entry.transport.close().catch((err) =>
      logger.debug('Error closing evicted session transport', { sessionId: id, err: String(err) })
    );
  }

  function sweepSessions(): void {
    const cutoff = Date.now() - SESSION_TRANSPORT_TTL_MS;
    for (const [id, entry] of sessions) if (entry.createdAt < cutoff) closeAndDelete(id, entry);
  }

  // Background sweep mirrors MemorySessionStore's approach — O(n) sweep runs
  // periodically instead of on every new session creation.
  const sessionSweepTimer = setInterval(sweepSessions, 5 * 60 * 1000).unref();

  function buildMcpServer(authHolder: { current: AuthInfo | undefined }): Server {
    const server = new Server({ name: 'social-analytics-mcp', version: VERSION }, { capabilities: { tools: {}, prompts: {} } });

    // Cache per-session context for static modes (token is fixed for the session
    // lifetime). In http-oauth mode we re-resolve on every tool call so that
    // Meta token staleness and refresh are re-evaluated on each request.
    let cachedContext: SessionContext | undefined;

    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: getAllTools() }));
    server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: PROMPTS }));

    server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      return getPromptContent(name, (args ?? {}) as Record<string, string>);
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      const formatSuccess = (data: unknown) => ({
        content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
      });
      const formatError = (err: unknown) => ({
        content: [{ type: 'text' as const, text: JSON.stringify({ error: err instanceof Error ? err.message : String(err) }) }],
        isError: true,
      });

      try {
        // Read auth from AsyncLocalStorage — set per-request in handleMcp so
        // concurrent requests on the same session use their own auth context.
        const authInfo = requestAuthStorage.getStore();
        if (cfg.mode === 'http-oauth') {
          // requireBearerAuth guarantees authInfo is set; treat absence as a
          // misconfiguration and fail closed rather than silently skipping checks.
          if (!authInfo) return formatError(new Error('Authentication required'));
          const requiredScope = name.startsWith('instagram_') ? 'instagram'
            : name.startsWith('facebook_') ? 'facebook'
            : null;
          if (requiredScope && !authInfo.scopes.includes(requiredScope)) {
            return formatError(new Error(`Insufficient scope: '${requiredScope}' required to call ${name}`));
          }
        }

        if (!cachedContext || cfg.mode === 'http-oauth') {
          cachedContext = await resolveContext(authInfo, cfg, store);
        }
        const ctx = cachedContext;
        let result: unknown;
        if (name.startsWith('instagram_')) {
          result = await handleInstagramTool(name, (args ?? {}) as Record<string, unknown>, ctx.instagramClient);
        } else if (name.startsWith('facebook_')) {
          result = await handleFacebookTool(name, (args ?? {}) as Record<string, unknown>, ctx.facebookClient);
        } else {
          throw new Error(`Unknown tool: ${name}`);
        }
        return formatSuccess(result);
      } catch (err) {
        return formatError(err);
      }
    });

    return server;
  }

  async function handleMcp(req: Request, res: Response): Promise<void> {
    const rawSessionId = req.headers['mcp-session-id'];
    if (Array.isArray(rawSessionId)) {
      res.status(400).json({ error: 'mcp-session-id must be a single header value' });
      return;
    }
    const sessionId = rawSessionId; // string | undefined
    let entry = sessionId ? sessions.get(sessionId) : undefined;

    // Enforce TTL on every request — the background timer sweeps periodically
    // but a session that slips through between sweeps must still be rejected here.
    if (entry && Date.now() - entry.createdAt > SESSION_TRANSPORT_TTL_MS) {
      closeAndDelete(sessionId!, entry);
      entry = undefined;
    }

    // In http-oauth mode, verify the JWT subject matches the session's recorded
    // subject on every request. Prevents session hijacking where a valid JWT
    // from user B is combined with a leaked session ID from user A.
    // authHolder is only updated in http-oauth; http-static has no per-request
    // identity binding (the static token is a shared secret, not per-user).
    if (entry && cfg.mode === 'http-oauth' && req.auth) {
      if (!entry.authHolder.current || req.auth.clientId !== entry.authHolder.current.clientId) {
        res.status(401)
          .set('WWW-Authenticate', 'Bearer error="invalid_token", error_description="Session does not belong to the authenticated user"')
          .json({ error: 'Session does not belong to the authenticated user' });
        return;
      }
      // Update holder so the hijacking check on the next request compares
      // against the most-recently verified identity for this session.
      entry.authHolder.current = req.auth;
    }

    if (!entry) {
      if (!isInitializeRequest(req.body)) {
        res.status(400).json({ error: 'No active session. Send initialize request first.' });
        return;
      }

      const effectiveServerUrl = cfg.serverUrl ?? `http://localhost:${cfg.port}`;
      const parsedHost = new URL(effectiveServerUrl).hostname;
      // '0.0.0.0' is a listen address, not a valid Host header value.
      const canonicalHost = parsedHost === '0.0.0.0' ? 'localhost' : parsedHost;
      // Only add loopback aliases when actually running locally; including them
      // unconditionally for external hostnames widens the accepted Host header
      // set and can undermine DNS rebinding protection.
      const isLocal = ['localhost', '127.0.0.1', '::1'].includes(canonicalHost);
      const allowedHosts = isLocal
        ? [canonicalHost, 'localhost', '127.0.0.1', '::1']
        : [canonicalHost];
      // authHolder is a mutable slot updated with req.auth before every dispatch
      // so the MCP handler always enforces the presented token's scopes.
      const authHolder: { current: AuthInfo | undefined } = { current: req.auth };

      // Declare server before transport so the onsessioninitialized closure
      // captures an already-assigned binding (avoids TDZ if the callback were
      // ever invoked before connect() in a future refactor).
      const server = buildMcpServer(authHolder);
      let sessionRegistered = false;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          sessionRegistered = true;
          if (sessions.size >= SESSION_TRANSPORT_MAX) {
            const oldestId = sessions.keys().next().value!;
            closeAndDelete(oldestId, sessions.get(oldestId)!);
          }
          sessions.set(id, { transport, server, authHolder, createdAt: Date.now() });
          logger.debug('MCP session initialized', { sessionId: id });
        },
        onsessionclosed: (id) => {
          sessions.delete(id);
          logger.debug('MCP session closed', { sessionId: id });
        },
        enableDnsRebindingProtection: true,
        allowedHosts,
      });

      entry = { transport, server, authHolder, createdAt: Date.now() };
      await server.connect(transport);
      await requestAuthStorage.run(req.auth, () =>
        entry!.transport.handleRequest(req, res, req.body)
      );
      // If onsessioninitialized never fired (e.g. SDK rejected the initialize
      // body), the transport was never stored in `sessions` and won't be swept.
      if (!sessionRegistered) {
        transport.close().catch((err) =>
          logger.debug('Error closing unregistered session transport', { err: String(err) })
        );
      }
      return;
    }

    await requestAuthStorage.run(req.auth, () =>
      entry!.transport.handleRequest(req, res, req.body)
    );
  }

  const resourceMetadataUrl = serverUrl
    ? `${serverUrl}/.well-known/oauth-protected-resource`
    : undefined;

  if (cfg.mode === 'http-oauth' && provider) {
    const bearerMiddleware = requireBearerAuth({ verifier: provider, resourceMetadataUrl });
    app.post('/mcp', bearerMiddleware, handleMcp);
    app.get('/mcp', bearerMiddleware, handleMcp);
    app.delete('/mcp', bearerMiddleware, handleMcp);
  } else if (cfg.mode === 'http-static') {
    // Pre-compute the expected token hash once at startup — cfg.staticToken is
    // static, so recomputing it on every request would be wasteful.
    const expectedTokenHash = cfg.staticToken
      ? createHash('sha256').update(cfg.staticToken).digest()
      : null;
    const staticMiddleware = (req: Request, res: Response, next: NextFunction) => {
      if (!expectedTokenHash) { next(); return; }
      const auth = req.headers.authorization ?? '';
      // RFC 6750: Bearer scheme name is case-insensitive; extract token with /i flag.
      const token = /^bearer\s+(\S+)$/i.exec(auth)?.[1] ?? '';
      const presented = createHash('sha256').update(token).digest();
      if (!timingSafeEqual(presented, expectedTokenHash)) {
        res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'Unauthorized' });
        return;
      }
      next();
    };
    app.post('/mcp', staticMiddleware, handleMcp);
    app.get('/mcp', staticMiddleware, handleMcp);
    app.delete('/mcp', staticMiddleware, handleMcp);
  }

  let isShuttingDown = false;
  app.get('/healthz', (_req: Request, res: Response) => res.json({ status: 'ok' }));
  app.get('/readyz', (_req: Request, res: Response) => {
    if (isShuttingDown) { res.status(503).json({ status: 'shutting_down' }); return; }
    res.json({ status: 'ok' });
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled HTTP error', err);
    res.status(500).json({ error: 'Internal server error' });
  });

  const httpServer = app.listen(cfg.port, cfg.host, () => {
    logger.info(`Social Analytics MCP Server v${VERSION} listening`, {
      mode: cfg.mode,
      host: cfg.host,
      port: cfg.port,
    });
  });

  function shutdown(): Promise<void> {
    isShuttingDown = true;
    logger.info('Shutting down HTTP server...');
    clearInterval(sessionSweepTimer);
    store.stopSweep?.();
    // Close all active MCP session transports so in-flight connections are not
    // left open after the HTTP listener stops accepting new requests.
    for (const [id, entry] of [...sessions]) closeAndDelete(id, entry);
    // Release idle keep-alive connections so the server can close promptly.
    // closeIdleConnections() (Node 18.2+) lets in-flight requests complete
    // while immediately releasing idle sockets that would otherwise hold the
    // process alive until the 10 s force-timeout fires.
    httpServer.closeIdleConnections?.();
    return new Promise((resolve, reject) => {
      const forceTimeout = setTimeout(() => reject(new Error('Server shutdown timed out after 10s')), 10_000);
      httpServer.close((err) => {
        clearTimeout(forceTimeout);
        if (err) { logger.error('HTTP server close error', err); reject(err); }
        else { logger.info('HTTP server closed'); resolve(); }
      });
    });
  }

  return shutdown;
}
