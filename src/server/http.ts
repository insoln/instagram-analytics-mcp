import { randomUUID, timingSafeEqual, createHash } from 'node:crypto';
import express, { type Request, type Response, type NextFunction } from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

// Augment Express Request to include auth info populated by requireBearerAuth.
declare global {
  namespace Express {
    interface Request {
      auth?: AuthInfo;
    }
  }
}
import type { Config } from '../config.js';
import type { SessionStore } from '../session/store.js';
import { MetaOAuthProvider } from '../auth/provider.js';
import { initJwtKeys, getJwks } from '../auth/jwt.js';
import { resolveContext, type SessionContext } from '../context.js';
import { getAllTools } from '../tools.js';
import { PROMPTS, getPromptContent } from '../prompts.js';
import { handleInstagramTool, handleFacebookTool } from '../handlers.js';
import { logger } from '../utils/logger.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const VERSION = '3.0.0';

const SESSION_TRANSPORT_MAX = 10_000;
const SESSION_TRANSPORT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface TransportEntry {
  transport: StreamableHTTPServerTransport;
  server: Server;
  authInfo: AuthInfo | undefined;
  createdAt: number;
}

export async function startHttpServer(cfg: Config, store: SessionStore): Promise<void> {
  const app = express();
  app.use(express.json());

  let provider: MetaOAuthProvider | null = null;

  if (cfg.mode === 'http-oauth') {
    // JWT keys are only needed in http-oauth mode; skip in http-static to avoid
    // unnecessary key generation and the ephemeral-key warning.
    await initJwtKeys(cfg.jwtPrivateKeyJwk);
    const serverUrl = cfg.serverUrl!;
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

  function sweepSessions(): void {
    const cutoff = Date.now() - SESSION_TRANSPORT_TTL_MS;
    for (const [id, entry] of sessions) if (entry.createdAt < cutoff) sessions.delete(id);
  }

  // authInfo is captured at session creation time (from the initialize request)
  // and stored in the session entry so all subsequent requests in the same
  // session use the same identity without touching private transport internals.
  function buildMcpServer(authInfo: AuthInfo | undefined): Server {
    const server = new Server({ name: 'social-analytics-mcp', version: VERSION }, { capabilities: { tools: {}, prompts: {} } });

    // Cache per-session client instances — constructors create Axios instances,
    // so we avoid recreating them on every tool call within the same session.
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
        if (!cachedContext) cachedContext = await resolveContext(authInfo, cfg, store);
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

    // Enforce TTL on every request — sweepSessions() only runs at creation time
    // so without this check an expired entry could be used indefinitely.
    if (entry && Date.now() - entry.createdAt > SESSION_TRANSPORT_TTL_MS) {
      sessions.delete(sessionId!);
      entry = undefined;
    }

    // In http-oauth mode, verify the JWT subject matches the session's recorded
    // subject on every request. Prevents session hijacking where a valid JWT
    // from user B is combined with a leaked session ID from user A.
    if (entry && cfg.mode === 'http-oauth' && req.auth) {
      if (req.auth.clientId !== entry.authInfo?.clientId) {
        res.status(401).json({ error: 'Session does not belong to the authenticated user' });
        return;
      }
    }

    if (!entry) {
      if (!isInitializeRequest(req.body)) {
        res.status(400).json({ error: 'No active session. Send initialize request first.' });
        return;
      }

      const serverUrl = cfg.serverUrl ?? `http://localhost:${cfg.port}`;
      const parsedHost = new URL(serverUrl).hostname;
      // '0.0.0.0' is a listen address, not a valid Host header value.
      const canonicalHost = parsedHost === '0.0.0.0' ? 'localhost' : parsedHost;
      // Only add loopback aliases when actually running locally; including them
      // unconditionally for external hostnames widens the accepted Host header
      // set and can undermine DNS rebinding protection.
      const isLocal = ['localhost', '127.0.0.1', '::1'].includes(canonicalHost);
      const allowedHosts = isLocal
        ? [canonicalHost, 'localhost', '127.0.0.1']
        : [canonicalHost];
      const authInfo: AuthInfo | undefined = req.auth;

      // Declare server before transport so the onsessioninitialized closure
      // captures an already-assigned binding (avoids TDZ if the callback were
      // ever invoked before connect() in a future refactor).
      const server = buildMcpServer(authInfo);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          sweepSessions();
          if (sessions.size >= SESSION_TRANSPORT_MAX) {
            sessions.delete(sessions.keys().next().value!);
          }
          sessions.set(id, { transport, server, authInfo, createdAt: Date.now() });
          logger.debug('MCP session initialized', { sessionId: id });
        },
        onsessionclosed: (id) => {
          sessions.delete(id);
          logger.debug('MCP session closed', { sessionId: id });
        },
        enableDnsRebindingProtection: true,
        allowedHosts,
      });

      entry = { transport, server, authInfo, createdAt: Date.now() };
      await server.connect(transport);
    }

    await entry!.transport.handleRequest(req, res, req.body);
  }

  // cfg.serverUrl is guaranteed non-null in http-oauth mode by superRefine validation.
  const resourceMetadataUrl = cfg.mode === 'http-oauth'
    ? `${cfg.serverUrl!}/.well-known/oauth-protected-resource`
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
      const presented = createHash('sha256').update(auth.startsWith('Bearer ') ? auth.slice(7) : '').digest();
      if (!auth.startsWith('Bearer ') || !timingSafeEqual(presented, expectedTokenHash)) {
        res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'Unauthorized' });
        return;
      }
      next();
    };
    app.post('/mcp', staticMiddleware, handleMcp);
    app.get('/mcp', staticMiddleware, handleMcp);
    app.delete('/mcp', staticMiddleware, handleMcp);
  }

  app.get('/healthz', (_req: Request, res: Response) => res.json({ status: 'ok' }));
  app.get('/readyz', (_req: Request, res: Response) => res.json({ status: 'ok' }));

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

  function shutdown() {
    logger.info('Shutting down HTTP server...');
    httpServer.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000);
  }

  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
