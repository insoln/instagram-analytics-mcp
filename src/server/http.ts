import { randomUUID } from 'node:crypto';
import express, { type Request, type Response, type NextFunction } from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { Config } from '../config.js';
import type { SessionStore } from '../session/store.js';
import { MetaOAuthProvider } from '../auth/provider.js';
import { initJwtKeys, getJwks } from '../auth/jwt.js';
import { resolveContext } from '../context.js';
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

interface TransportEntry {
  transport: StreamableHTTPServerTransport;
  server: Server;
  authInfo: AuthInfo | undefined;
}

export async function startHttpServer(cfg: Config, store: SessionStore): Promise<void> {
  await initJwtKeys(cfg.jwtPrivateKeyJwk);

  const app = express();
  app.use(express.json());

  let provider: MetaOAuthProvider | null = null;

  if (cfg.mode === 'http-oauth') {
    const serverUrl = cfg.serverUrl!;
    const metaCallbackUri = `${serverUrl}${cfg.metaCallbackPath}`;
    const serverAudience = `${serverUrl}/mcp`;

    provider = new MetaOAuthProvider({
      store,
      metaAppId: cfg.metaAppId!,
      metaAppSecret: cfg.metaAppSecret!,
      metaCallbackUri,
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
      const { code, state, error, error_description } = req.query as Record<string, string>;

      if (error) {
        logger.warn('Meta OAuth callback error', { error, error_description });
        res.status(400).send(`Meta authorization failed: ${error_description ?? error}`);
        return;
      }

      if (!code || !state) {
        res.status(400).send('Missing code or state parameter');
        return;
      }

      try {
        const redirectUrl = await provider!.handleMetaCallback(code, state);
        res.redirect(redirectUrl);
      } catch (err) {
        logger.error('Meta callback handling failed', err);
        res.status(400).send(`Authorization failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    });

    app.get('/.well-known/jwks.json', (_req: Request, res: Response) => {
      res.json(getJwks());
    });
  }

  const sessions = new Map<string, TransportEntry>();

  // authInfo is captured at session creation time (from the initialize request)
  // and stored in the session entry so all subsequent requests in the same
  // session use the same identity without touching private transport internals.
  function buildMcpServer(authInfo: AuthInfo | undefined): Server {
    const server = new Server({ name: 'social-analytics-mcp', version: VERSION }, { capabilities: { tools: {}, prompts: {} } });

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
        const ctx = await resolveContext(authInfo, cfg, store);
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
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let entry = sessionId ? sessions.get(sessionId) : undefined;

    if (!entry) {
      if (!isInitializeRequest(req.body)) {
        res.status(400).json({ error: 'No active session. Send initialize request first.' });
        return;
      }

      const serverUrl = cfg.serverUrl ?? `http://${cfg.host}:${cfg.port}`;
      const allowedHost = new URL(serverUrl).hostname;
      const authInfo: AuthInfo | undefined = req.auth;

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          sessions.set(id, { transport, server, authInfo });
          logger.debug('MCP session initialized', { sessionId: id });
        },
        onsessionclosed: (id) => {
          sessions.delete(id);
          logger.debug('MCP session closed', { sessionId: id });
        },
        enableDnsRebindingProtection: true,
        allowedHosts: [allowedHost, 'localhost', '127.0.0.1'],
      });

      const server = buildMcpServer(authInfo);
      entry = { transport, server, authInfo };
      await server.connect(transport);
    }

    await entry.transport.handleRequest(req, res, req.body);
  }

  const resourceMetadataUrl = cfg.mode === 'http-oauth'
    ? `${cfg.serverUrl}/.well-known/oauth-protected-resource`
    : undefined;

  if (cfg.mode === 'http-oauth' && provider) {
    const bearerMiddleware = requireBearerAuth({ verifier: provider, resourceMetadataUrl });
    app.post('/mcp', bearerMiddleware, handleMcp);
    app.get('/mcp', bearerMiddleware, handleMcp);
    app.delete('/mcp', bearerMiddleware, handleMcp);
  } else if (cfg.mode === 'http-static') {
    const staticMiddleware = (req: Request, res: Response, next: NextFunction) => {
      if (!cfg.staticToken) { next(); return; }
      const auth = req.headers.authorization ?? '';
      if (!auth.startsWith('Bearer ') || auth.slice(7) !== cfg.staticToken) {
        res.status(401).json({ error: 'Unauthorized' });
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
