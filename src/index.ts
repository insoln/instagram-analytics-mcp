#!/usr/bin/env node

/**
 * Social Analytics MCP Server
 * Supports three modes via MCP_MODE env var:
 *   stdio-static (default) — stdin/stdout transport, token from env
 *   http-static            — HTTP transport, token from env
 *   http-oauth             — HTTP transport, Meta OAuth 2.1 multi-tenant
 */

import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { VERSION } from './version.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { loadConfig } from './config.js';
import { InstagramClient } from './platforms/instagram/client.js';
import { FacebookClient } from './platforms/facebook/client.js';
import { getAllTools } from './tools.js';
import { PROMPTS, getPromptContent } from './prompts.js';
import { handleInstagramTool, handleFacebookTool } from './handlers.js';
import { logger } from './utils/logger.js';

// Re-export public API for programmatic usage
export { InstagramClient, FacebookClient };
export { getAllTools } from './tools.js';
export { PROMPTS, getPromptContent } from './prompts.js';
export { handleInstagramTool, handleFacebookTool } from './handlers.js';
export type { InstagramConfig } from './platforms/instagram/types.js';
export type { FacebookConfig } from './platforms/facebook/types.js';

// Backward-compatible singleton for programmatic consumers who imported
// `{ server }` from the previous version. The Server instance is created
// lazily on first property access (no side effects at import time).
// env vars must be set before first access; call server.connect(transport) to start.
// Note: the Proxy target is Object.create(Server.prototype) — an empty placeholder.
// Object.assign / spread / JSON.stringify on this export will return an empty object.
// Always interact with `server` through its methods, not by inspecting its properties.
let _server: Server | undefined;
function _getInstance(): Server { return (_server ??= createServer()); }
export const server: Server = new Proxy(Object.create(Server.prototype) as Server, {
  // Use the real instance as both target and receiver so getter properties and
  // any private-field accesses resolve on Server, not the placeholder target.
  // Bind functions explicitly for the same reason — method calls must have `this`
  // pointing to the real instance, not the Proxy.
  get(_t, p) {
    const inst = _getInstance();
    const val = Reflect.get(inst, p, inst);
    return typeof val === 'function' ? (val as (...a: unknown[]) => unknown).bind(inst) : val;
  },
  set(_t, p, v) { const inst = _getInstance(); return Reflect.set(inst, p, v, inst); },
});

/**
 * Create a pre-configured MCP Server instance using static tokens from env vars.
 * Returns an unconnected Server; call server.connect(transport) to start it.
 * Preserved for backward compatibility with programmatic usage.
 *
 * **Breaking change from v2**: does NOT call dotenv.config() anymore.
 * Previous versions loaded .env at module init; programmatic consumers who
 * relied on a local .env file must now call dotenv.config() (or equivalent)
 * before calling createServer() or accessing any `server` methods.
 * The CLI entry point handles env loading via loadConfig() — this only
 * affects programmatic / library usage.
 */
export function createServer() {
  const instagramAccessToken = process.env.INSTAGRAM_ACCESS_TOKEN;
  const facebookAccessToken = process.env.FACEBOOK_ACCESS_TOKEN;

  const instagramClient = instagramAccessToken
    ? new InstagramClient({
        accessToken: instagramAccessToken,
        accountId: process.env.INSTAGRAM_ACCOUNT_ID,
        apiVersion: process.env.INSTAGRAM_API_VERSION,
      })
    : null;

  const facebookClient = facebookAccessToken
    ? new FacebookClient({
        accessToken: facebookAccessToken,
        pageId: process.env.FACEBOOK_PAGE_ID,
        defaultApiVersion: process.env.FACEBOOK_API_VERSION,
      })
    : null;

  const server = new Server(
    { name: 'social-analytics-mcp', version: VERSION },
    { capabilities: { tools: {}, prompts: {} } }
  );

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
    const formatError = (error: unknown) => ({
      content: [{ type: 'text' as const, text: JSON.stringify({ error: error instanceof Error ? error.message : String(error) }, null, 2) }],
      isError: true,
    });

    try {
      let result: unknown;
      if (name.startsWith('instagram_')) {
        result = await handleInstagramTool(name, (args ?? {}) as Record<string, unknown>, instagramClient);
      } else if (name.startsWith('facebook_')) {
        result = await handleFacebookTool(name, (args ?? {}) as Record<string, unknown>, facebookClient);
      } else {
        throw new Error(`Unknown tool: ${name}`);
      }
      return formatSuccess(result);
    } catch (error) {
      return formatError(error);
    }
  });

  return server;
}

async function runStdioStatic(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  logger.info(`Social Analytics MCP Server v${VERSION} starting (stdio-static)`);
  await server.connect(transport);
}

async function runHttpServer(config: ReturnType<typeof loadConfig>): Promise<void> {
  const { startHttpServer } = await import('./server/http.js');

  let store: import('./session/store.js').SessionStore;
  if (config.sessionStore === 'redis') {
    const { RedisSessionStore } = await import('./session/redis-store.js');
    store = new RedisSessionStore(config.redisUrl, config.tokenEncryptionKey!);
    // Fail fast if Redis is unreachable before binding the HTTP port.
    await store.ping!();
    logger.info('Redis session store connected', { url: config.redisUrl });
  } else {
    const { MemorySessionStore } = await import('./session/memory-store.js');
    // Only http-oauth uses the session store (OAuth token storage, code/state maps).
    // http-static has no OAuth provider so there is no need to run the sweep timer.
    store = new MemorySessionStore(config.mode === 'http-oauth' ? undefined : 0);
  }

  logger.info(`Social Analytics MCP Server v${VERSION} starting (${config.mode})`, {
    port: config.port,
    host: config.host,
  });

  const shutdown = await startHttpServer(config, store);
  const handleSignal = () => {
    shutdown()
      .then(() => process.exit(0))
      .catch((err) => { logger.error('Error during shutdown', err); process.exit(1); });
  };
  process.once('SIGTERM', handleSignal);
  process.once('SIGINT', handleSignal);
}

// Guard: only connect and listen when invoked directly as the CLI entry point.
// `export const server` is now lazy — no side effects at import time.
// Use realpathSync so symlinked bin entries (node_modules/.bin/) resolve correctly.
const isMain = (() => { try { return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (isMain) (async () => {
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch (error) {
    logger.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }

  try {
    if (config.mode === 'stdio-static') {
      await runStdioStatic();
    } else {
      await runHttpServer(config);
    }
  } catch (error) {
    logger.error('Failed to start server', error);
    process.exit(1);
  }
})();
