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

// VERSION must be declared before `export const server = createServer()`
// because createServer() references it and const is not hoisted (TDZ).
const VERSION = '3.0.0';

// Backward-compatible singleton for programmatic consumers who imported
// `{ server }` from the previous version. Created eagerly at module
// evaluation time. The instance is unconnected — call
// server.connect(transport) to start it.
// NOTE: env vars are NOT loaded automatically here. Call dotenv.config()
// (or set env vars another way) before importing if you need .env support.
export const server = createServer();

/**
 * Create a pre-configured MCP Server instance using static tokens from env vars.
 * Returns an unconnected Server; call server.connect(transport) to start it.
 * Preserved for backward compatibility with programmatic usage.
 *
 * Does NOT call dotenv.config(). The CLI entry point handles env loading via
 * loadConfig(). Programmatic callers must set env vars themselves before calling.
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
  const { MemorySessionStore } = await import('./session/memory-store.js');
  const { startHttpServer } = await import('./server/http.js');

  const store = new MemorySessionStore();

  logger.info(`Social Analytics MCP Server v${VERSION} starting (${config.mode})`, {
    port: config.port,
    host: config.host,
  });

  await startHttpServer(config, store);
}

// Guard: only run the server when invoked directly as the CLI entry point.
// This prevents startup side effects when the package is imported programmatically.
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
