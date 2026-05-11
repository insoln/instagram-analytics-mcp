#!/usr/bin/env node

/**
 * Social Analytics MCP Server
 * Supports three modes via MCP_MODE env var:
 *   stdio-static (default) — stdin/stdout transport, token from env
 *   http-static            — HTTP transport, token from env
 *   http-oauth             — HTTP transport, Meta OAuth 2.1 multi-tenant
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { config } from './config.js';
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

const VERSION = '3.0.0';

async function runStdioStatic(): Promise<void> {
  const instagramClient = config.instagramAccessToken
    ? new InstagramClient({
        accessToken: config.instagramAccessToken,
        accountId: config.instagramAccountId,
        apiVersion: config.instagramApiVersion,
      })
    : null;

  const facebookClient = config.facebookAccessToken
    ? new FacebookClient({
        accessToken: config.facebookAccessToken,
        pageId: config.facebookPageId,
        defaultApiVersion: config.facebookApiVersion,
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

  const transport = new StdioServerTransport();

  logger.info(`Social Analytics MCP Server v${VERSION} starting (stdio-static)`, {
    instagram: !!instagramClient,
    facebook: !!facebookClient,
  });

  await server.connect(transport);
}

async function runHttpServer(): Promise<void> {
  const { MemorySessionStore } = await import('./session/memory-store.js');
  const { startHttpServer } = await import('./server/http.js');

  const store = new MemorySessionStore();

  logger.info(`Social Analytics MCP Server v${VERSION} starting (${config.mode})`, {
    port: config.port,
    host: config.host,
  });

  await startHttpServer(config, store);
}

// Entry point
(async () => {
  try {
    if (config.mode === 'stdio-static') {
      await runStdioStatic();
    } else {
      await runHttpServer();
    }
  } catch (error) {
    logger.error('Failed to start server', error);
    process.exit(1);
  }
})();
