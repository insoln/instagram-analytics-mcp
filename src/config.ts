import { z } from 'zod';
import dotenv from 'dotenv';

export const ModeSchema = z.enum(['stdio-static', 'http-static', 'http-oauth']);
export type Mode = z.infer<typeof ModeSchema>;

const ConfigSchema = z
  .object({
    mode: ModeSchema.default('stdio-static'),
    port: z.coerce.number().int().min(1).max(65535).default(3000),
    host: z.string().default('0.0.0.0'),

    // Tokens for static modes
    instagramAccessToken: z.string().optional(),
    instagramAccountId: z.string().optional(),
    instagramApiVersion: z.string().default('v23.0'),
    facebookAccessToken: z.string().optional(),
    facebookPageId: z.string().optional(),
    facebookApiVersion: z.string().default('v23.0'),

    // Optional bearer key for http-static mode
    staticToken: z.string().optional(),

    // Required for http-oauth mode.
    // Must be an origin-only URL (no path/query/fragment) — paths would silently
    // break callback URIs, audience values, and OAuth discovery endpoints.
    serverUrl: z.string().url()
      .refine((u) => {
        try { const p = new URL(u); return (p.pathname === '/' || p.pathname === '') && !p.search && !p.hash; }
        catch { return false; }
      }, 'SERVER_URL must be an origin URL with no path, query, or fragment (e.g. https://example.com or https://example.com:3000)')
      .transform((u) => new URL(u).origin)
      .optional(),
    metaAppId: z.string().optional(),
    metaAppSecret: z.string().optional(),
    metaCallbackPath: z.string()
      .refine(
        (p) => !p.includes('://') && !p.includes('?') && !p.includes('#') && !p.includes('..'),
        'META_CALLBACK_PATH must be a plain path (e.g. /auth/callback) — no scheme, query string, fragment, or ".." segments'
      )
      .transform((p) => p.startsWith('/') ? p : `/${p}`)
      .default('/auth/meta/callback'),
    jwtPrivateKeyJwk: z.string().optional(),
    jwtExpiry: z.string().regex(/^\d+[smhd]$/, 'JWT_EXPIRY must be a number followed by s, m, h, or d (e.g. "1h", "30m")').default('1h'),
    refreshTokenExpirySeconds: z.coerce.number().int().positive().default(2592000), // 30 days

  })
  .superRefine((data, ctx) => {
    // http-static: SERVER_URL is optional. When omitted the server falls back to
    // localhost-only allowedHosts (DNS-rebinding protection still active, but
    // external clients that send a non-loopback Host header will be rejected).
    // Users who need external access must set SERVER_URL explicitly.
    if (data.mode === 'http-oauth') {
      if (!data.serverUrl) {
        ctx.addIssue({ code: 'custom', message: 'SERVER_URL is required in http-oauth mode', path: ['serverUrl'] });
      } else {
        const url = new URL(data.serverUrl);
        const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
        if (!isLoopback && url.protocol !== 'https:') {
          ctx.addIssue({ code: 'custom', message: 'SERVER_URL must use https:// in http-oauth mode (except localhost)', path: ['serverUrl'] });
        }
      }
      if (!data.metaAppId) {
        ctx.addIssue({ code: 'custom', message: 'META_APP_ID is required in http-oauth mode', path: ['metaAppId'] });
      }
      if (!data.metaAppSecret) {
        ctx.addIssue({
          code: 'custom',
          message: 'META_APP_SECRET is required in http-oauth mode',
          path: ['metaAppSecret'],
        });
      }
    }
  });

export type Config = z.infer<typeof ConfigSchema>;

function load(): Config {
  const raw: Record<string, unknown> = {
    mode: process.env.MCP_MODE,
    port: process.env.PORT,
    host: process.env.HOST,
    instagramAccessToken: process.env.INSTAGRAM_ACCESS_TOKEN,
    instagramAccountId: process.env.INSTAGRAM_ACCOUNT_ID,
    instagramApiVersion: process.env.INSTAGRAM_API_VERSION,
    facebookAccessToken: process.env.FACEBOOK_ACCESS_TOKEN,
    facebookPageId: process.env.FACEBOOK_PAGE_ID,
    facebookApiVersion: process.env.FACEBOOK_API_VERSION,
    staticToken: process.env.STATIC_TOKEN,
    serverUrl: process.env.SERVER_URL,
    metaAppId: process.env.META_APP_ID,
    metaAppSecret: process.env.META_APP_SECRET,
    metaCallbackPath: process.env.META_CALLBACK_PATH,
    jwtPrivateKeyJwk: process.env.JWT_PRIVATE_KEY_JWK,
    jwtExpiry: process.env.JWT_EXPIRY,
    refreshTokenExpirySeconds: process.env.REFRESH_TOKEN_EXPIRY_SECONDS,
  };

  const cleaned = Object.fromEntries(Object.entries(raw).filter(([, v]) => v !== undefined && v !== ''));
  const mode = cleaned.mode ?? 'stdio-static';
  // Strip fields irrelevant to the resolved mode so strict validators
  // (SERVER_URL origin check, JWT_EXPIRY regex, port coercion, etc.) never
  // throw on unrelated env vars present in generic deployment environments.
  // Keys that are only meaningful in http-oauth mode.
  // serverUrl is intentionally kept in http-static (not in OAUTH_ONLY_KEYS) so
  // that an explicitly configured SERVER_URL is used for allowedHosts validation.
  const OAUTH_ONLY_KEYS = ['metaAppId', 'metaAppSecret', 'metaCallbackPath',
    'jwtPrivateKeyJwk', 'jwtExpiry', 'refreshTokenExpirySeconds'];
  if (mode === 'stdio-static') {
    for (const key of ['port', 'host', 'staticToken', 'serverUrl', ...OAUTH_ONLY_KEYS]) delete cleaned[key];
  } else if (mode === 'http-static') {
    for (const key of OAUTH_ONLY_KEYS) delete cleaned[key];
  }
  const result = ConfigSchema.safeParse(cleaned);

  if (!result.success) {
    const messages = result.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid configuration:\n${messages}`);
  }

  return result.data;
}

export function loadConfig(): Config {
  // Load .env file if present — idempotent, no-op if already loaded or vars already set.
  // Callers who manage env vars themselves (e.g. K8s, Docker) are unaffected.
  dotenv.config();
  return load();
}
