import type { McpCodeRecord, OAuthStateRecord, SessionRecord } from './types.js';

export interface SessionStore {
  // Long-lived Meta token records, keyed by subject ("fb_<userId>")
  getSession(subject: string): Promise<SessionRecord | undefined>;
  setSession(subject: string, record: SessionRecord): Promise<void>;
  deleteSession(subject: string): Promise<void>;

  // Short-lived OAuth state during Meta redirect, keyed by state param
  getOAuthState(state: string): Promise<OAuthStateRecord | undefined>;
  setOAuthState(state: string, record: OAuthStateRecord): Promise<void>;
  deleteOAuthState(state: string): Promise<void>;

  // Short-lived MCP authorization codes, keyed by the code value
  getMcpCode(code: string): Promise<McpCodeRecord | undefined>;
  setMcpCode(code: string, record: McpCodeRecord): Promise<void>;
  deleteMcpCode(code: string): Promise<void>;

  // Refresh tokens: opaque string → {subject, clientId, scopes} (long-lived, rotated on use)
  getRefreshToken(token: string): Promise<{ subject: string; clientId: string; scopes: string[] } | undefined>;
  /** expiresAt: Unix timestamp in milliseconds (Date.now() + TTL) */
  setRefreshToken(token: string, subject: string, clientId: string, scopes: string[], expiresAt: number): Promise<void>;
  deleteRefreshToken(token: string): Promise<void>;

  /** Optional: stop background sweep timers for clean shutdown/testing. */
  stopSweep?(): void;
}
