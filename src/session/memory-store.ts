import type { SessionStore } from './store.js';
import type { McpCodeRecord, OAuthStateRecord, SessionRecord } from './types.js';

// Sessions whose Meta token expired more than SESSION_GRACE_MS ago are considered
// permanently stale (token can no longer be refreshed via the 60-day window).
const SESSION_MAX = 10_000;
const SESSION_GRACE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// Size caps for short-lived maps. Entries are also swept by sweepExpired() on
// every write. Caps bound memory growth from high-frequency OAuth flows or DoS.
const OAUTH_STATE_MAX = 5_000;
const MCP_CODE_MAX = 5_000;
const REFRESH_TOKEN_MAX = 100_000;

interface RefreshRecord {
  subject: string;
  clientId: string;
  scopes: string[];
  expiresAt: number;
}

export class MemorySessionStore implements SessionStore {
  private sessions = new Map<string, SessionRecord>();
  private oauthStates = new Map<string, OAuthStateRecord>();
  private mcpCodes = new Map<string, McpCodeRecord>();
  private refreshTokens = new Map<string, RefreshRecord>();
  private sweepTimer: ReturnType<typeof setInterval> | undefined;

  /**
   * @param sweepIntervalMs How often to purge expired entries in the background.
   *   Defaults to 5 minutes. Pass 0 to disable the timer (useful in tests).
   *   Memory is still bounded by the per-map size caps regardless of sweep frequency.
   */
  constructor(sweepIntervalMs = 5 * 60 * 1000) {
    if (sweepIntervalMs > 0) {
      // .unref() so the timer doesn't prevent process exit.
      this.sweepTimer = setInterval(() => this.sweepExpired(), sweepIntervalMs).unref();
    }
  }

  stopSweep(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = undefined;
    }
  }

  // Purge expired entries from all maps. Called periodically by the background
  // timer. Per-read lazy expiry (in get* methods) handles individual lookups.
  // Size caps in set* methods bound memory growth between sweeps.
  private sweepExpired(): void {
    const now = Date.now();
    for (const [k, v] of this.oauthStates) if (now > v.expiresAt) this.oauthStates.delete(k);
    for (const [k, v] of this.mcpCodes) if (now > v.expiresAt) this.mcpCodes.delete(k);
    for (const [k, v] of this.refreshTokens) if (now > v.expiresAt) this.refreshTokens.delete(k);
    for (const [k, v] of this.sessions) if (now > v.metaTokenExpiresAt + SESSION_GRACE_MS) this.sessions.delete(k);
  }

  async getSession(subject: string): Promise<SessionRecord | undefined> {
    const record = this.sessions.get(subject);
    if (!record) return undefined;
    if (Date.now() > record.metaTokenExpiresAt + SESSION_GRACE_MS) {
      this.sessions.delete(subject);
      return undefined;
    }
    return record;
  }

  async setSession(subject: string, record: SessionRecord): Promise<void> {
    // Evict oldest entry only when inserting a new subject (not updating an existing one).
    if (!this.sessions.has(subject) && this.sessions.size >= SESSION_MAX) {
      this.sessions.delete(this.sessions.keys().next().value!);
    }
    this.sessions.set(subject, record);
  }

  async deleteSession(subject: string): Promise<void> {
    this.sessions.delete(subject);
  }

  async getOAuthState(state: string): Promise<OAuthStateRecord | undefined> {
    const record = this.oauthStates.get(state);
    if (!record) return undefined;
    if (Date.now() > record.expiresAt) {
      this.oauthStates.delete(state);
      return undefined;
    }
    return record;
  }

  async setOAuthState(state: string, record: OAuthStateRecord): Promise<void> {
    if (!this.oauthStates.has(state) && this.oauthStates.size >= OAUTH_STATE_MAX) {
      this.oauthStates.delete(this.oauthStates.keys().next().value!);
    }
    this.oauthStates.set(state, record);
  }

  async deleteOAuthState(state: string): Promise<void> {
    this.oauthStates.delete(state);
  }

  async getMcpCode(code: string): Promise<McpCodeRecord | undefined> {
    const record = this.mcpCodes.get(code);
    if (!record) return undefined;
    if (Date.now() > record.expiresAt) {
      this.mcpCodes.delete(code);
      return undefined;
    }
    return record;
  }

  async setMcpCode(code: string, record: McpCodeRecord): Promise<void> {
    if (!this.mcpCodes.has(code) && this.mcpCodes.size >= MCP_CODE_MAX) {
      this.mcpCodes.delete(this.mcpCodes.keys().next().value!);
    }
    this.mcpCodes.set(code, record);
  }

  async deleteMcpCode(code: string): Promise<void> {
    this.mcpCodes.delete(code);
  }

  async getRefreshToken(token: string): Promise<{ subject: string; clientId: string; scopes: string[] } | undefined> {
    const record = this.refreshTokens.get(token);
    if (!record) return undefined;
    if (Date.now() > record.expiresAt) {
      this.refreshTokens.delete(token);
      return undefined;
    }
    return { subject: record.subject, clientId: record.clientId, scopes: record.scopes };
  }

  async setRefreshToken(token: string, subject: string, clientId: string, scopes: string[], expiresAt: number): Promise<void> {
    if (!this.refreshTokens.has(token) && this.refreshTokens.size >= REFRESH_TOKEN_MAX) {
      this.refreshTokens.delete(this.refreshTokens.keys().next().value!);
    }
    this.refreshTokens.set(token, { subject, clientId, scopes, expiresAt });
  }

  async deleteRefreshToken(token: string): Promise<void> {
    this.refreshTokens.delete(token);
  }
}
