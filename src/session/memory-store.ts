import type { SessionStore } from './store.js';
import type { McpCodeRecord, OAuthStateRecord, SessionRecord } from './types.js';

// Sessions whose Meta token expired more than SESSION_GRACE_MS ago are considered
// permanently stale (token can no longer be refreshed via the 60-day window).
const SESSION_MAX = 10_000;
const SESSION_GRACE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

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

  // Sweep expired entries on every write to prevent unbounded growth.
  // Short-lived records (states, codes, refresh tokens) are swept on expiry.
  // Sessions are swept after metaTokenExpiresAt + SESSION_GRACE_MS to allow
  // one last token-refresh attempt before eviction.
  private sweepExpired(): void {
    const now = Date.now();
    for (const [k, v] of this.oauthStates) if (now > v.expiresAt) this.oauthStates.delete(k);
    for (const [k, v] of this.mcpCodes) if (now > v.expiresAt) this.mcpCodes.delete(k);
    for (const [k, v] of this.refreshTokens) if (now > v.expiresAt) this.refreshTokens.delete(k);
    for (const [k, v] of this.sessions) if (now > v.metaTokenExpiresAt + SESSION_GRACE_MS) this.sessions.delete(k);
  }

  async getSession(subject: string): Promise<SessionRecord | undefined> {
    return this.sessions.get(subject);
  }

  async setSession(subject: string, record: SessionRecord): Promise<void> {
    this.sweepExpired();
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
    this.sweepExpired();
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
    this.sweepExpired();
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
    this.sweepExpired();
    this.refreshTokens.set(token, { subject, clientId, scopes, expiresAt });
  }

  async deleteRefreshToken(token: string): Promise<void> {
    this.refreshTokens.delete(token);
  }
}
