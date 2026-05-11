import type { SessionStore } from './store.js';
import type { McpCodeRecord, OAuthStateRecord, SessionRecord } from './types.js';

interface RefreshRecord {
  subject: string;
  expiresAt: number;
}

export class MemorySessionStore implements SessionStore {
  private sessions = new Map<string, SessionRecord>();
  private oauthStates = new Map<string, OAuthStateRecord>();
  private mcpCodes = new Map<string, McpCodeRecord>();
  private refreshTokens = new Map<string, RefreshRecord>();

  async getSession(subject: string): Promise<SessionRecord | undefined> {
    return this.sessions.get(subject);
  }

  async setSession(subject: string, record: SessionRecord): Promise<void> {
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
    this.mcpCodes.set(code, record);
  }

  async deleteMcpCode(code: string): Promise<void> {
    this.mcpCodes.delete(code);
  }

  async getRefreshToken(token: string): Promise<string | undefined> {
    const record = this.refreshTokens.get(token);
    if (!record) return undefined;
    if (Date.now() > record.expiresAt) {
      this.refreshTokens.delete(token);
      return undefined;
    }
    return record.subject;
  }

  async setRefreshToken(token: string, subject: string, expiresAt: number): Promise<void> {
    this.refreshTokens.set(token, { subject, expiresAt });
  }

  async deleteRefreshToken(token: string): Promise<void> {
    this.refreshTokens.delete(token);
  }
}
