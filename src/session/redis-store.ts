import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Redis } from 'ioredis';
import type { SessionStore } from './store.js';
import type { McpCodeRecord, OAuthStateRecord, SessionRecord } from './types.js';

const ALGO = 'aes-256-gcm' as const;
const IV_BYTES = 12;  // 96-bit IV (GCM standard)
const TAG_BYTES = 16;

const TTL_SESSION_MAX_S = 60 * 24 * 60 * 60;  // 60 days hard cap
const TTL_SESSION_GRACE_S = 7 * 24 * 60 * 60; // 7-day grace after token expiry
const TTL_OAUTH_STATE_S = 10 * 60;
const TTL_MCP_CODE_S = 5 * 60;
const TTL_REFRESH_TOKEN_MAX_S = 30 * 24 * 60 * 60;

const KEY_PREFIX = 'social-analytics';

function redisKey(type: 'sess' | 'ostate' | 'mcpcode' | 'rtoken', id: string): string {
  return `${KEY_PREFIX}:${type}:${id}`;
}

export class RedisSessionStore implements SessionStore {
  private readonly redis: InstanceType<typeof Redis>;
  private readonly encKey: Buffer;

  /**
   * @param redisUrl  ioredis connection URL, e.g. "redis://localhost:6379"
   * @param encryptionKeyHex  32-byte AES-256-GCM key encoded as 64 lowercase hex chars.
   *   Required: Meta access tokens must never be stored in plaintext.
   */
  constructor(redisUrl: string, encryptionKeyHex: string) {
    if (!/^[0-9a-fA-F]{64}$/.test(encryptionKeyHex)) {
      throw new Error('TOKEN_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
    }
    this.encKey = Buffer.from(encryptionKeyHex, 'hex');
    this.redis = new Redis(redisUrl, { enableOfflineQueue: false });
  }

  async ping(): Promise<void> {
    await this.redis.ping();
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }

  // --- Encryption helpers ---------------------------------------------------

  private encrypt(plaintext: string): string {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGO, this.encKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = (cipher as ReturnType<typeof createCipheriv> & { getAuthTag(): Buffer }).getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${ciphertext.toString('hex')}`;
  }

  private decrypt(stored: string): string {
    const parts = stored.split(':');
    if (parts.length !== 3) throw new Error('Encrypted value has unexpected format');
    const [ivHex, tagHex, ctHex] = parts;
    const decipher = createDecipheriv(ALGO, this.encKey, Buffer.from(ivHex, 'hex'));
    (decipher as ReturnType<typeof createDecipheriv> & { setAuthTag(tag: Buffer): void })
      .setAuthTag(Buffer.from(tagHex, 'hex'));
    return (
      decipher.update(Buffer.from(ctHex, 'hex'), undefined, 'utf8') +
      decipher.final('utf8')
    );
  }

  private ser<T>(value: T): string { return this.encrypt(JSON.stringify(value)); }
  private de<T>(stored: string): T { return JSON.parse(this.decrypt(stored)) as T; }

  // --- SessionStore impl ----------------------------------------------------

  async getSession(subject: string): Promise<SessionRecord | undefined> {
    const raw = await this.redis.get(redisKey('sess', subject));
    return raw ? this.de<SessionRecord>(raw) : undefined;
  }

  async setSession(subject: string, record: SessionRecord): Promise<void> {
    const graceExpiry = record.metaTokenExpiresAt + TTL_SESSION_GRACE_S * 1000;
    const ttlS = Math.min(
      Math.max(1, Math.ceil((graceExpiry - Date.now()) / 1000)),
      TTL_SESSION_MAX_S,
    );
    await this.redis.setex(redisKey('sess', subject), ttlS, this.ser(record));
  }

  async deleteSession(subject: string): Promise<void> {
    await this.redis.del(redisKey('sess', subject));
  }

  async getOAuthState(state: string): Promise<OAuthStateRecord | undefined> {
    const raw = await this.redis.get(redisKey('ostate', state));
    return raw ? this.de<OAuthStateRecord>(raw) : undefined;
  }

  async setOAuthState(state: string, record: OAuthStateRecord): Promise<void> {
    await this.redis.setex(redisKey('ostate', state), TTL_OAUTH_STATE_S, this.ser(record));
  }

  async deleteOAuthState(state: string): Promise<void> {
    await this.redis.del(redisKey('ostate', state));
  }

  async getMcpCode(code: string): Promise<McpCodeRecord | undefined> {
    const raw = await this.redis.get(redisKey('mcpcode', code));
    return raw ? this.de<McpCodeRecord>(raw) : undefined;
  }

  async setMcpCode(code: string, record: McpCodeRecord): Promise<void> {
    await this.redis.setex(redisKey('mcpcode', code), TTL_MCP_CODE_S, this.ser(record));
  }

  async deleteMcpCode(code: string): Promise<void> {
    await this.redis.del(redisKey('mcpcode', code));
  }

  async getRefreshToken(token: string): Promise<{ subject: string; clientId: string; scopes: string[] } | undefined> {
    const raw = await this.redis.get(redisKey('rtoken', token));
    return raw ? this.de<{ subject: string; clientId: string; scopes: string[] }>(raw) : undefined;
  }

  async setRefreshToken(token: string, subject: string, clientId: string, scopes: string[], expiresAt: number): Promise<void> {
    const ttlS = Math.min(
      Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000)),
      TTL_REFRESH_TOKEN_MAX_S,
    );
    await this.redis.setex(redisKey('rtoken', token), ttlS, this.ser({ subject, clientId, scopes }));
  }

  async deleteRefreshToken(token: string): Promise<void> {
    await this.redis.del(redisKey('rtoken', token));
  }
}
