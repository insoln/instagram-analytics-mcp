import { SignJWT, jwtVerify, generateKeyPair, exportJWK, importJWK, type JWTPayload } from 'jose';
import { randomUUID } from 'node:crypto';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { logger } from '../utils/logger.js';

let privateKey: CryptoKey;
let publicKey: CryptoKey;
let publicKeyJwk: Record<string, unknown>;
let keyId: string;

export async function initJwtKeys(privateKeyJwkJson?: string): Promise<void> {
  if (privateKeyJwkJson) {
    const parsed = JSON.parse(privateKeyJwkJson) as Record<string, unknown>;
    privateKey = (await importJWK(parsed, 'ES256')) as CryptoKey;
    // Derive public key by stripping private fields
    const { d: _d, ...pubJwk } = parsed;
    publicKey = (await importJWK(pubJwk, 'ES256')) as CryptoKey;
    keyId = (parsed.kid as string) ?? randomUUID();
    publicKeyJwk = { ...pubJwk, kid: keyId };
    logger.info('JWT: loaded key from JWT_PRIVATE_KEY_JWK');
  } else {
    const pair = await generateKeyPair('ES256');
    privateKey = pair.privateKey as CryptoKey;
    publicKey = pair.publicKey as CryptoKey;
    keyId = randomUUID();
    publicKeyJwk = { ...(await exportJWK(publicKey)), kid: keyId, use: 'sig', alg: 'ES256' };
    logger.warn('JWT: using ephemeral key — tokens will be invalidated on restart. Set JWT_PRIVATE_KEY_JWK for persistence.');
  }
}

export async function signAccessToken(params: {
  subject: string;
  audience: string;
  expiresIn: string;
  scopes?: string[];
}): Promise<string> {
  if (!privateKey) throw new Error('JWT keys not initialized');

  return new SignJWT({ scope: (params.scopes ?? []).join(' ') })
    .setProtectedHeader({ alg: 'ES256', kid: keyId })
    .setSubject(params.subject)
    .setAudience(params.audience)
    .setIssuedAt()
    .setExpirationTime(params.expiresIn)
    .setJti(randomUUID())
    .sign(privateKey);
}

export async function verifyAccessToken(token: string, audience: string): Promise<AuthInfo> {
  if (!publicKey) throw new Error('JWT keys not initialized');

  const { payload } = await jwtVerify(token, publicKey, { audience });
  const { sub, scope } = payload as JWTPayload & { scope?: string };

  if (!sub) throw new Error('Missing sub claim in JWT');

  const scopes = scope ? scope.split(' ').filter(Boolean) : [];
  return { token, clientId: sub, scopes };
}

export function getJwks(): { keys: unknown[] } {
  return { keys: [publicKeyJwk] };
}
