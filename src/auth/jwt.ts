import { SignJWT, jwtVerify, generateKeyPair, exportJWK, importJWK, type JWTPayload } from 'jose';
import { randomUUID } from 'node:crypto';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { logger } from '../utils/logger.js';

let privateKey: CryptoKey | undefined;
let publicKey: CryptoKey | undefined;
let publicKeyJwk: Record<string, unknown> | undefined;
let keyId: string | undefined;

export async function initJwtKeys(privateKeyJwkJson?: string): Promise<void> {
  if (privateKeyJwkJson) {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(privateKeyJwkJson) as Record<string, unknown>;
    } catch {
      throw new Error('JWT_PRIVATE_KEY_JWK contains invalid JSON. Expected an EC P-256 private key in JWK format.');
    }
    if (typeof parsed.d !== 'string') {
      throw new Error('JWT_PRIVATE_KEY_JWK must be an EC P-256 private key JWK (missing "d" parameter). Supply the full private JWK, not just the public portion.');
    }
    try {
      privateKey = (await importJWK(parsed, 'ES256')) as CryptoKey;
      const { d: _d, ...pubJwk } = parsed;
      publicKey = (await importJWK(pubJwk, 'ES256')) as CryptoKey;
      keyId = typeof parsed.kid === 'string' ? parsed.kid : randomUUID();
      publicKeyJwk = { ...pubJwk, kid: keyId, use: 'sig', alg: 'ES256' };
    } catch {
      throw new Error('JWT_PRIVATE_KEY_JWK is not a valid EC P-256 private key JWK.');
    }
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
  issuer: string;
  expiresIn: string;
  scopes?: string[];
}): Promise<string> {
  if (!privateKey) throw new Error('JWT keys not initialized');

  return new SignJWT({ scope: (params.scopes ?? []).join(' ') })
    .setProtectedHeader({ alg: 'ES256', kid: keyId })
    .setSubject(params.subject)
    .setAudience(params.audience)
    .setIssuer(params.issuer)
    .setIssuedAt()
    .setExpirationTime(params.expiresIn)
    .setJti(randomUUID())
    .sign(privateKey);
}

export async function verifyAccessToken(token: string, audience: string, issuer: string): Promise<AuthInfo> {
  if (!publicKey) throw new Error('JWT keys not initialized');

  const { payload } = await jwtVerify(token, publicKey, { audience, issuer });
  const { sub, scope } = payload as JWTPayload & { scope?: string };

  if (!sub) throw new Error('Missing sub claim in JWT');

  const scopes = scope ? scope.split(' ').filter(Boolean) : [];
  return { token, clientId: sub, scopes };
}

export function getJwks(): { keys: unknown[] } {
  if (!publicKeyJwk) throw new Error('JWT keys not initialized');
  return { keys: [publicKeyJwk] };
}
