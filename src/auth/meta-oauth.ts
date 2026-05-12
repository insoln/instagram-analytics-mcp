import axios from 'axios';

const metaHttp = axios.create({ timeout: 10_000 });

const IG_AUTHORIZE_URL = 'https://www.instagram.com/oauth/authorize';
const IG_TOKEN_URL = 'https://api.instagram.com/oauth/access_token';
const IG_LONG_LIVED_URL = 'https://graph.instagram.com/access_token';
const IG_REFRESH_URL = 'https://graph.instagram.com/refresh_access_token';
const IG_ME_URL = 'https://graph.instagram.com/me';

// Scopes needed for analytics + basic profile
const DEFAULT_SCOPES = ['instagram_business_basic', 'instagram_business_manage_insights'];

export function buildMetaAuthorizationUrl(params: {
  appId: string;
  redirectUri: string;
  state: string;
  scopes?: string[];
}): string {
  const scopes = params.scopes ?? DEFAULT_SCOPES;
  const url = new URL(IG_AUTHORIZE_URL);
  url.searchParams.set('client_id', params.appId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', scopes.join(','));
  url.searchParams.set('state', params.state);
  return url.toString();
}

interface ShortLivedTokenResponse {
  access_token: string;
  token_type: string;
  user_id?: string | number;
}

export async function exchangeMetaCode(params: {
  code: string;
  appId: string;
  appSecret: string;
  redirectUri: string;
}): Promise<{ accessToken: string; userId: string }> {
  const body = new URLSearchParams({
    client_id: params.appId,
    client_secret: params.appSecret,
    grant_type: 'authorization_code',
    redirect_uri: params.redirectUri,
    code: params.code,
  });

  const response = await metaHttp.post<ShortLivedTokenResponse>(IG_TOKEN_URL, body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const { access_token, user_id } = response.data;
  if (!access_token) throw new Error('No access_token in Meta token response');

  // user_id may come back as a number
  const userId = user_id !== undefined ? String(user_id) : await fetchMetaUserId(access_token);
  return { accessToken: access_token, userId };
}

async function fetchMetaUserId(accessToken: string): Promise<string> {
  const response = await metaHttp.get<{ id: string }>(IG_ME_URL, {
    params: { access_token: accessToken, fields: 'id' },
  });
  return response.data.id;
}

interface LongLivedTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export async function exchangeForLongLivedToken(params: {
  shortLivedToken: string;
  appSecret: string;
}): Promise<{ accessToken: string; expiresIn: number }> {
  const response = await metaHttp.get<LongLivedTokenResponse>(IG_LONG_LIVED_URL, {
    params: {
      grant_type: 'ig_exchange_token',
      client_secret: params.appSecret,
      access_token: params.shortLivedToken,
    },
  });

  const { access_token, expires_in } = response.data;
  if (!access_token) throw new Error('No access_token in long-lived token response');
  return { accessToken: access_token, expiresIn: expires_in };
}

export async function refreshLongLivedToken(accessToken: string): Promise<{ accessToken: string; expiresIn: number }> {
  const response = await metaHttp.get<LongLivedTokenResponse>(IG_REFRESH_URL, {
    params: {
      grant_type: 'ig_refresh_token',
      access_token: accessToken,
    },
  });

  const { access_token, expires_in } = response.data;
  if (!access_token) throw new Error('No access_token in token refresh response');
  return { accessToken: access_token, expiresIn: expires_in };
}

// Returns true if the stored token should be refreshed (within 7 days of expiry)
export function isMetaTokenStale(expiresAt: number): boolean {
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
  return Date.now() > expiresAt - sevenDaysMs;
}
