import axios from 'axios';

const metaHttp = axios.create({ timeout: 10_000 });

// Facebook Login endpoints — issues Facebook Graph API tokens compatible with
// graph.facebook.com. Clients (InstagramClient, FacebookClient) require Graph
// API tokens, not Instagram Login (api.instagram.com) tokens.
const FB_AUTHORIZE_URL = 'https://www.facebook.com/dialog/oauth';
const FB_TOKEN_URL = 'https://graph.facebook.com/v23.0/oauth/access_token';
const FB_ME_URL = 'https://graph.facebook.com/v23.0/me';

// Scopes required to access both Instagram Business accounts and Facebook pages
// via the Graph API (same permissions as the static-token setup instructions).
const DEFAULT_SCOPES = [
  'pages_show_list',
  'pages_read_engagement',
  'instagram_basic',
  'instagram_manage_insights',
  'read_insights',
  'business_management',
];

export function buildMetaAuthorizationUrl(params: {
  appId: string;
  redirectUri: string;
  state: string;
  scopes?: string[];
}): string {
  const scopes = params.scopes ?? DEFAULT_SCOPES;
  const url = new URL(FB_AUTHORIZE_URL);
  url.searchParams.set('client_id', params.appId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', scopes.join(','));
  url.searchParams.set('state', params.state);
  return url.toString();
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
}

export async function exchangeMetaCode(params: {
  code: string;
  appId: string;
  appSecret: string;
  redirectUri: string;
}): Promise<{ accessToken: string; userId: string }> {
  const response = await metaHttp.get<TokenResponse>(FB_TOKEN_URL, {
    params: {
      client_id: params.appId,
      client_secret: params.appSecret,
      redirect_uri: params.redirectUri,
      code: params.code,
    },
  });

  const { access_token } = response.data;
  if (!access_token) throw new Error('No access_token in Facebook token response');

  const userId = await fetchFacebookUserId(access_token);
  return { accessToken: access_token, userId };
}

async function fetchFacebookUserId(accessToken: string): Promise<string> {
  const response = await metaHttp.get<{ id: string }>(FB_ME_URL, {
    params: { access_token: accessToken, fields: 'id' },
  });
  return response.data.id;
}

export async function exchangeForLongLivedToken(params: {
  shortLivedToken: string;
  appId: string;
  appSecret: string;
}): Promise<{ accessToken: string; expiresIn: number }> {
  // Facebook long-lived tokens (~60 days) via fb_exchange_token grant.
  const response = await metaHttp.get<TokenResponse>(FB_TOKEN_URL, {
    params: {
      grant_type: 'fb_exchange_token',
      client_id: params.appId,
      client_secret: params.appSecret,
      fb_exchange_token: params.shortLivedToken,
    },
  });

  const { access_token, expires_in } = response.data;
  if (!access_token) throw new Error('No access_token in long-lived token response');
  return { accessToken: access_token, expiresIn: expires_in ?? 5183944 }; // ~60 days
}

export async function refreshLongLivedToken(params: {
  accessToken: string;
  appId: string;
  appSecret: string;
}): Promise<{ accessToken: string; expiresIn: number }> {
  // Refresh a Facebook long-lived token before it expires by re-exchanging it.
  const response = await metaHttp.get<TokenResponse>(FB_TOKEN_URL, {
    params: {
      grant_type: 'fb_exchange_token',
      client_id: params.appId,
      client_secret: params.appSecret,
      fb_exchange_token: params.accessToken,
    },
  });

  const { access_token, expires_in } = response.data;
  if (!access_token) throw new Error('No access_token in token refresh response');
  return { accessToken: access_token, expiresIn: expires_in ?? 5183944 };
}

// Returns true if the stored token should be refreshed (within 7 days of expiry)
export function isMetaTokenStale(expiresAt: number): boolean {
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
  return Date.now() > expiresAt - sevenDaysMs;
}
