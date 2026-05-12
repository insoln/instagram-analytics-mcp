export interface SessionRecord {
  subject: string; // "fb_<facebook_user_id>"
  metaAccessToken: string;
  metaTokenExpiresAt: number; // Unix ms
  fbUserId: string;
}

// Short-lived: stores PKCE + client info during Meta OAuth redirect (keyed by state param)
export interface OAuthStateRecord {
  codeChallenge: string;
  redirectUri: string;
  clientId: string;
  scopes: string[];
  resource?: string;
  clientState?: string;
  expiresAt: number; // Unix ms
}

// Short-lived: links MCP authorization code to subject + PKCE challenge (keyed by mcp code)
export interface McpCodeRecord {
  subject: string;
  codeChallenge: string;
  clientId: string;
  scopes: string[];
  resource?: string;
  expiresAt: number; // Unix ms
}
