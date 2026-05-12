/**
 * Facebook Graph API Client
 * Handles all API requests to Facebook Graph API
 */

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { createHash } from 'node:crypto';
import { requestWithRetry } from '../../utils/retry.js';
import { FacebookApiError } from '../../utils/errors.js';
import { logger } from '../../utils/logger.js';
import type { NormalizedError } from '../../utils/errors.js';
import {
  FacebookConfig,
  PageInsightsParams,
  PageInsightsResult,
  PostInsightsParams,
  ListPostsWithInsightsParams,
  PostsWithInsightsResponse,
  KnownMetricsResponse,
  ValidateTokenParams,
  ValidateTokenResult,
  InsightsResponse,
  GraphApiError,
  KnownMetric,
  ListPagesResponse,
  PageDetails,
  PageFeedResponse,
} from './types.js';

const GRAPH_API_BASE_URL = 'https://graph.facebook.com';
const DEFAULT_API_VERSION = 'v22.0';
const DEFAULT_POST_FIELDS = 'message,created_time,permalink_url';

const KNOWN_PAGE_METRICS: KnownMetric[] = [
  { name: 'page_impressions', periods: ['day', 'week', 'days_28'] },
  { name: 'page_impressions_unique', periods: ['day', 'week', 'days_28'] },
  { name: 'page_engaged_users', periods: ['day', 'week', 'days_28'] },
  { name: 'page_post_engagements', periods: ['day', 'week', 'days_28'] },
  { name: 'page_views_total', periods: ['day', 'week', 'days_28'] },
  { name: 'page_fans', periods: ['day', 'week', 'days_28', 'lifetime'] },
  { name: 'page_fan_adds_unique', periods: ['day', 'week', 'days_28', 'lifetime'], notes: 'Requires period when not lifetime' },
];

const KNOWN_POST_METRICS: KnownMetric[] = [
  { name: 'post_impressions', periods: ['day', 'week', 'days_28'] },
  { name: 'post_impressions_unique', periods: ['day', 'week', 'days_28'] },
  { name: 'post_engaged_users', periods: ['day', 'week', 'days_28'] },
];

const PAGE_TOKEN_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const PAGE_TOKEN_CACHE_MAX = 500;

interface PageTokenEntry {
  token: string;
  expiresAt: number;
}

function pageTokenCacheKey(pageId: string, userToken: string): string {
  return createHash('sha256').update(`${pageId}:${userToken}`).digest('hex').slice(0, 32);
}

export class FacebookClient {
  private readonly axiosInstance: AxiosInstance;
  private readonly config: FacebookConfig;
  // Keyed by hash(pageId + userToken) to avoid storing raw tokens as Map keys.
  // TTL-bounded (1h) and capped at 500 entries to prevent unbounded growth.
  private readonly pageTokenCache = new Map<string, PageTokenEntry>();
  // In-flight fetch promises keyed by cacheKey. Coalesces concurrent requests
  // for the same page token so only one Graph API call is made per key.
  private readonly inFlightFetches = new Map<string, Promise<string>>();

  constructor(config: FacebookConfig) {
    this.config = config;
    this.axiosInstance = axios.create({
      baseURL: GRAPH_API_BASE_URL,
    });

    logger.debug('Facebook client initialized', {
      apiVersion: config.defaultApiVersion || DEFAULT_API_VERSION,
    });
  }

  // Returns a valid Page Access Token for the given page, fetching and caching
  // it if absent or expired. Page-level API endpoints reject User Access Tokens.
  // Concurrent calls for the same key share a single in-flight fetch so only
  // one Graph API call is made regardless of how many requests arrive at once.
  // Retry/invalidation on token errors is handled by the caller (withPageToken).
  private async resolvePageToken(pageId: string, userToken: string, apiVersion: string): Promise<string> {
    const cacheKey = pageTokenCacheKey(pageId, userToken);
    const cached = this.pageTokenCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) return cached.token;

    const existing = this.inFlightFetches.get(cacheKey);
    if (existing) return existing;

    const fetch = this.fetchPageToken(pageId, userToken, apiVersion).then((token) => {
      this.inFlightFetches.delete(cacheKey);
      this.storeCachedToken(cacheKey, token);
      return token;
    }).catch((err) => {
      this.inFlightFetches.delete(cacheKey);
      throw err;
    });

    this.inFlightFetches.set(cacheKey, fetch);
    return fetch;
  }

  private async fetchPageToken(pageId: string, userToken: string, apiVersion: string): Promise<string> {
    const data = await this.request<{ access_token?: string; id?: string }>({
      method: 'GET',
      url: this.buildPath(apiVersion, pageId),
      params: { fields: 'access_token', access_token: userToken },
    });

    if (!data.access_token) {
      throw new FacebookApiError({
        code: 'OAUTH',
        message: `Could not retrieve Page Access Token for page ${pageId}`,
        raw: { pageId, fields: 'access_token', response: data },
      });
    }
    return data.access_token;
  }

  private invalidatePageToken(pageId: string, userToken: string): void {
    this.pageTokenCache.delete(pageTokenCacheKey(pageId, userToken));
  }

  // Single place that writes to pageTokenCache — enforces the eviction guard
  // so neither resolvePageToken nor the withPageToken retry can bypass it.
  // When at capacity, expired entries are preferred for eviction over still-valid
  // ones; FIFO is only used as a fallback when no expired entry is found.
  private storeCachedToken(cacheKey: string, token: string): void {
    if (!this.pageTokenCache.has(cacheKey) && this.pageTokenCache.size >= PAGE_TOKEN_CACHE_MAX) {
      const now = Date.now();
      let evicted = false;
      for (const [k, v] of this.pageTokenCache) {
        if (now >= v.expiresAt) {
          this.pageTokenCache.delete(k);
          evicted = true;
          break;
        }
      }
      if (!evicted) {
        this.pageTokenCache.delete(this.pageTokenCache.keys().next().value!);
      }
    }
    this.pageTokenCache.set(cacheKey, { token, expiresAt: Date.now() + PAGE_TOKEN_CACHE_TTL_MS });
  }

  // Resolves a page token, runs fn, and retries once with a fresh token if the
  // page token is invalid or expired (OAUTH / subcode TOKEN — graph code 190
  // with no specific error_subcode).  More specific subcodes (PERMISSION,
  // numeric Meta subcodes for revoked/expired user tokens) are not retried
  // because a fresh page token will not resolve them.
  // Note: if multiple coalesced callers all receive the same invalid token and
  // each enters the retry path, each issues its own fresh fetchPageToken call.
  // This is an acceptable edge case — the results are correct and the extra
  // calls are bounded by the number of concurrent waiters (typically very small).
  private async withPageToken<T>(
    pageId: string,
    userToken: string,
    apiVersion: string,
    fn: (pageToken: string) => Promise<T>
  ): Promise<T> {
    const pageToken = await this.resolvePageToken(pageId, userToken, apiVersion);
    try {
      return await fn(pageToken);
    } catch (err) {
      const isTokenError =
        err instanceof FacebookApiError &&
        err.normalized.code === 'OAUTH' &&
        err.normalized.subcode === 'TOKEN';
      if (isTokenError) {
        this.invalidatePageToken(pageId, userToken);
        const freshToken = await this.fetchPageToken(pageId, userToken, apiVersion);
        this.storeCachedToken(pageTokenCacheKey(pageId, userToken), freshToken);
        return fn(freshToken);
      }
      throw err;
    }
  }

  async getPageInsights(params: PageInsightsParams): Promise<PageInsightsResult> {
    const pageId = params.pageId || this.config.pageId;
    if (!pageId) {
      throw new FacebookApiError({ code: 'OAUTH', message: 'page_id is required', raw: null });
    }

    if (!params.metrics || params.metrics.length === 0) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'At least one metric is required', raw: null });
    }

    const apiVersion = this.resolveApiVersion(params.apiVersion);
    const userToken = this.resolveAccessToken(params.accessToken);

    return this.withPageToken(pageId, userToken, apiVersion, async (accessToken) => {
      const query: Record<string, string> = {
        metric: params.metrics.join(','),
        access_token: accessToken,
      };

      if (params.period) query.period = params.period;
      if (params.since) query.since = params.since;
      if (params.until) query.until = params.until;
      if (typeof params.limit === 'number') query.limit = String(params.limit);
      if (params.after) query.after = params.after;
      if (params.before) query.before = params.before;

      const data = await this.request<InsightsResponse>({
        method: 'GET',
        url: this.buildPath(apiVersion, `${pageId}/insights`),
        params: query,
      });

      const warnings: string[] = [];
      if (!params.period) {
        warnings.push('No period provided. Some metrics may require a period parameter.');
      }

      const result: PageInsightsResult = { data: data.data, paging: data.paging };
      if (warnings.length > 0) result.warnings = warnings;
      return result;
    });
  }

  async getPostInsights(params: PostInsightsParams): Promise<InsightsResponse> {
    if (!params.postId) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'post_id is required', raw: null });
    }

    if (!params.metrics || params.metrics.length === 0) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'At least one metric is required', raw: null });
    }

    const apiVersion = this.resolveApiVersion(params.apiVersion);
    const userToken = this.resolveAccessToken(params.accessToken);
    // Post IDs are in format pageId_postId — extract pageId to get the page token.
    const derivedPageId = params.postId.includes('_')
      ? params.postId.split('_')[0]
      : this.config.pageId;
    if (!derivedPageId) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'Cannot determine page_id from post_id. Provide FACEBOOK_PAGE_ID or use a post_id in pageId_postId format.', raw: null });
    }
    return this.withPageToken(derivedPageId, userToken, apiVersion, async (accessToken) => {
      const query: Record<string, string> = {
        metric: params.metrics.join(','),
        access_token: accessToken,
      };

      if (params.period) query.period = params.period;

      return this.request<InsightsResponse>({
        method: 'GET',
        url: this.buildPath(apiVersion, `${params.postId}/insights`),
        params: query,
      });
    });
  }

  async listPostsWithInsights(params: ListPostsWithInsightsParams): Promise<PostsWithInsightsResponse> {
    const pageId = params.pageId || this.config.pageId;
    if (!pageId) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'page_id is required', raw: null });
    }

    if (!params.postMetrics || params.postMetrics.length === 0) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'At least one post metric is required', raw: null });
    }

    const apiVersion = this.resolveApiVersion(params.apiVersion);
    const userToken = this.resolveAccessToken(params.accessToken);

    return this.withPageToken(pageId, userToken, apiVersion, async (accessToken) => {
      const fields = `${DEFAULT_POST_FIELDS},insights.metric(${params.postMetrics.join(',')})`;
      const query: Record<string, string> = {
        fields,
        access_token: accessToken,
        limit: String(params.limit ?? 25),
      };
      if (params.after) query.after = params.after;
      if (params.before) query.before = params.before;

      return this.request<PostsWithInsightsResponse>({
        method: 'GET',
        url: this.buildPath(apiVersion, `${pageId}/posts`),
        params: query,
      });
    });
  }

  async listPages(accessToken?: string): Promise<ListPagesResponse> {
    const token = this.resolveAccessToken(accessToken);
    const apiVersion = this.resolveApiVersion();

    return this.request<ListPagesResponse>({
      method: 'GET',
      url: this.buildPath(apiVersion, 'me/accounts'),
      params: {
        access_token: token,
        fields: 'id,name,access_token,category,tasks',
      },
    });
  }

  async getPageDetails(pageId?: string): Promise<PageDetails> {
    const resolvedPageId = pageId || this.config.pageId;
    if (!resolvedPageId) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'page_id is required', raw: null });
    }

    const apiVersion = this.resolveApiVersion();
    const accessToken = this.resolveAccessToken();

    return this.request<PageDetails>({
      method: 'GET',
      url: this.buildPath(apiVersion, resolvedPageId),
      params: {
        access_token: accessToken,
        fields: 'id,name,about,category,category_list,fan_count,followers_count,link,website,phone,emails,location,single_line_address,cover,picture',
      },
    });
  }

  async getPageFeed(pageId?: string, limit?: number): Promise<PageFeedResponse> {
    const resolvedPageId = pageId || this.config.pageId;
    if (!resolvedPageId) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'page_id is required', raw: null });
    }

    const apiVersion = this.resolveApiVersion();
    const accessToken = this.resolveAccessToken();

    return this.request<PageFeedResponse>({
      method: 'GET',
      url: this.buildPath(apiVersion, `${resolvedPageId}/feed`),
      params: {
        access_token: accessToken,
        fields: 'id,message,created_time,permalink_url,full_picture,type,shares,reactions.summary(true),comments.summary(true)',
        limit: String(limit ?? 25),
      },
    });
  }

  listKnownMetrics(): KnownMetricsResponse {
    return {
      page: KNOWN_PAGE_METRICS,
      post: KNOWN_POST_METRICS,
    };
  }

  async validateAccessToken(params: ValidateTokenParams): Promise<ValidateTokenResult> {
    if (!params.accessToken) {
      throw new FacebookApiError({ code: 'VALIDATION', message: 'access_token is required', raw: null });
    }

    const apiVersion = this.resolveApiVersion(params.apiVersion);

    try {
      const response = await this.request<{ id?: string; name?: string } & Record<string, unknown>>({
        method: 'GET',
        url: this.buildPath(apiVersion, 'me'),
        params: {
          access_token: params.accessToken,
          fields: params.fields?.join(',') || 'id,name',
        },
      });

      return {
        isValid: true,
        id: response.id as string | undefined,
        name: response.name as string | undefined,
        raw: response,
      };
    } catch (error) {
      if (error instanceof FacebookApiError) {
        return {
          isValid: false,
          raw: error.normalized.raw,
        };
      }
      throw error;
    }
  }

  private resolveApiVersion(version?: string) {
    return version || this.config.defaultApiVersion || DEFAULT_API_VERSION;
  }

  private resolveAccessToken(token?: string) {
    const resolved = token || this.config.accessToken;
    if (!resolved) {
      throw new FacebookApiError({ code: 'OAUTH', message: 'Facebook access token is required. Provide FACEBOOK_ACCESS_TOKEN or pass accessToken in the request.', raw: null });
    }
    return resolved;
  }

  private buildPath(version: string, path: string) {
    const cleanedPath = path.startsWith('/') ? path.slice(1) : path;
    return `/${version}/${cleanedPath}`;
  }

  private async request<T>(config: AxiosRequestConfig): Promise<T> {
    try {
      return await requestWithRetry<T>(this.axiosInstance, config);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw this.wrapAxiosError(error as GraphApiError);
      }
      throw new FacebookApiError({ code: 'UNKNOWN', message: (error as Error)?.message || 'Unknown error', raw: error });
    }
  }

  private wrapAxiosError(error: GraphApiError) {
    const graphError = error.response?.data?.error;

    if (!graphError) {
      const normalized: NormalizedError = {
        code: 'NETWORK',
        message: error.message,
        raw: error.toJSON ? error.toJSON() : error,
      };
      return new FacebookApiError(normalized);
    }

    let code = 'GRAPH';
    let subcode: string | undefined;

    if (graphError.code === 190 || graphError.type === 'OAuthException') {
      code = 'OAUTH';
      subcode = graphError.error_subcode ? String(graphError.error_subcode) : 'TOKEN';
    } else if ([10, 200, 299].includes(graphError.code ?? 0)) {
      code = 'OAUTH';
      subcode = 'PERMISSION';
    } else if ([4, 17, 32, 613].includes(graphError.code ?? 0)) {
      code = 'RATE_LIMIT';
    } else if (graphError.code === 100) {
      code = 'VALIDATION';
    }

    const normalized: NormalizedError = {
      code,
      subcode,
      message: graphError.message,
      raw: error.response?.data,
    };

    return new FacebookApiError(normalized);
  }
}
