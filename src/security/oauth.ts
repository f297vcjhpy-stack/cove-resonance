import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidClientMetadataError, InvalidGrantError, InvalidScopeError, InvalidTargetError, InvalidTokenError, InvalidRequestError, ServerError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

export const opaque = () => randomBytes(32).toString("base64url");
export const digest = (s: string) => createHash("sha256").update(s).digest("hex");
export const AUTHORIZATION_REQUEST_TTL_MS = 15 * 60_000;
type Timed = { until: number };
export class ExpiringStore<T extends Timed> {
  private values = new Map<string, T>();
  constructor(private now = Date.now, private limit = 100) {}
  get(key: string): T | undefined {
    const value = this.values.get(key);
    if (value && value.until <= this.now()) { this.values.delete(key); return; }
    return value;
  }
  set(key: string, value: T): void {
    for (const [k, v] of this.values) if (v.until <= this.now()) this.values.delete(k);
    if (!this.values.has(key) && this.values.size >= this.limit) throw new ServerError("Try again later");
    this.values.set(key, value);
  }
  delete(key: string): void { this.values.delete(key); }
  clear(): void { this.values.clear(); }
}
type Client = OAuthClientInformationFull & Timed;
export type Pending = Timed & { client: OAuthClientInformationFull; params: AuthorizationParams };
type Code = Pending;
type Grant = Timed & { clientId: string; family: string };

/** Single-owner OAuth provider. The SDK handles parsing, DCR, PKCE and client authentication. */
export class OwnerOAuth implements OAuthServerProvider {
  private clients: ExpiringStore<Client>;
  readonly pending: ExpiringStore<Pending>;
  private codes: ExpiringStore<Code>;
  private access: ExpiringStore<Grant>;
  private refresh: ExpiringStore<Grant>;
  private spentRefresh: ExpiringStore<Grant>;
  private families: ExpiringStore<Timed>;
  constructor(readonly resource: URL, private redirectOrigins: Set<string>, private now = Date.now) {
    this.clients = new ExpiringStore(now); this.pending = new ExpiringStore(now);
    this.codes = new ExpiringStore(now); this.access = new ExpiringStore(now, 500);
    this.refresh = new ExpiringStore(now, 500); this.families = new ExpiringStore(now);
    this.spentRefresh = new ExpiringStore(now, 4096);
  }
  readonly clientsStore = {
    getClient: async (id: string) => this.clients.get(id),
    registerClient: async (input: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): Promise<OAuthClientInformationFull> => {
      if (!input.redirect_uris.length || input.redirect_uris.length > 5) throw new InvalidClientMetadataError("Invalid redirect URIs");
      for (const uri of input.redirect_uris) {
        const u = new URL(uri);
        if (!this.redirectOrigins.has(u.origin) || u.username || u.password || u.hash) throw new InvalidClientMetadataError("Redirect origin is not allowed");
      }
      if (input.token_endpoint_auth_method && !["none", "client_secret_post"].includes(input.token_endpoint_auth_method)) throw new InvalidClientMetadataError("Unsupported client authentication");
      const client = { ...input, client_id: randomUUID(), client_id_issued_at: Math.floor(this.now() / 1000) };
      this.clients.set(client.client_id, { ...client, until: this.now() + 7 * 86400_000 });
      return client;
    },
  };
  private target(resource?: URL): void {
    if (resource && resource.href !== this.resource.href) throw new InvalidTargetError("Wrong resource");
  }
  private scopes(scopes?: string[]): void {
    if (scopes?.some(s => s !== "music")) throw new InvalidScopeError("Only music is supported");
  }
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    this.target(params.resource); this.scopes(params.scopes);
    if (!/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)) throw new InvalidRequestError("S256 PKCE is required");
    // Defense in depth beyond the SDK redirect validation.
    if (!client.redirect_uris.includes(params.redirectUri)) throw new InvalidRequestError("Exact redirect URI required");
    const id = opaque();
    this.pending.set(id, { client, params, until: this.now() + AUTHORIZATION_REQUEST_TTL_MS });
    res.redirect(303, "/admin?request=" + id);
  }
  consent(id: string, allow: boolean): string {
    const pending = this.pending.get(id);
    if (!pending) throw new InvalidGrantError("Authorization request expired");
    this.pending.delete(id);
    const u = new URL(pending.params.redirectUri);
    if (allow) {
      const code = opaque();
      this.codes.set(digest(code), { ...pending, until: this.now() + 60_000 });
      u.searchParams.set("code", code);
    } else u.searchParams.set("error", "access_denied");
    if (pending.params.state !== undefined) u.searchParams.set("state", pending.params.state);
    return u.href;
  }
  private code(client: OAuthClientInformationFull, raw: string): Code {
    const c = this.codes.get(digest(raw));
    if (!c || c.client.client_id !== client.client_id) throw new InvalidGrantError("Invalid authorization code");
    return c;
  }
  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    return this.code(client, code).params.codeChallenge;
  }
  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens> {
    const c = this.code(client, code);
    this.target(resource);
    if (redirectUri !== c.params.redirectUri) throw new InvalidGrantError("Redirect URI mismatch");
    this.codes.delete(digest(code));
    const family = opaque();
    this.families.set(family, { until: this.now() + 7 * 86400_000 });
    return this.issue(client.client_id, family);
  }
  private issue(clientId: string, family: string): OAuthTokens {
    const access = opaque(), refresh = opaque();
    const familyExpiry = this.families.get(family)?.until;
    if (!familyExpiry) throw new InvalidGrantError("Session expired");
    this.access.set(digest(access), { clientId, family, until: this.now() + 15 * 60_000 });
    this.refresh.set(digest(refresh), { clientId, family, until: familyExpiry });
    return { access_token: access, token_type: "Bearer", expires_in: 900, refresh_token: refresh, scope: "music" };
  }
  async exchangeRefreshToken(client: OAuthClientInformationFull, token: string, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    this.target(resource); this.scopes(scopes);
    const key = digest(token);
    const replay = this.spentRefresh.get(key);
    if (replay?.clientId === client.client_id) {
      this.families.delete(replay.family);
      throw new InvalidGrantError("Refresh token replay detected; reconnect");
    }
    const grant = this.refresh.get(key);
    if (!grant || grant.clientId !== client.client_id || !this.families.get(grant.family)) throw new InvalidGrantError("Invalid refresh token");
    this.refresh.delete(key); this.spentRefresh.set(key, grant);
    return this.issue(client.client_id, grant.family);
  }
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const grant = this.access.get(digest(token));
    if (!grant || !this.families.get(grant.family)) throw new InvalidTokenError("Invalid or expired token");
    return { token, clientId: grant.clientId, scopes: ["music"], expiresAt: Math.floor(grant.until / 1000), resource: this.resource };
  }
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const key = digest(request.token);
    const grant = this.access.get(key) ?? this.refresh.get(key);
    if (grant?.clientId === client.client_id) this.families.delete(grant.family);
  }
  revokeAll(): void { this.access.clear(); this.refresh.clear(); this.spentRefresh.clear(); this.codes.clear(); this.pending.clear(); this.families.clear(); }
}
