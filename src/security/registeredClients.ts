import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from "node:crypto";
import { OAuthClientInformationFullSchema, type OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

type Metadata = Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">;
const REGISTRATION_TTL_MS = 30 * 86400_000;

/**
 * Restart-safe DCR without a database: client_id is an AES-GCM sealed registration.
 * It is NOT an access token and never bypasses owner consent or PKCE. The existing
 * owner secret derives a resource-specific encryption key, so no new secret is
 * collected. Client secrets remain encrypted inside the public client identifier.
 */
export class RegisteredClients {
  private readonly key: Buffer;
  private readonly aad: Buffer;
  constructor(secret: string, resource: URL, private origins: Set<string>, private now = Date.now) {
    if (secret.length < 32) throw new Error("Owner registration secret is required");
    this.key = Buffer.from(hkdfSync("sha256", secret, resource.href, "cove-dcr-v1", 32));
    this.aad = Buffer.from("cove-dcr-v1:" + resource.href);
  }
  private validRedirects(uris: string[]): boolean {
    if (!uris.length || uris.length > 5) return false;
    return uris.every(uri => {
      try { const u = new URL(uri); return this.origins.has(u.origin) && !u.username && !u.password && !u.hash; }
      catch { return false; }
    });
  }
  async registerClient(input: Metadata): Promise<OAuthClientInformationFull> {
    if (!this.validRedirects(input.redirect_uris)) throw new InvalidClientMetadataError("Redirect origin is not allowed");
    if (input.token_endpoint_auth_method && !["none", "client_secret_post"].includes(input.token_endpoint_auth_method)) throw new InvalidClientMetadataError("Unsupported client authentication");
    const client = OAuthClientInformationFullSchema.parse({ ...input, client_id: randomUUID(), client_id_issued_at: Math.floor(this.now() / 1000) });
    const payload = Buffer.from(JSON.stringify({ version: 1, until: this.now() + REGISTRATION_TTL_MS, client }));
    if (payload.length > 5000) throw new InvalidClientMetadataError("Client metadata is too large");
    const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(this.aad);
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
    const id = ["cove1", nonce.toString("base64url"), ciphertext.toString("base64url"), cipher.getAuthTag().toString("base64url")].join(".");
    return { ...client, client_id: id };
  }
  async getClient(id: string): Promise<OAuthClientInformationFull | undefined> {
    if (typeof id !== "string" || id.length > 7000) return;
    const parts = id.split(".");
    if (parts.length !== 4 || parts[0] !== "cove1" || parts.slice(1).some(p => !/^[A-Za-z0-9_-]+$/.test(p))) return;
    try {
      const nonce = Buffer.from(parts[1], "base64url"), tag = Buffer.from(parts[3], "base64url");
      if (nonce.length !== 12 || tag.length !== 16) return;
      const decipher = createDecipheriv("aes-256-gcm", this.key, nonce);
      decipher.setAAD(this.aad); decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(Buffer.from(parts[2], "base64url")), decipher.final()]);
      const payload = JSON.parse(plaintext.toString("utf8"));
      if (payload.version !== 1 || !Number.isFinite(payload.until) || payload.until <= this.now()) return;
      const parsed = OAuthClientInformationFullSchema.safeParse(payload.client);
      if (!parsed.success || !this.validRedirects(parsed.data.redirect_uris)) return;
      return { ...parsed.data, client_id: id };
    } catch { return; }
  }
}
