import { timingSafeEqual, createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import express, { type Request, type Response, type NextFunction } from "express";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { OwnerOAuth, ExpiringStore, opaque, digest } from "./oauth.js";
import { loginHtml, consentHtml, dashboardHtml, expiredConsentHtml } from "./adminHtml.js";
import { InvalidGrantError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { QrApi } from "./neteaseLogin.js";
import type { WorkerHost } from "./workerHost.js";

type Session = { until: number; csrf: string; qr?: { key: string; until: number; lastPoll: number }; busy?: boolean };
type Options = { origin: string; adminSecret: string; host: WorkerHost; qr: QrApi; redirectOrigins?: Set<string>; now?: () => number };
const sessionCookie = "__Host-cove_session";
const loginCookie = "__Host-cove_login";
const same = (a: string, b: string) => timingSafeEqual(createHash("sha256").update(a).digest(), createHash("sha256").update(b).digest());
const cookie = (req: Request, name: string): string => {
  const part = req.headers.cookie?.split(";").map(s => s.trim()).find(s => s.startsWith(name + "="));
  const value = part?.slice(name.length + 1) ?? "";
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : "";
};
const requestId = (v: unknown) => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v) ? v : "";

export function createSecureGateway(options: Options) {
  const { host, qr } = options, now = options.now ?? Date.now;
  const parsed = new URL(options.origin);
  if (parsed.origin !== options.origin || (parsed.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(parsed.hostname))) throw new Error("A canonical HTTPS origin is required");
  if (options.adminSecret.length < 32 || options.adminSecret.length > 512) throw new Error("Set COVE_ADMIN_SECRET to a private random value of at least 32 characters");
  const oauth = new OwnerOAuth(new URL("/mcp/music", options.origin), options.redirectOrigins ?? new Set(["https://chatgpt.com", "https://chat.openai.com"]), options.adminSecret, now);
  const sessions = new ExpiringStore<Session>(now, 20), logins = new ExpiringStore<{ until: number }>(now, 50);
  const app = express();
  app.disable("x-powered-by");
  // No proxy trust: do not use caller-supplied X-Forwarded-For to bypass limits.
  app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    // no-referrer can turn a browser form POST's Origin into "null". Keep the
    // same-origin form identity required by CSRF checks without cross-site leaks.
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Strict-Transport-Security", "max-age=31536000");
    if ((req.url?.length ?? 0) > 8192) { res.sendStatus(414); return; }
    next();
  });
  app.get("/", (_req, res) => res.json({ ok: true, service: "cove-secure-gateway" }));
  // Bound all OAuth bodies before entering SDK middleware.
  app.use(["/register", "/token", "/revoke", "/authorize"], express.json({ limit: "16kb" }), express.urlencoded({ extended: false, limit: "16kb" }));
  app.use(mcpAuthRouter({ provider: oauth, issuerUrl: new URL(options.origin), resourceServerUrl: oauth.resource, scopesSupported: ["music"], resourceName: "Cove Resonance Music" }));
  app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json({ resource: oauth.resource.href, authorization_servers: [options.origin + "/"], scopes_supported: ["music"] }));
  app.use("/admin", express.urlencoded({ extended: false, limit: "8kb" }), express.json({ limit: "8kb" }));
  const session = (req: Request) => sessions.get(digest(cookie(req, sessionCookie)));
  const csrf = (req: Request, s: Session) => req.headers.origin === options.origin && same(String(req.headers["x-cove-csrf"] ?? req.body?.csrf ?? ""), s.csrf);
  const issueCookie = (res: Response, name: string, value: string, maxAge: number) => res.setHeader("Set-Cookie", `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
  const html = (res: Response, content: string, nonce?: string) => {
    res.setHeader("Content-Security-Policy", `default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
    res.type("html").send(content);
  };
  app.get("/admin", (req, res) => {
    const s = session(req), id = requestId(req.query.request);
    if (!s) {
      const token = opaque(); logins.set(digest(token), { until: now() + 5 * 60_000 });
      issueCookie(res, loginCookie, token, 300); html(res, loginHtml(token, id)); return;
    }
    if (id) {
      const p = oauth.pending.get(id);
      if (!p) { res.status(410); html(res, expiredConsentHtml()); return; }
      html(res, consentHtml(s.csrf, id, p.client.client_name ?? "OAuth client", p.params.redirectUri, Math.max(1, Math.ceil((p.until - now()) / 60_000)))); return;
    }
    const nonce = opaque(); html(res, dashboardHtml(s.csrf, nonce), nonce);
  });
  let attempts = 0, attemptWindow = now();
  app.post("/admin/login", (req, res) => {
    if (now() - attemptWindow > 15 * 60_000) { attempts = 0; attemptWindow = now(); }
    if (++attempts > 20) { res.sendStatus(429); return; }
    const token = cookie(req, loginCookie);
    if (req.headers.origin !== options.origin || !logins.get(digest(token)) || !same(String(req.body?.csrf ?? ""), token)) {
      const id = requestId(req.body?.request);
      const retry = id ? "/admin?request=" + id : "/admin";
      res.status(403);
      html(res, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>请重新打开登录页</title><h1>本次登录校验未通过</h1><p>登录页可能已过期、在其他标签页被刷新，或浏览器没有保留当前会话。</p><p><a href="${retry}">重新打开登录页</a>，再输入你自己的管理密钥。若内置浏览器反复出现此提示，请在 Safari 中打开同一个登录链接。</p><p>不要把密钥发到聊天中。</p></html>`);
      return;
    }
    logins.delete(digest(token));
    if (typeof req.body?.secret !== "string" || req.body.secret.length > 512 || !same(req.body.secret, options.adminSecret)) { res.status(401).send("管理密钥不正确，请刷新页面重试。"); return; }
    const sid = opaque(); sessions.set(digest(sid), { until: now() + 15 * 60_000, csrf: opaque() });
    issueCookie(res, sessionCookie, sid, 900);
    const id = requestId(req.body.request); res.redirect(303, id ? "/admin?request=" + id : "/admin");
  });
  app.use("/admin", (req, res, next) => {
    const s = session(req);
    if (!s) { res.sendStatus(401); return; }
    if (req.method !== "GET" && !csrf(req, s)) { res.sendStatus(403); return; }
    res.locals.session = s; next();
  });
  app.post("/admin/consent", (req, res) => {
    if (!["allow", "deny"].includes(req.body?.decision)) { res.sendStatus(400); return; }
    try {
      res.redirect(303, oauth.consent(requestId(req.body.request), req.body.decision === "allow"));
    } catch (error) {
      if (!(error instanceof InvalidGrantError)) throw error;
      res.status(410); html(res, expiredConsentHtml());
    }
  });
  app.get("/admin/status", (_req, res) => res.json({ bound: host.bound, storage: "memory-only" }));
  app.post("/admin/qr/start", async (_req, res) => {
    const s = res.locals.session as Session;
    if (s.busy || s.qr && s.qr.until > now()) { res.sendStatus(409); return; }
    s.busy = true;
    try {
      if (host.bound) { res.status(409).json({ error: "disconnect_before_switching_accounts" }); return; }
      const result = await qr.start();
      s.qr = { key: result.key, until: now() + 3 * 60_000, lastPoll: 0 };
      res.json({ image: result.image });
    } finally { s.busy = false; }
  });
  app.post("/admin/qr/check", async (req, res) => {
    const s = res.locals.session as Session, pending = s.qr;
    if (!pending || pending.until <= now()) { s.qr = undefined; res.json({ code: 800 }); return; }
    if (s.busy || now() - pending.lastPoll < 2500) { res.sendStatus(429); return; }
    pending.lastPoll = now(); s.busy = true;
    try {
      const result = await qr.check(pending.key);
      if (s.qr !== pending || session(req) !== s) { res.sendStatus(409); return; }
      if (result.code === 803) {
        s.qr = undefined;
        if (!result.cookie || host.bound) { res.sendStatus(409); return; }
        await host.replace(result.cookie);
      } else if (result.code === 800) s.qr = undefined;
      // Never serialize the provider result: it contains the login cookie on success.
      res.json({ code: result.code });
    } finally { s.busy = false; }
  });
  app.post("/admin/disconnect", async (_req, res) => {
    // Clearing sessions cancels outstanding QR requests before awaiting worker shutdown.
    sessions.clear(); oauth.revokeAll();
    await host.replace(""); issueCookie(res, sessionCookie, "", 0); res.json({ ok: true });
  });
  app.post("/admin/revoke", (_req, res) => { oauth.revokeAll(); res.json({ ok: true }); });
  app.post("/admin/logout", (req, res) => {
    const s = res.locals.session as Session; s.qr = undefined;
    sessions.delete(digest(cookie(req, sessionCookie))); issueCookie(res, sessionCookie, "", 0); res.json({ ok: true });
  });
  const proxy = (req: Request, res: Response) => {
    const upstream = httpRequest({ host: "127.0.0.1", port: host.port, path: req.originalUrl, method: req.method, headers: {
      host: "127.0.0.1", accept: req.headers.accept ?? "application/json", "content-type": req.headers["content-type"] ?? "application/json",
      ...(req.headers["mcp-protocol-version"] ? { "mcp-protocol-version": req.headers["mcp-protocol-version"] } : {}),
    } }, response => {
      res.status(response.statusCode ?? 502);
      for (const name of ["content-type", "cache-control", "access-control-allow-origin", "access-control-expose-headers"]) {
        if (response.headers[name]) res.setHeader(name, response.headers[name]!);
      }
      response.pipe(res);
    });
    upstream.setTimeout(65_000, () => upstream.destroy());
    upstream.on("error", () => { if (!res.headersSent) res.status(503).json({ error: "worker_unavailable" }); else res.destroy(); });
    res.once("close", () => upstream.destroy());
    if (Buffer.isBuffer(req.body)) upstream.end(req.body); else upstream.end();
  };
  // No public /events ingress. No legacy or unknown paths are forwarded.
  app.all(["/mcp/music", "/mcp"], async (req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "content-type, authorization, mcp-protocol-version, mcp-session-id");
      res.sendStatus(204); return;
    }
    if (!["GET", "POST", "DELETE"].includes(req.method)) { res.sendStatus(405); return; }
    try {
      const auth = req.headers.authorization ?? "";
      if (!auth.startsWith("Bearer ") || auth.length > 512) throw new Error();
      await oauth.verifyAccessToken(auth.slice(7));
      next();
    } catch {
      res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${options.origin}/.well-known/oauth-protected-resource/mcp/music", scope="music"`);
      res.status(401).json({ error: "unauthorized" });
    }
  }, express.raw({ type: () => true, limit: "64kb" }), proxy);
  // Listener uses its own short-lived single-use token, minted by an authenticated MCP call.
  app.get("/listener/events", proxy);
  app.use((_req, res) => res.sendStatus(404));
  app.use((error: any, _req: Request, res: Response, _next: NextFunction) => {
    // Do not log exception payloads from login providers, OAuth tokens, or request bodies.
    if (res.headersSent) { res.destroy(); return; }
    res.status(error?.type === "entity.too.large" ? 413 : 400).json({ error: "request_failed" });
  });
  return { app, oauth };
}
