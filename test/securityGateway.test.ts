import assert from "node:assert/strict";
import test from "node:test";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import vm from "node:vm";
import { createSecureGateway } from "../src/security/gateway.js";
import { dashboardHtml } from "../src/security/adminHtml.js";
import type { QrApi } from "../src/security/neteaseLogin.js";
import type { WorkerHost } from "../src/security/workerHost.js";

const secret = randomBytes(32).toString("hex");
const origin = "https://cove.test", resource = origin + "/mcp/music";
const callback = "https://chatgpt.com/connector_platform/oauth_redirect";
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const sessionCookie = (r: Response) => r.headers.get("set-cookie")!.split(";")[0];

async function harness(run: (h: Awaited<ReturnType<typeof setup>>) => Promise<void>) {
  const h = await setup();
  try { await run(h); } finally { await h.close(); }
}
async function setup() {
  let time = Date.now(), providerCookie = "", qrCount = 0;
  let qrResult: () => Promise<{ code: number; cookie?: string }> = async () => ({ code: 803, cookie: "MUSIC_U=test-provider-cookie-not-a-real-account" });
  const backend = createServer((req, res) => {
    if (req.url?.startsWith("/listener/events")) { res.writeHead(401).end(); return; }
    res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ forwarded: true }));
  });
  await new Promise<void>(r => backend.listen(0, "127.0.0.1", r));
  const host: WorkerHost = {
    port: (backend.address() as any).port,
    get bound() { return Boolean(providerCookie); },
    async replace(value) { providerCookie = value; }, async close() {},
  };
  const qr: QrApi = { async start() { qrCount++; return { key: "private-qr-key", image: "data:image/png;base64,aGVsbG8=" }; }, async check() { return qrResult(); } };
  const { app } = createSecureGateway({ origin, adminSecret: secret, host, qr, now: () => time });
  const server = createServer(app);
  await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
  const base = "http://127.0.0.1:" + (server.address() as any).port;
  const request = (path: string, options: RequestInit = {}) => fetch(base + path, { ...options, redirect: "manual" });
  async function login(password = secret) {
    const page = await request("/admin");
    const text = await page.text();
    const csrf = text.match(/name="csrf" value="([^"]+)"/)![1];
    const response = await request("/admin/login", { method: "POST", headers: { cookie: sessionCookie(page), origin }, body: new URLSearchParams({ secret: password, csrf }) });
    if (response.status !== 303) return { response, cookie: "", csrf: "" };
    const cookie = sessionCookie(response);
    const home = await request("/admin", { headers: { cookie } });
    const html = await home.text();
    return { response, cookie, csrf: html.match(/const csrf="([^"]+)"/)![1] };
  }
  async function register(redirect = callback) {
    return request("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "ChatGPT test", redirect_uris: [redirect], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
  }
  const form = (path: string, values: Record<string, string>) => request(path, { method: "POST", body: new URLSearchParams(values) });
  async function authorize() {
    const registration = await register(); assert.equal(registration.status, 201);
    const client = await registration.json();
    const response = await request("/authorize?" + new URLSearchParams({ client_id: client.client_id, redirect_uri: callback, response_type: "code", code_challenge: challenge, code_challenge_method: "S256", scope: "music", resource, state: "preserve-state" }));
    assert.equal(response.status, 303);
    const id = new URL(response.headers.get("location")!, origin).searchParams.get("request")!;
    return { client, id };
  }
  async function consent() {
    const { client, id } = await authorize(), admin = await login();
    const response = await request("/admin/consent", { method: "POST", headers: { cookie: admin.cookie, origin }, body: new URLSearchParams({ csrf: admin.csrf, request: id, decision: "allow" }) });
    assert.equal(response.status, 303);
    const location = new URL(response.headers.get("location")!);
    assert.equal(location.origin, "https://chatgpt.com"); assert.equal(location.searchParams.get("state"), "preserve-state");
    return { client, code: location.searchParams.get("code")!, admin };
  }
  async function grant() {
    const c = await consent();
    const response = await form("/token", { client_id: c.client.client_id, grant_type: "authorization_code", code: c.code, code_verifier: verifier, redirect_uri: callback, resource });
    assert.equal(response.status, 200);
    return { ...c, tokens: await response.json() };
  }
  const adminPost = (path: string, admin: { cookie: string; csrf: string }, extraHeaders: Record<string, string> = {}) => request("/admin/" + path, { method: "POST", headers: { cookie: admin.cookie, origin, "x-cove-csrf": admin.csrf, "content-type": "application/json", ...extraHeaders }, body: "{}" });
  return { request, login, register, form, authorize, consent, grant, adminPost, host,
    get qrCount() { return qrCount; },
    set qrResult(fn: typeof qrResult) { qrResult = fn; },
    advance(ms: number) { time += ms; },
    async close() { server.closeAllConnections(); backend.closeAllConnections(); await Promise.all([new Promise<void>(r => server.close(() => r())), new Promise<void>(r => backend.close(() => r()))]); },
  };
}

test("all MCP routes reject anonymous calls and expose PKCE metadata", () => harness(async h => {
  for (const path of ["/mcp/music", "/mcp"]) {
    const r = await h.request(path, { method: "POST", body: "{}" }); assert.equal(r.status, 401);
    assert.match(r.headers.get("www-authenticate")!, /oauth-protected-resource\/mcp\/music/);
  }
  assert.equal((await h.request("/events", { method: "POST", body: "{}" })).status, 404);
  const metadata = await (await h.request("/.well-known/oauth-authorization-server")).json();
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  assert.equal((await (await h.request("/.well-known/oauth-protected-resource/mcp/music")).json()).resource, resource);
}));
test("DCR rejects untrusted and fragment-bearing redirects", () => harness(async h => {
  assert.equal((await h.register("https://evil.test/callback")).status, 400);
  assert.equal((await h.register(callback + "#fragment")).status, 400);
}));
test("admin secret is required; cookies are Secure HttpOnly and login is CSRF protected", () => harness(async h => {
  assert.equal((await h.login("wrong-secret")).response.status, 401);
  assert.equal((await h.request("/admin/login", { method: "POST", body: new URLSearchParams({ secret }) })).status, 403);
  const admin = await h.login(); assert.match(admin.response.headers.get("set-cookie")!, /HttpOnly; Secure; SameSite=Lax/);
  assert.equal((await h.adminPost("qr/start", admin, { origin: "https://evil.test" })).status, 403);
  assert.equal(h.qrCount, 0);
}));
test("authorization requires authenticated explicit consent", () => harness(async h => {
  const { id } = await h.authorize();
  const r = await h.request("/admin/consent", { method: "POST", body: new URLSearchParams({ request: id, decision: "allow" }) });
  assert.equal(r.status, 401);
}));
test("PKCE, client, redirect and resource are bound; authorization codes are single-use", () => harness(async h => {
  const c = await h.consent();
  const common = { client_id: c.client.client_id, grant_type: "authorization_code", code: c.code, code_verifier: verifier, redirect_uri: callback, resource };
  assert.equal((await h.form("/token", { ...common, code_verifier: "wrong" })).status, 400);
  assert.equal((await h.form("/token", { ...common, resource: "https://evil.test/mcp" })).status, 400);
  assert.equal((await h.form("/token", { ...common, redirect_uri: callback + "/changed" })).status, 400);
  const client2 = await (await h.register()).json();
  assert.equal((await h.form("/token", { ...common, client_id: client2.client_id })).status, 400);
  assert.equal((await h.form("/token", common)).status, 200);
  assert.equal((await h.form("/token", common)).status, 400);
}));
test("access tokens expire; refresh tokens rotate and replay revokes the family", () => harness(async h => {
  const { client, tokens } = await h.grant();
  const headers = { authorization: "Bearer " + tokens.access_token };
  assert.equal((await h.request("/mcp/music", { headers })).status, 200);
  h.advance(901_000); assert.equal((await h.request("/mcp/music", { headers })).status, 401);
  const common = { client_id: client.client_id, grant_type: "refresh_token", refresh_token: tokens.refresh_token, resource };
  const r = await h.form("/token", common); assert.equal(r.status, 200);
  const newer = await r.json(); assert.notEqual(newer.refresh_token, tokens.refresh_token);
  assert.equal((await h.form("/token", common)).status, 400);
  assert.equal((await h.request("/mcp/music", { headers: { authorization: "Bearer " + newer.access_token } })).status, 401);
}));
test("QR login is admin-only and neither provider cookies nor QR keys are serialized", () => harness(async h => {
  assert.equal((await h.request("/admin/qr/start", { method: "POST" })).status, 401);
  const admin = await h.login();
  const start = await h.adminPost("qr/start", admin); assert.equal(start.status, 200);
  assert.doesNotMatch(await start.text(), /private-qr-key|MUSIC_U/);
  const check = await h.adminPost("qr/check", admin); assert.equal(check.status, 200);
  assert.deepEqual(await check.json(), { code: 803 }); assert.equal(h.host.bound, true);
}));
test("logout invalidates an in-flight QR check before it can bind an account", () => harness(async h => {
  const admin = await h.login(); await h.adminPost("qr/start", admin);
  let resolve!: (value: { code: number; cookie: string }) => void;
  let entered!: () => void;
  const seen = new Promise<void>(r => entered = r);
  h.qrResult = () => new Promise(r => { resolve = r; entered(); });
  const pending = h.adminPost("qr/check", admin); await seen;
  await h.adminPost("logout", admin);
  resolve({ code: 803, cookie: "MUSIC_U=cancelled-session" });
  assert.equal((await pending).status, 409); assert.equal(h.host.bound, false);
}));
test("disconnect invalidates account, admin sessions and MCP grants", () => harness(async h => {
  const { admin, tokens } = await h.grant();
  await h.adminPost("qr/start", admin); await h.adminPost("qr/check", admin);
  assert.equal(h.host.bound, true);
  assert.equal((await h.adminPost("disconnect", admin)).status, 200); assert.equal(h.host.bound, false);
  assert.equal((await h.request("/mcp/music", { headers: { authorization: "Bearer " + tokens.access_token } })).status, 401);
  assert.equal((await h.request("/admin/status", { headers: { cookie: admin.cookie } })).status, 401);
}));
test("authorized MCP request body size is bounded", () => harness(async h => {
  const { tokens } = await h.grant();
  const response = await h.request("/mcp/music", { method: "POST", headers: { authorization: "Bearer " + tokens.access_token, "content-type": "application/json" }, body: JSON.stringify({ text: "x".repeat(70_000) }) });
  assert.equal(response.status, 413);
}));
test("management UI script parses and never exposes a raw-cookie input", () => {
  const html = dashboardHtml("test-csrf", "test-nonce");
  const js = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)![1];
  assert.doesNotThrow(() => new vm.Script(js)); assert.doesNotMatch(html, /name="(?:cookie|NETEASE_COOKIE)"/);
});
