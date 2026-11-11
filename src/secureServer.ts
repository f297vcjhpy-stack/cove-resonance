import { createSecureGateway } from "./security/gateway.js";
import { NeteaseQrApi } from "./security/neteaseLogin.js";
import { PrivateWorker } from "./security/workerHost.js";
import { randomBytes } from "node:crypto";
import express from "express";

const origin = process.env.BRIDGE_PUBLIC_ORIGIN ?? process.env.RENDER_EXTERNAL_URL ?? "";
const adminSecret = process.env.COVE_ADMIN_SECRET ?? "";
const port = Number(process.env.PORT ?? 8787);
const workerPort = 18787;
if (!Number.isInteger(port) || port < 1 || port > 65535 || port === workerPort) throw new Error("Invalid public PORT");
if (process.env.NETEASE_COOKIE) throw new Error("Remove NETEASE_COOKIE; use the protected QR login page");
const host = new PrivateWorker(workerPort, origin);
// Allow first deployment and public 401/metadata checks before the owner enters
// a secret in Render. A random, undisclosed fallback plus a closed admin gate
// makes this state unclaimable by public visitors.
const { app } = createSecureGateway({ origin, adminSecret: adminSecret || randomBytes(32).toString("base64url"), host, qr: new NeteaseQrApi() });
const publicApp = express();
publicApp.disable("x-powered-by");
if (!adminSecret) publicApp.use("/admin", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  res.status(503).type("html").send('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cove 管理页待配置</title><h1>管理页尚未启用</h1><p>请在 Render 服务的 Environment 页面自行设置 COVE_ADMIN_SECRET，至少 32 个随机字符，然后重新部署。</p><p>请勿把密钥发到聊天中。配置完成前，任何访客都无法登录或绑定网易云。</p></html>');
});
publicApp.use(app);
await host.replace("");
const server = publicApp.listen(port, "0.0.0.0", () => console.log("Cove secure gateway ready"));
let stopping = false;
async function stop() {
  if (stopping) return; stopping = true;
  const force = setTimeout(() => process.exit(1), 10_000); force.unref();
  server.close(); server.closeAllConnections();
  await host.close(); process.exit(0);
}
process.once("SIGTERM", () => void stop()); process.once("SIGINT", () => void stop());
