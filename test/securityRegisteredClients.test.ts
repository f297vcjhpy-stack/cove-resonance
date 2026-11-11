import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { RegisteredClients } from "../src/security/registeredClients.js";

const secret = randomBytes(32).toString("base64url");
const resource = new URL("https://cove.test/mcp/music"), origins = new Set(["https://chatgpt.com"]);
const metadata = { redirect_uris: ["https://chatgpt.com/connector/oauth/test-callback"], client_name: "ChatGPT", token_endpoint_auth_method: "client_secret_post", client_secret: "synthetic-test-client-secret" };
test("DCR registration survives a new store instance without a database", async () => {
  const first = new RegisteredClients(secret, resource, origins);
  const registered = await first.registerClient(metadata);
  const restarted = new RegisteredClients(secret, resource, origins);
  const recovered = await restarted.getClient(registered.client_id);
  assert.deepEqual(recovered, registered);
  assert.equal(recovered?.client_secret, metadata.client_secret);
  assert.ok(!registered.client_id.includes(metadata.client_secret));
});
test("sealed registrations reject tampering, different owner, resource and unknown legacy IDs", async () => {
  const store = new RegisteredClients(secret, resource, origins), registered = await store.registerClient(metadata);
  const parts = registered.client_id.split(".");
  parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
  assert.equal(await store.getClient(parts.join(".")), undefined);
  assert.equal(await new RegisteredClients(randomBytes(32).toString("hex"), resource, origins).getClient(registered.client_id), undefined);
  assert.equal(await new RegisteredClients(secret, new URL("https://different.test/mcp/music"), origins).getClient(registered.client_id), undefined);
  assert.equal(await store.getClient("unknown-old-client-id"), undefined);
});
test("sealed registrations expire and respect updated callback policy", async () => {
  let now = Date.now();
  const store = new RegisteredClients(secret, resource, origins, () => now), registered = await store.registerClient(metadata);
  assert.equal(await new RegisteredClients(secret, resource, new Set()).getClient(registered.client_id), undefined);
  now += 31 * 86400_000;
  assert.equal(await store.getClient(registered.client_id), undefined);
});
