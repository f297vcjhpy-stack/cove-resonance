import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { NeteaseQrApi } from "../src/security/neteaseLogin.js";

async function fixture(source: string, run: (api: NeteaseQrApi) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), "cove-qr-test-"));
  try {
    const file = join(dir, "worker.mjs"); await writeFile(file, source);
    await run(new NeteaseQrApi(pathToFileURL(file)));
  } finally { await rm(dir, { recursive: true, force: true }); }
}
test("QR helper is isolated from gateway secrets and validates provider results", async () => {
  const before = process.env.COVE_ADMIN_SECRET;
  process.env.COVE_ADMIN_SECRET = "must-not-reach-login-helper";
  try {
    await fixture(`process.on('message',m=>{
      if(process.env.COVE_ADMIN_SECRET)process.exit(1);
      console.log('SIMULATED_PROVIDER_LOG_MUST_BE_SUPPRESSED');
      process.send({ok:true,result:m.operation==='start'?{key:'fixture-key-123',image:'data:image/png;base64,aGVsbG8='}:{code:803,cookie:'MUSIC_U=synthetic-test-cookie'}});
    });`, async api => {
      const qr = await api.start(); assert.equal(qr.key, "fixture-key-123");
      const result = await api.check(qr.key); assert.equal(result.code, 803);
      assert.equal(result.cookie, "MUSIC_U=synthetic-test-cookie");
    });
  } finally { if (before === undefined) delete process.env.COVE_ADMIN_SECRET; else process.env.COVE_ADMIN_SECRET = before; }
});
test("malformed QR data and malformed login cookies fail closed", () => fixture(`process.on('message',m=>process.send({ok:true,result:m.operation==='start'?{key:'fixture-key-123',image:'https://evil.test/image'}:{code:803,cookie:'MUSIC_U=test\\r\\nInjected: header'}}));`, async api => {
  await assert.rejects(api.start(), /Invalid NetEase QR image/);
  await assert.rejects(api.check("fixture-key-123"), /Invalid NetEase login session/);
}));
test("QR helper exit yields a generic error without provider error contents", () => fixture(`console.error('SYNTHETIC_PRIVATE_ERROR');process.exit(1);`, async api => {
  await assert.rejects(api.start(), { message: "NetEase login request failed" });
}));
