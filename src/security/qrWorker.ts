import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
// This helper is invoked only with stdout/stderr disabled and a private IPC pipe.
process.once("message", async (message: any) => {
  try {
    const sdk = require("NeteaseCloudMusicApi");
    let result: Record<string, unknown>;
    if (message?.operation === "start") {
      const response = await sdk.login_qr_key({ cookie: "", timestamp: Date.now() });
      const key = response.body?.data?.unikey;
      if (typeof key !== "string" || !/^[A-Za-z0-9_-]{8,256}$/.test(key)) throw new Error();
      const qr = await sdk.login_qr_create({ key, qrimg: true, cookie: "" });
      result = { key, image: qr.body?.data?.qrimg };
    } else if (message?.operation === "check" && typeof message.key === "string" && /^[A-Za-z0-9_-]{8,256}$/.test(message.key)) {
      const response = await sdk.login_qr_check({ key: message.key, cookie: "", timestamp: Date.now(), noCookie: true });
      result = { code: response.body?.code, cookie: response.body?.code === 803 ? response.body.cookie : undefined };
    } else throw new Error();
    process.send?.({ ok: true, result });
  } catch { process.send?.({ ok: false }); }
});
