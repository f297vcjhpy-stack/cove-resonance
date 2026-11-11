import { fork } from "node:child_process";
export interface QrApi {
  start(): Promise<{ key: string; image: string }>;
  check(key: string): Promise<{ code: number; cookie?: string }>;
}
/** Deliberately exposes no login operation as an MCP tool. */
export class NeteaseQrApi implements QrApi {
  constructor(private workerFile = new URL("./qrWorker.js", import.meta.url)) {}
  private call(operation: "start" | "check", key?: string): Promise<any> {
    // The upstream API logs whole error responses (including cookies). Never run it
    // in the public gateway process or forward its stdout/stderr to hosting logs.
    const env = { ...process.env };
    for (const name of ["COVE_ADMIN_SECRET", "NETEASE_COOKIE", "BRIDGE_INGEST_TOKEN"]) delete env[name];
    const child = fork(this.workerFile, [], { env, execArgv: [], stdio: ["ignore", "ignore", "ignore", "ipc"] });
    return new Promise((resolve, reject) => {
      let finished = false;
      const done = (value?: unknown) => {
        if (finished) return; finished = true; clearTimeout(timer); child.kill("SIGKILL");
        if (value) resolve(value); else reject(new Error("NetEase login request failed"));
      };
      const timer = setTimeout(() => done(), 15_000);
      child.once("message", (message: any) => done(message?.ok === true ? message.result : undefined));
      child.once("error", () => done()); child.once("exit", () => done());
      child.send({ operation, key }, error => { if (error) done(); });
    });
  }
  async start() {
    const result = await this.call("start");
    const key: unknown = result.key;
    if (typeof key !== "string" || !/^[A-Za-z0-9_-]{8,256}$/.test(key)) throw new Error("Invalid NetEase QR response");
    const image: unknown = result.image;
    if (typeof image !== "string" || !/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(image) || image.length > 100_000) throw new Error("Invalid NetEase QR image");
    return { key, image };
  }
  async check(key: string) {
    const result = await this.call("check", key);
    const code = Number(result.code);
    if (![800, 801, 802, 803].includes(code)) throw new Error("Invalid NetEase QR status");
    if (code !== 803) return { code };
    const cookie = result.cookie;
    if (typeof cookie !== "string" || !/(?:^|;\s*)MUSIC_U=[^;\s]+/.test(cookie) || cookie.length > 32_000 || /[\r\n]/.test(cookie)) throw new Error("Invalid NetEase login session");
    return { code, cookie };
  }
}
