import { spawn, type ChildProcess } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
export interface WorkerHost {
  readonly port: number;
  readonly bound: boolean;
  replace(cookie: string): Promise<void>;
  close(): Promise<void>;
}
/** Private child keeps the existing queue/NIM lifecycle intact. Nothing listens publicly except the gateway. */
export class PrivateWorker implements WorkerHost {
  private child?: ChildProcess;
  private cookie = "";
  private operation: Promise<void> = Promise.resolve();
  constructor(readonly port: number, private origin: string) {}
  get bound() { return Boolean(this.cookie); }
  replace(cookie: string): Promise<void> {
    const next = this.operation.then(() => this.replaceNow(cookie));
    this.operation = next.catch(() => {});
    return next;
  }
  private async replaceNow(cookie: string) {
      await this.stopChild();
      this.cookie = cookie;
      const env = { ...process.env, NODE_ENV: "production", PORT: String(this.port), BRIDGE_HOST: "127.0.0.1", BRIDGE_UNIX_SOCKET: "", NETEASE_COOKIE: cookie, TOGETHER_ENABLED: cookie ? "true" : "false", BRIDGE_PUBLIC_ORIGIN: this.origin };
      delete (env as NodeJS.ProcessEnv).COVE_ADMIN_SECRET;
      // Native and provider logs are intentionally not forwarded to shared hosting logs.
      const child = spawn(process.execPath, [new URL("../server.js", import.meta.url).pathname], { env, stdio: "ignore" });
      this.child = child;
      child.on("error", () => {});
      let exited = false;
      child.once("exit", () => { exited = true; });
      for (let i = 0; i < 100; i++) {
        if (exited) break;
        try {
          const r = await fetch(`http://127.0.0.1:${this.port}/`, { signal: AbortSignal.timeout(300) });
          if (r.ok) return;
        } catch {}
        await delay(100);
      }
      await this.stopChild(); this.cookie = "";
      throw new Error("Private worker failed to start");
  }
  private async stopChild() {
    const child = this.child; this.child = undefined;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>(resolve => {
      const timeout = setTimeout(() => child.kill("SIGKILL"), 3000);
      child.once("exit", () => { clearTimeout(timeout); resolve(); });
      child.kill("SIGTERM");
    });
  }
  async close() { await this.operation; this.cookie = ""; await this.stopChild(); }
}
