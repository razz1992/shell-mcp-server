import { spawn, spawnSync } from "node:child_process";
import type { Config } from "./config.js";
import type { ShellKind } from "./policy.js";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exit_code: number | null;
  timed_out: boolean;
  truncated: boolean;
  duration_ms: number;
}

export interface ExecOptions {
  shell: ShellKind;
  command: string;
  cwd?: string;
  timeoutMs: number;
  maxOutputBytes: number;
  /** "head" keeps the first bytes (foreground); "tail" keeps the most recent (background jobs). */
  keep?: "head" | "tail";
}

export interface Running {
  pid: number | undefined;
  done: Promise<ExecResult>;
  kill(): void;
  snapshot(): { stdout: string; stderr: string; truncated: boolean };
}

class Capture {
  private chunks: Buffer[] = [];
  private bytes = 0;
  truncated = false;
  constructor(private cap: number, private mode: "head" | "tail") {}
  push(b: Buffer) {
    if (this.mode === "head") {
      if (this.bytes >= this.cap) return void (this.truncated = true);
      const room = this.cap - this.bytes;
      if (b.length > room) {
        this.chunks.push(b.subarray(0, room));
        this.bytes += room;
        this.truncated = true;
      } else {
        this.chunks.push(b);
        this.bytes += b.length;
      }
    } else {
      this.chunks.push(b);
      this.bytes += b.length;
      if (this.bytes > this.cap * 2) {
        const all = Buffer.concat(this.chunks);
        this.chunks = [all.subarray(all.length - this.cap)];
        this.bytes = this.cap;
        this.truncated = true;
      }
    }
  }
  text() {
    let all = Buffer.concat(this.chunks);
    if (this.mode === "tail" && all.length > this.cap) {
      all = all.subarray(all.length - this.cap);
      this.truncated = true;
    }
    return all.toString("utf8");
  }
}

function buildSpawn(cfg: Config, shell: ShellKind, command: string) {
  if (shell === "powershell") {
    // -EncodedCommand avoids every quoting/escaping pitfall for multi-line scripts.
    const wrapped = `$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ${command}`;
    const enc = Buffer.from(wrapped, "utf16le").toString("base64");
    return {
      file: cfg.powershellBin,
      args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
      verbatim: false,
    };
  }
  // cmd.exe: /d skips AutoRun, /s + outer quotes preserve the command line verbatim.
  return { file: cfg.cmdBin, args: ["/d", "/s", "/c", `"${command}"`], verbatim: true };
}

function killTree(pid: number | undefined, child: { kill(sig?: NodeJS.Signals): boolean }) {
  if (pid && process.platform === "win32") {
    spawnSync("taskkill", ["/pid", String(pid), "/t", "/f"], { windowsHide: true });
  } else if (pid) {
    try {
      process.kill(-pid, "SIGKILL"); // whole process group (child was spawned detached)
    } catch {
      child.kill("SIGKILL");
    }
  } else {
    child.kill("SIGKILL");
  }
}

export function startShell(cfg: Config, o: ExecOptions): Running {
  const t0 = Date.now();
  const { file, args, verbatim } = buildSpawn(cfg, o.shell, o.command);
  const out = new Capture(o.maxOutputBytes, o.keep ?? "head");
  const err = new Capture(o.maxOutputBytes, o.keep ?? "head");
  let timedOut = false;

  const child = spawn(file, args, {
    cwd: o.cwd,
    windowsHide: true,
    windowsVerbatimArguments: verbatim,
    detached: process.platform !== "win32", // own process group so timeouts/cancel kill the whole tree
    stdio: ["ignore", "pipe", "pipe"], // no stdin: interactive prompts fail fast instead of hanging
  });
  child.stdout.on("data", (b: Buffer) => out.push(b));
  child.stderr.on("data", (b: Buffer) => err.push(b));

  const timer = setTimeout(() => {
    timedOut = true;
    killTree(child.pid, child);
  }, o.timeoutMs);

  const done = new Promise<ExecResult>((resolve) => {
    const finish = (code: number | null, extraErr = "") => {
      clearTimeout(timer);
      resolve({
        stdout: out.text(),
        stderr: err.text() + extraErr,
        exit_code: code,
        timed_out: timedOut,
        truncated: out.truncated || err.truncated,
        duration_ms: Date.now() - t0,
      });
    };
    child.on("error", (e) => finish(null, `Failed to start '${file}': ${e.message}`));
    child.on("close", (code) => finish(code));
  });

  return {
    pid: child.pid,
    done,
    kill: () => killTree(child.pid, child),
    snapshot: () => ({ stdout: out.text(), stderr: err.text(), truncated: out.truncated || err.truncated }),
  };
}

/** True when the current process is an elevated Administrator (Windows only). */
export function isElevated(): boolean {
  if (process.platform !== "win32") return typeof process.getuid === "function" && process.getuid() === 0;
  return spawnSync("net", ["session"], { windowsHide: true, stdio: "ignore" }).status === 0;
}
