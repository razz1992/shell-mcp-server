import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Audit } from "./audit.js";
import type { Config } from "./config.js";
import type { JobManager } from "./jobs.js";
import { describePolicy, evaluate, type ShellKind } from "./policy.js";
import { isElevated, startShell, type ExecResult } from "./shell.js";

export const SERVER_INSTRUCTIONS = `
This server controls ONE Windows machine (the user's own PC) through PowerShell and cmd.exe.
Commands run as a normal, non-administrator user. Start with get_system_info to learn the OS, current mode and limits.

Choosing a tool:
- Inspect files: use list_directory / read_file (read-only, restricted to allowed folders). Do not shell out for this.
- Windows administration, services, registry reads, networking, scripting: run_powershell (preferred shell).
- .bat/cmd-specific syntax or legacy tools only: run_cmd.
- Anything expected to take longer than ~30 seconds (builds, installs, long scans): start_background_job, then poll get_job_output.
- Read-only process listing: list_processes.

Rules: every command is audit-logged. Destructive actions (recursive deletes, disk/registry changes, shutdown, security or account changes, nested/encoded commands) are rejected by policy; read shell://policy for the exact rules. If a command is rejected, do not try to obfuscate it; ask the user instead. Output is capped; narrow your command (Select-Object, -First, Where-Object) rather than dumping everything.
`.trim();

const execOutput = {
  shell: z.enum(["powershell", "cmd"]).describe("Shell that ran the command"),
  exit_code: z.number().nullable().describe("Process exit code; null if it failed to start or was killed"),
  stdout: z.string().describe("Standard output (UTF-8), possibly truncated"),
  stderr: z.string().describe("Standard error, possibly truncated"),
  timed_out: z.boolean().describe("True if the command was killed for exceeding its timeout"),
  truncated: z.boolean().describe("True if output exceeded the size cap"),
  duration_ms: z.number().describe("Wall-clock runtime in milliseconds"),
};

const text = (r: ExecResult) =>
  [
    `exit_code: ${r.exit_code}${r.timed_out ? " (TIMED OUT)" : ""}${r.truncated ? " (output truncated)" : ""}`,
    r.stdout && `--- stdout ---\n${r.stdout}`,
    r.stderr && `--- stderr ---\n${r.stderr}`,
  ].filter(Boolean).join("\n");

const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true as const });

export function createServer(cfg: Config, audit: Audit, jobs: JobManager, subject: string) {
  const server = new McpServer(
    { name: "windows-shell-mcp", title: "Windows PowerShell & CMD Shell", version: "0.1.0" },
    { instructions: SERVER_INSTRUCTIONS },
  );

  const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
  const mutating = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true };

  const clampTimeout = (s?: number) => Math.min(s ?? cfg.defaultTimeoutSec, cfg.maxTimeoutSec) * 1000;

  // Guard for file tools: resolve symlinks and require the path to sit inside an allowed root.
  const safePath = async (p: string) => {
    const real = await fs.realpath(path.resolve(p));
    const norm = (s: string) => (process.platform === "win32" ? s.toLowerCase() : s);
    const ok = cfg.allowedPaths.some((root) => {
      const rel = path.relative(norm(root), norm(real));
      return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
    });
    if (!ok) throw new Error(`Path is outside the allowed folders: ${cfg.allowedPaths.join(", ")}`);
    return real;
  };

  // ---------- shared handler for the two shells ----------
  const runTool = (shell: ShellKind, tool: string) =>
    async ({ command, working_directory, timeout_seconds }: { command: string; working_directory?: string; timeout_seconds?: number }) => {
      const verdict = evaluate(shell, command, cfg.mode);
      if (!verdict.allowed) {
        audit.log({ subject, tool, decision: "denied", detail: `${verdict.reason} :: ${command}` });
        return fail(`REJECTED by policy (${cfg.mode} mode): ${verdict.reason} Do not retry with obfuscation; ask the user.`);
      }
      const r = await startShell(cfg, {
        shell, command, cwd: working_directory,
        timeoutMs: clampTimeout(timeout_seconds), maxOutputBytes: cfg.maxOutputBytes,
      }).done;
      audit.log({ subject, tool, decision: "allowed", detail: command, exit_code: r.exit_code, duration_ms: r.duration_ms });
      return { content: [{ type: "text" as const, text: text(r) }], structuredContent: { shell, ...r } };
    };

  const execInput = {
    command: z.string().min(1).max(20000).describe("The command or multi-line script to run"),
    working_directory: z.string().optional().describe("Absolute directory to run in. Defaults to the server's directory."),
    timeout_seconds: z.number().int().positive().optional()
      .describe(`Kill the command after this many seconds (default ${cfg.defaultTimeoutSec}, max ${cfg.maxTimeoutSec}). Use start_background_job for longer work.`),
  };

  server.registerTool("run_powershell", {
    title: "Run PowerShell command",
    description:
      "Execute a PowerShell command or script on the user's Windows PC and return stdout, stderr and exit code. " +
      "Use for Windows administration, Get-* cmdlets, services, registry reads, networking, file operations and scripting. " +
      "Runs as a normal non-admin user with -NoProfile -NonInteractive (no prompts; commands needing input will fail). " +
      "Prefer list_directory/read_file for plain file inspection and list_processes for process lists. " +
      "Use run_cmd only for .bat/cmd syntax. Policy-blocked commands are rejected without running. " +
      `Default timeout ${cfg.defaultTimeoutSec}s; use start_background_job for longer tasks. Output is capped at ${cfg.maxOutputBytes} bytes.`,
    inputSchema: execInput,
    outputSchema: execOutput,
    annotations: { title: "Run PowerShell command", ...mutating },
  }, runTool("powershell", "run_powershell"));

  server.registerTool("run_cmd", {
    title: "Run cmd.exe command",
    description:
      "Execute a command line in cmd.exe (Command Prompt) on the user's Windows PC and return stdout, stderr and exit code. " +
      "Use ONLY when cmd-specific syntax is required (batch builtins like dir/type/set, %VAR% expansion, .bat files, legacy tools). " +
      "For everything else use run_powershell. Runs non-interactively as a normal user; policy-blocked commands are rejected. " +
      `Default timeout ${cfg.defaultTimeoutSec}s. Output capped at ${cfg.maxOutputBytes} bytes.`,
    inputSchema: execInput,
    outputSchema: execOutput,
    annotations: { title: "Run cmd.exe command", ...mutating },
  }, runTool("cmd", "run_cmd"));

  // ---------- diagnostics ----------
  server.registerTool("get_system_info", {
    title: "Get system info",
    description:
      "Return facts about the machine and this server: OS, hostname, user, whether the server is elevated, PowerShell version, active policy mode, timeouts, output cap and allowed file folders. " +
      "Call this FIRST to plan safely. Does not modify anything.",
    inputSchema: {},
    outputSchema: {
      os: z.string(), hostname: z.string(), user: z.string(), elevated: z.boolean(),
      powershell_version: z.string().nullable(), policy_mode: z.string(),
      default_timeout_seconds: z.number(), max_timeout_seconds: z.number(),
      max_output_bytes: z.number(), allowed_paths: z.array(z.string()), working_directory: z.string(),
    },
    annotations: { title: "Get system info", ...readOnly },
  }, async () => {
    const ps = await startShell(cfg, {
      shell: "powershell", command: "$PSVersionTable.PSVersion.ToString()", timeoutMs: 10_000, maxOutputBytes: 1024,
    }).done;
    const info = {
      os: `${os.type()} ${os.release()} (${os.arch()})`, hostname: os.hostname(), user: os.userInfo().username,
      elevated: isElevated(), powershell_version: ps.exit_code === 0 ? ps.stdout.trim() : null,
      policy_mode: cfg.mode, default_timeout_seconds: cfg.defaultTimeoutSec, max_timeout_seconds: cfg.maxTimeoutSec,
      max_output_bytes: cfg.maxOutputBytes, allowed_paths: cfg.allowedPaths, working_directory: process.cwd(),
    };
    audit.log({ subject, tool: "get_system_info", decision: "allowed" });
    return { content: [{ type: "text" as const, text: JSON.stringify(info, null, 2) }], structuredContent: info };
  });

  server.registerTool("list_processes", {
    title: "List processes",
    description:
      "List running processes (name, PID, CPU seconds, memory MB), sorted by memory use, optionally filtered by name. Read-only. Use this instead of run_powershell for process inspection.",
    inputSchema: {
      name_filter: z.string().regex(/^[\w.*-]{0,64}$/).optional().describe("Wildcard on process name, e.g. 'chrome*'"),
      limit: z.number().int().min(1).max(200).default(30).describe("Maximum rows to return"),
    },
    outputSchema: { processes: z.array(z.object({ name: z.string(), id: z.number(), cpu_seconds: z.number().nullable(), memory_mb: z.number() })) },
    annotations: { title: "List processes", ...readOnly },
  }, async ({ name_filter, limit }) => {
    const filter = name_filter ? `-Name '${name_filter}'` : "";
    const cmd = `@(Get-Process ${filter} -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First ${limit} @{n='name';e={$_.ProcessName}}, @{n='id';e={$_.Id}}, @{n='cpu_seconds';e={if($_.CPU){[math]::Round($_.CPU,1)}else{$null}}}, @{n='memory_mb';e={[math]::Round($_.WorkingSet64/1MB,1)}}) | ConvertTo-Json -Compress`;
    const r = await startShell(cfg, { shell: "powershell", command: cmd, timeoutMs: 20_000, maxOutputBytes: cfg.maxOutputBytes }).done;
    audit.log({ subject, tool: "list_processes", decision: r.exit_code === 0 ? "allowed" : "error", exit_code: r.exit_code });
    if (r.exit_code !== 0) return fail(r.stderr || "Failed to list processes");
    const parsed = r.stdout.trim() ? JSON.parse(r.stdout) : [];
    const processes = Array.isArray(parsed) ? parsed : [parsed];
    return { content: [{ type: "text" as const, text: JSON.stringify(processes) }], structuredContent: { processes } };
  });

  // ---------- file tools ----------
  server.registerTool("list_directory", {
    title: "List directory",
    description:
      "List files and folders in a directory (name, type, size, modified time). Read-only and restricted to the allowed folders reported by get_system_info. Use this instead of 'dir' or Get-ChildItem for simple browsing.",
    inputSchema: {
      path: z.string().describe("Absolute directory path"),
      limit: z.number().int().min(1).max(1000).default(200).describe("Maximum entries to return"),
    },
    outputSchema: {
      path: z.string(), truncated: z.boolean(),
      entries: z.array(z.object({ name: z.string(), type: z.enum(["file", "directory", "other"]), size_bytes: z.number().nullable(), modified: z.string().nullable() })),
    },
    annotations: { title: "List directory", ...readOnly },
  }, async ({ path: p, limit }) => {
    try {
      const dir = await safePath(p);
      const names = await fs.readdir(dir, { withFileTypes: true });
      const entries = await Promise.all(names.slice(0, limit).map(async (d) => {
        const st = await fs.stat(path.join(dir, d.name)).catch(() => null);
        return {
          name: d.name, type: d.isDirectory() ? "directory" as const : d.isFile() ? "file" as const : "other" as const,
          size_bytes: st && d.isFile() ? st.size : null, modified: st ? st.mtime.toISOString() : null,
        };
      }));
      audit.log({ subject, tool: "list_directory", decision: "allowed", detail: dir });
      const out = { path: dir, truncated: names.length > limit, entries };
      return { content: [{ type: "text" as const, text: JSON.stringify(out) }], structuredContent: out };
    } catch (e) {
      audit.log({ subject, tool: "list_directory", decision: "error", detail: `${p}: ${(e as Error).message}` });
      return fail((e as Error).message);
    }
  });

  server.registerTool("read_file", {
    title: "Read text file",
    description:
      "Read the beginning of a text file (UTF-8). Read-only and restricted to the allowed folders. Use for config files, logs and source code; for large logs prefer run_powershell with Get-Content -Tail.",
    inputSchema: {
      path: z.string().describe("Absolute file path"),
      max_bytes: z.number().int().min(1).max(1_000_000).optional().describe(`Bytes to read (default/max follows server cap ${cfg.maxOutputBytes})`),
    },
    outputSchema: { path: z.string(), size_bytes: z.number(), truncated: z.boolean(), content: z.string() },
    annotations: { title: "Read text file", ...readOnly },
  }, async ({ path: p, max_bytes }) => {
    try {
      const file = await safePath(p);
      const cap = Math.min(max_bytes ?? cfg.maxOutputBytes, cfg.maxOutputBytes);
      const fh = await fs.open(file, "r");
      try {
        const { size } = await fh.stat();
        const buf = Buffer.alloc(Math.min(cap, size));
        await fh.read(buf, 0, buf.length, 0);
        const out = { path: file, size_bytes: size, truncated: size > buf.length, content: buf.toString("utf8") };
        audit.log({ subject, tool: "read_file", decision: "allowed", detail: file });
        return { content: [{ type: "text" as const, text: out.content }], structuredContent: out };
      } finally {
        await fh.close();
      }
    } catch (e) {
      audit.log({ subject, tool: "read_file", decision: "error", detail: `${p}: ${(e as Error).message}` });
      return fail((e as Error).message);
    }
  });

  // ---------- background jobs ----------
  server.registerTool("start_background_job", {
    title: "Start background job",
    description:
      "Start a long-running PowerShell or cmd command without blocking (builds, installs, long scans, watchers). Returns a job_id immediately; poll get_job_output and stop with cancel_job. Same policy checks as run_powershell/run_cmd. Limited concurrent jobs.",
    inputSchema: {
      shell: z.enum(["powershell", "cmd"]).default("powershell"),
      command: z.string().min(1).max(20000),
      working_directory: z.string().optional(),
    },
    outputSchema: { job_id: z.string(), status: z.string() },
    annotations: { title: "Start background job", ...mutating },
  }, async ({ shell, command, working_directory }) => {
    const verdict = evaluate(shell, command, cfg.mode);
    if (!verdict.allowed) {
      audit.log({ subject, tool: "start_background_job", decision: "denied", detail: `${verdict.reason} :: ${command}` });
      return fail(`REJECTED by policy (${cfg.mode} mode): ${verdict.reason}`);
    }
    const job = jobs.start(subject, shell, command, working_directory);
    if ("error" in job) return fail(job.error);
    audit.log({ subject, tool: "start_background_job", decision: "allowed", detail: `[${job.id}] ${command}` });
    const out = { job_id: job.id, status: "running" };
    return { content: [{ type: "text" as const, text: JSON.stringify(out) }], structuredContent: out };
  });

  server.registerTool("get_job_output", {
    title: "Get background job output",
    description: "Return status and the most recent output (tail) of a background job, or list all jobs if job_id is omitted. Read-only.",
    inputSchema: { job_id: z.string().optional().describe("Job id from start_background_job; omit to list all jobs") },
    outputSchema: {
      jobs: z.array(z.object({ job_id: z.string(), shell: z.string(), status: z.string(), started_at: z.string(), command: z.string() })).optional(),
      job_id: z.string().optional(), status: z.string().optional(), exit_code: z.number().nullable().optional(),
      stdout: z.string().optional(), stderr: z.string().optional(), truncated: z.boolean().optional(),
    },
    annotations: { title: "Get background job output", ...readOnly },
  }, async ({ job_id }) => {
    if (!job_id) {
      const out = { jobs: jobs.list() };
      return { content: [{ type: "text" as const, text: JSON.stringify(out) }], structuredContent: out };
    }
    const j = jobs.get(job_id);
    if (!j) return fail(`No such job: ${job_id}`);
    const snap = j.result ?? j.running.snapshot();
    const out = {
      job_id, status: j.result ? "finished" : "running", exit_code: j.result ? j.result.exit_code : null,
      stdout: snap.stdout, stderr: snap.stderr, truncated: snap.truncated,
    };
    return { content: [{ type: "text" as const, text: JSON.stringify(out) }], structuredContent: out };
  });

  server.registerTool("cancel_job", {
    title: "Cancel background job",
    description: "Stop a running background job and its child processes. Safe to call on finished jobs.",
    inputSchema: { job_id: z.string() },
    outputSchema: { job_id: z.string(), cancelled: z.boolean() },
    annotations: { title: "Cancel background job", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  }, async ({ job_id }) => {
    const ok = jobs.cancel(job_id);
    audit.log({ subject, tool: "cancel_job", decision: ok ? "allowed" : "error", detail: job_id });
    if (!ok) return fail(`No such job: ${job_id}`);
    const out = { job_id, cancelled: true };
    return { content: [{ type: "text" as const, text: JSON.stringify(out) }], structuredContent: out };
  });

  // ---------- resource ----------
  server.registerResource("policy", "shell://policy", {
    title: "Execution policy",
    description: "The active execution mode, limits and the exact categories of commands that are rejected. Read before planning destructive work.",
    mimeType: "application/json",
  }, async (uri) => ({
    contents: [{
      uri: uri.href, mimeType: "application/json",
      text: JSON.stringify({
        ...describePolicy(cfg.mode),
        limits: { default_timeout_seconds: cfg.defaultTimeoutSec, max_timeout_seconds: cfg.maxTimeoutSec, max_output_bytes: cfg.maxOutputBytes, max_background_jobs: cfg.maxJobs },
        allowed_paths_for_file_tools: cfg.allowedPaths,
      }, null, 2),
    }],
  }));

  return server;
}
