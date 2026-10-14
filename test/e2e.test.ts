import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const PORT = 8765;
const TOKEN = "t".repeat(40);
const URL_ = `http://127.0.0.1:${PORT}/mcp`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-e2e-"));
fs.writeFileSync(path.join(tmp, "hello.txt"), "hello world");
const shim = path.resolve("test/fake-shell.mjs");
let proc: ChildProcess;
let client: Client;

before(async () => {
  proc = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], {
    env: { ...process.env, PORT: String(PORT), AUTH_MODE: "token", DEV_BEARER_TOKEN: TOKEN, SHELL_MODE: "standard",
      POWERSHELL_BIN: shim, CMD_BIN: shim, ALLOWED_PATHS: tmp, AUDIT_LOG: path.join(tmp, "audit.jsonl"),
      ALLOW_ELEVATED: "true", DEFAULT_TIMEOUT_SECONDS: "30", MAX_OUTPUT_BYTES: "2000", PUBLIC_URL: "https://x.example" },
    stdio: "pipe",
  });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`http://127.0.0.1:${PORT}/healthz`)).ok) break; } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  client = new Client({ name: "e2e", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(URL_), { requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } } }));
});
after(async () => { try { await Promise.race([client?.close(), new Promise((r) => setTimeout(r, 2000))]); } catch {} proc?.kill("SIGKILL"); });

const call = (name: string, args: Record<string, unknown> = {}) => client.callTool({ name, arguments: args }) as Promise<any>;

test("rejects missing/bad token with OAuth discovery challenge", async () => {
  const r = await fetch(URL_, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(r.status, 401);
  assert.match(r.headers.get("www-authenticate") ?? "", /resource_metadata="https:\/\/x\.example\/\.well-known\/oauth-protected-resource"/);
  const bad = await fetch(URL_, { method: "POST", headers: { authorization: "Bearer nope", "content-type": "application/json" }, body: "{}" });
  assert.equal(bad.status, 401);
  const meta = await (await fetch(`http://127.0.0.1:${PORT}/.well-known/oauth-protected-resource`)).json() as any;
  assert.equal(meta.resource, "https://x.example/mcp");
});

test("rejects browser origins", async () => {
  const r = await fetch(URL_, { method: "POST", headers: { origin: "https://evil.example", authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: "{}" });
  assert.equal(r.status, 403);
});

test("advertises identifiable, well-described tools", async () => {
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ["cancel_job", "get_job_output", "get_system_info", "list_directory", "list_processes", "read_file", "run_cmd", "run_powershell", "start_background_job"]);
  for (const t of tools) {
    assert.ok(t.description && t.description.length > 40, `${t.name} needs a real description`);
    assert.ok(t.annotations, `${t.name} needs annotations`);
    assert.ok(t.outputSchema, `${t.name} needs an output schema`);
  }
  assert.equal(tools.find((t) => t.name === "run_powershell")!.annotations!.destructiveHint, true);
  assert.equal(tools.find((t) => t.name === "read_file")!.annotations!.readOnlyHint, true);
  assert.match(client.getInstructions() ?? "", /get_system_info/);
  assert.equal(client.getServerVersion()?.name, "windows-shell-mcp");
  const res = await client.listResources();
  assert.ok(res.resources.some((r) => r.uri === "shell://policy"));
});

test("get_system_info and policy resource", async () => {
  const r = await call("get_system_info");
  assert.equal(r.structuredContent.policy_mode, "standard");
  assert.equal(r.structuredContent.powershell_version, "7.4.0");
  const pol = await client.readResource({ uri: "shell://policy" });
  assert.match(String((pol.contents[0] as any).text), /recursive-delete/);
});

test("runs commands in both shells and captures output/exit code", async () => {
  const a = await call("run_powershell", { command: "echo hi-ps; echo oops 1>&2; exit 3" });
  assert.equal(a.structuredContent.exit_code, 3);
  assert.match(a.structuredContent.stdout, /hi-ps/);
  assert.match(a.structuredContent.stderr, /oops/);
  const b = await call("run_cmd", { command: "echo hi-cmd" });
  assert.equal(b.structuredContent.exit_code, 0);
  assert.match(b.structuredContent.stdout, /hi-cmd/);
});

test("policy denial, timeout and output cap", async () => {
  const d = await call("run_powershell", { command: "Remove-Item x -Recurse" });
  assert.equal(d.isError, true);
  assert.match(d.content[0].text, /REJECTED/);
  const t = await call("run_powershell", { command: "sleep 10", timeout_seconds: 1 });
  assert.equal(t.structuredContent.timed_out, true);
  const big = await call("run_powershell", { command: "yes aaaaaaaaaa | head -c 100000" });
  assert.equal(big.structuredContent.truncated, true);
  assert.ok(big.structuredContent.stdout.length <= 2000);
});

test("file tools stay inside allowed folders", async () => {
  const ok = await call("list_directory", { path: tmp });
  assert.ok(ok.structuredContent.entries.some((e: any) => e.name === "hello.txt"));
  const rd = await call("read_file", { path: path.join(tmp, "hello.txt") });
  assert.equal(rd.structuredContent.content, "hello world");
  const out = await call("list_directory", { path: "/etc" });
  assert.equal(out.isError, true);
  const trav = await call("read_file", { path: path.join(tmp, "..", "..", "etc", "passwd") });
  assert.equal(trav.isError, true);
});

test("background jobs: start, poll, cancel", async () => {
  const s = await call("start_background_job", { command: "echo started; sleep 30" });
  const id = s.structuredContent.job_id;
  await new Promise((r) => setTimeout(r, 600));
  const o = await call("get_job_output", { job_id: id });
  assert.equal(o.structuredContent.status, "running");
  assert.match(o.structuredContent.stdout, /started/);
  await call("cancel_job", { job_id: id });
  await new Promise((r) => setTimeout(r, 600));
  assert.equal((await call("get_job_output", { job_id: id })).structuredContent.status, "finished");
});

test("audit log records allowed and denied calls", () => {
  const lines = fs.readFileSync(path.join(tmp, "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(lines.some((l) => l.decision === "denied" && l.tool === "run_powershell"));
  assert.ok(lines.some((l) => l.decision === "allowed" && l.tool === "run_cmd"));
});
