import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Audit } from "./audit.js";
import { makeAuth, makeRateLimiter, protectedResourceMetadata } from "./auth.js";
import { loadConfig } from "./config.js";
import { JobManager } from "./jobs.js";
import { isElevated } from "./shell.js";
import { createServer } from "./tools.js";

const cfg = loadConfig();
if (isElevated() && !cfg.allowElevated) {
  console.error("Refusing to start: process is elevated (Administrator/root). Run as a normal user, or set ALLOW_ELEVATED=true (not recommended).");
  process.exit(1);
}

const audit = new Audit(cfg.auditLog);
const jobs = new JobManager(cfg);
const app = express();
app.set("trust proxy", 1); // behind ngrok
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// Unauthenticated, non-sensitive endpoints
app.get("/healthz", (_req, res) => void res.json({ ok: true }));
const prm = (_req: express.Request, res: express.Response) => void res.json(protectedResourceMetadata(cfg));
app.get("/.well-known/oauth-protected-resource", prm);
app.get("/.well-known/oauth-protected-resource/mcp", prm);

// Reject browser cross-origin calls (DNS-rebinding / CSRF style abuse). MCP clients send no Origin.
const originGuard: express.RequestHandler = (req, res, next) => {
  const origin = req.get("origin");
  if (origin && !cfg.allowedOrigins.includes(origin)) return void res.status(403).json({ error: "Origin not allowed" });
  next();
};

app.post("/mcp", originGuard, makeAuth(cfg), makeRateLimiter(cfg.rateLimitPerMin), async (req, res) => {
  // Stateless: a fresh server + transport per request (works with multiple agents and ngrok pooling).
  const server = createServer(cfg, audit, jobs, req.principal!.subject);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("[mcp] error:", err);
    if (!res.headersSent)
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
  }
});

const notAllowed: express.RequestHandler = (_req, res) =>
  void res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server)" }, id: null });
app.get("/mcp", notAllowed);
app.delete("/mcp", notAllowed);

app.listen(cfg.port, cfg.host, () => {
  console.log(`windows-shell-mcp listening on http://${cfg.host}:${cfg.port}/mcp`);
  console.log(`  mode=${cfg.mode} auth=${cfg.authMode} public=${cfg.publicUrl}/mcp`);
  console.log(`  audit log: ${cfg.auditLog}`);
});
