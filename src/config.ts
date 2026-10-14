import "dotenv/config";
import os from "node:os";
import path from "node:path";

export type ShellMode = "read_only" | "standard" | "unrestricted";
export type AuthMode = "oauth" | "token";

const list = (v?: string) =>
  (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const int = (v: string | undefined, d: number) => {
  const n = Number.parseInt(v ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : d;
};
const bool = (v: string | undefined) => (v ?? "").toLowerCase() === "true";

export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const port = int(env.PORT, 8000);
  const mode = (env.SHELL_MODE ?? "standard") as ShellMode;
  const authMode = (env.AUTH_MODE ?? "oauth") as AuthMode;
  if (!["read_only", "standard", "unrestricted"].includes(mode))
    throw new Error(`Invalid SHELL_MODE: ${mode}`);
  if (!["oauth", "token"].includes(authMode))
    throw new Error(`Invalid AUTH_MODE: ${authMode}`);

  const publicUrl = (env.PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/+$/, "");
  const issuer = env.OAUTH_ISSUER ?? "";
  const cfg = {
    port,
    host: env.HOST ?? "127.0.0.1",
    publicUrl,
    mode,
    authMode,
    defaultTimeoutSec: int(env.DEFAULT_TIMEOUT_SECONDS, 30),
    maxTimeoutSec: int(env.MAX_TIMEOUT_SECONDS, 300),
    maxOutputBytes: int(env.MAX_OUTPUT_BYTES, 65536),
    maxJobs: int(env.MAX_BACKGROUND_JOBS, 5),
    rateLimitPerMin: int(env.RATE_LIMIT_PER_MINUTE, 60),
    allowedPaths: (list(env.ALLOWED_PATHS).length ? list(env.ALLOWED_PATHS) : [os.homedir()]).map((p) =>
      path.resolve(p),
    ),
    allowElevated: bool(env.ALLOW_ELEVATED),
    oauth: {
      issuer,
      audience: env.OAUTH_AUDIENCE ?? `${publicUrl}/mcp`,
      jwksUrl:
        env.OAUTH_JWKS_URL ||
        (issuer ? new URL(".well-known/jwks.json", issuer.endsWith("/") ? issuer : issuer + "/").href : ""),
      requiredScope: env.OAUTH_REQUIRED_SCOPE || "",
    },
    allowedSubjects: list(env.ALLOWED_SUBJECTS),
    devBearerToken: env.DEV_BEARER_TOKEN ?? "",
    allowedOrigins: list(env.ALLOWED_ORIGINS),
    powershellBin: env.POWERSHELL_BIN ?? "powershell.exe",
    cmdBin: env.CMD_BIN ?? "cmd.exe",
    auditLog: path.resolve(env.AUDIT_LOG ?? "logs/audit.jsonl"),
  };

  if (authMode === "oauth") {
    if (!cfg.oauth.issuer) throw new Error("AUTH_MODE=oauth requires OAUTH_ISSUER");
    if (!cfg.allowedSubjects.length)
      console.warn(
        "[warn] ALLOWED_SUBJECTS is empty: ANY valid token from your IdP/audience can run commands. Set it to your own identity.",
      );
  } else if (cfg.devBearerToken.length < 32) {
    throw new Error("AUTH_MODE=token requires DEV_BEARER_TOKEN of at least 32 characters");
  }
  return cfg;
}

export type Config = ReturnType<typeof loadConfig>;
