import { createHash, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Config } from "./config.js";

export interface Principal {
  subject: string;
  scopes: string[];
}

declare module "express-serve-static-core" {
  interface Request {
    principal?: Principal;
  }
}

const sha = (s: string) => createHash("sha256").update(s).digest();

export function protectedResourceMetadata(cfg: Config) {
  return {
    resource: `${cfg.publicUrl}/mcp`,
    authorization_servers: cfg.oauth.issuer ? [cfg.oauth.issuer] : [],
    bearer_methods_supported: ["header"],
    scopes_supported: cfg.oauth.requiredScope ? [cfg.oauth.requiredScope] : [],
    resource_name: "Local Windows Shell MCP Server",
  };
}

export function makeAuth(cfg: Config) {
  const jwks = cfg.authMode === "oauth" ? createRemoteJWKSet(new URL(cfg.oauth.jwksUrl)) : null;

  const challenge = (res: Response, status: 401 | 403, msg: string) => {
    res
      .status(status)
      .set(
        "WWW-Authenticate",
        `Bearer resource_metadata="${cfg.publicUrl}/.well-known/oauth-protected-resource"` +
          (status === 403 ? ', error="insufficient_scope"' : ', error="invalid_token"'),
      )
      .json({ error: msg });
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    const m = /^Bearer\s+(.+)$/i.exec(req.get("authorization") ?? "");
    if (!m) return challenge(res, 401, "Missing bearer token");
    const token = m[1];

    try {
      if (cfg.authMode === "token") {
        if (!timingSafeEqual(sha(token), sha(cfg.devBearerToken))) return challenge(res, 401, "Invalid token");
        req.principal = { subject: "dev-token", scopes: [] };
        return next();
      }

      const { payload } = await jwtVerify(token, jwks!, {
        issuer: cfg.oauth.issuer,
        audience: cfg.oauth.audience,
      });
      const scopes = String(payload.scope ?? "").split(" ").filter(Boolean)
        .concat(Array.isArray(payload.permissions) ? (payload.permissions as string[]) : []);
      const subject = String(payload.sub ?? "unknown");
      const email = typeof payload.email === "string" ? payload.email : "";

      if (cfg.oauth.requiredScope && !scopes.includes(cfg.oauth.requiredScope))
        return challenge(res, 403, `Missing required scope ${cfg.oauth.requiredScope}`);
      if (cfg.allowedSubjects.length && !cfg.allowedSubjects.includes(subject) && !cfg.allowedSubjects.includes(email))
        return challenge(res, 403, "Subject not allowed");

      req.principal = { subject: email || subject, scopes };
      next();
    } catch {
      challenge(res, 401, "Invalid or expired token");
    }
  };
}

/** Tiny fixed-window per-principal limiter. */
export function makeRateLimiter(limitPerMin: number) {
  const hits = new Map<string, { n: number; reset: number }>();
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.principal?.subject ?? req.ip ?? "anon";
    const now = Date.now();
    const h = hits.get(key);
    if (!h || now > h.reset) hits.set(key, { n: 1, reset: now + 60_000 });
    else if (++h.n > limitPerMin) return void res.status(429).json({ error: "Rate limit exceeded" });
    next();
  };
}
