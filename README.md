# Windows Shell MCP Server

MCP server (TypeScript, Streamable HTTP) that exposes your local **PowerShell** and **cmd.exe** to AI agents through **ngrok**.
It is stateless, OAuth-protected, policy-filtered, audit-logged, and runs as a normal (non-admin) user.

> **Risk:** whoever can authenticate to this server can run commands as the Windows user it runs under.
> Run it as a dedicated low-privilege account, set `ALLOWED_SUBJECTS`, and treat the denylist as a speed bump, not a sandbox.

## Tools (what planners see)

| Tool | Use it for | Type |
|---|---|---|
| `get_system_info` | First call: OS, user, elevation, PowerShell version, mode, limits, allowed folders | read-only |
| `run_powershell` | Windows admin, Get-* cmdlets, services, registry reads, networking, scripting | mutating |
| `run_cmd` | Only cmd-specific syntax (.bat, %VAR%, legacy tools) | mutating |
| `list_processes` | Process listing (name, PID, CPU, MB) | read-only |
| `list_directory` / `read_file` | File browsing/reading inside `ALLOWED_PATHS` | read-only |
| `start_background_job` / `get_job_output` / `cancel_job` | Commands longer than the timeout | mutating / read-only / mutating |

Also exposed: a `shell://policy` resource (active mode, limits, denied categories) and server `instructions` that tell agents how to choose between tools.

## Execution modes (`SHELL_MODE`)

- `standard` (default): everything except a denylist (recursive deletes, disk/registry changes, shutdown, Defender/firewall tampering, account/service/scheduled-task creation, `Invoke-Expression`/`iex`, nested `-EncodedCommand`, credential dumping...). See `src/policy.ts`.
- `read_only`: allowlist of inspection commands only; blocks redirection and state-changing verbs.
- `unrestricted`: no filtering.

Other safeguards: timeouts (default 30s, max 300s), output cap, no stdin (no hanging prompts), process-tree kill, per-user rate limit, Origin check, refuses to start if elevated, JSONL audit log (`logs/audit.jsonl`).

## Setup

1. **Install:** Node 20+, then `npm install && npm run build`.
2. **Create a low-privilege Windows user** (e.g. `mcpsvc`) and run the server as that user. Give it access only to what agents should touch.
3. **ngrok:** reserve a domain in the dashboard (e.g. `your-name.ngrok-free.app`).
4. **Identity provider (OAuth):** use one that supports OAuth 2.1 authorization-code + PKCE and dynamic client registration (Auth0, Okta, Keycloak, Entra ID, ...). Create an API/resource whose identifier (audience) is `https://your-name.ngrok-free.app/mcp`, issuing JWT access tokens. Optionally define a scope like `shell:execute`.
5. **Configure:** copy `.env.example` to `.env` and set `PUBLIC_URL`, `OAUTH_ISSUER`, `OAUTH_AUDIENCE`, and **`ALLOWED_SUBJECTS`** (your user's `sub` or email from the token).
6. **Run:** `npm start`, then in another terminal:
   `ngrok http 8000 --url=your-name.ngrok-free.app --traffic-policy-file=ngrok/policy.yml`
7. **Connect an agent** to `https://your-name.ngrok-free.app/mcp`. The agent hits the server, gets a `401` with a `WWW-Authenticate: Bearer resource_metadata=...` header, discovers your IdP through `/.well-known/oauth-protected-resource`, and runs the OAuth login.

### Why the auth isn't ngrok's `oauth` action
ngrok's `oauth` Traffic Policy action is a browser flow (login redirect + session cookie), so non-browser MCP clients can't complete it. This server is instead an OAuth 2.1 **resource server**: it validates the IdP's JWT (signature via JWKS, issuer, audience, optional scope, optional allowed subjects) and publishes the discovery metadata MCP clients expect. ngrok still provides the stable HTTPS endpoint, rate limiting, and optional IP restriction.

### Local testing without an IdP
`AUTH_MODE=token` with `DEV_BEARER_TOKEN` (32+ random chars) enables a static bearer token. Use only locally. Inspect with `npm run inspect` and connect to `http://127.0.0.1:8000/mcp` with header `Authorization: Bearer <token>`.

## Running as a service
Use NSSM or Task Scheduler as the low-privilege user, e.g. `nssm install ShellMcp "C:\Program Files\nodejs\node.exe" "C:\path\shell-mcp-server\dist\index.js"`, and run ngrok as a service via `ngrok service install` with your config. Kill switch: stop the `ShellMcp` service and the ngrok service.

## Development
`npm run typecheck`, `npm test` (policy unit tests + an end-to-end MCP test using a shell shim, runs on any OS), `npm run dev`.
