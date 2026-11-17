# cf-d1-vault

MIT-licensed TypeScript credential vault and stateless remote MCP gateway for Cloudflare Workers Free + D1. Any MCP agent — Claude Code, Cursor, Cline, Codex, Pi, or any Streamable HTTP client — holds a request-only bearer; the vault admin controls administration and two-hour grants. Keys stay inside the Worker — no agent ever sees one.

## What it is

A vault for **every service, not one**. A key is three things only:

- **service** — a short slug: `github`, `cloudflare`, `openrouter`, … or any custom slug
- **label** — a key name, e.g. `work`
- **website** — the API base the key belongs to, e.g. `https://api.github.com`
- **secret** — the value itself: a classic PAT, a fine-grained PAT, any API key

There is no stored repo/branch/path policy. What the agent may do with a key is said **in chat** — "read README.md in 0xsatwik/cf-d1-vault on main" — not stored in the vault. The grant is the boundary: one agent, one service, one key label, two hours. When the window closes, the agent asks the admin to unlock again.

## How the whole system fits together

```text
Trusted admin environment / human browser
  holds: raw high-entropy master, upstream key during entry
  POST /admin/agents  -> register SHA-256 bearer hash
  POST /admin/keys    -> add / rotate / disable / enable / delete encrypted key rows
  POST /unlock        -> agent + service + key label, 7200 seconds
  POST /revoke        -> grant / agent / key
              | HTTPS Authorization: Bearer <MASTER_SECRET>
              v
Cloudflare Worker (trusted code and deployment boundary)
  MASTER_SHA256 secret: verifies the admin; raw master is not persisted
  HUMAN_SHA256 secret: second password, add-keys + list-keys only
  VAULT_DEK_V1 / V2 secrets: independent AES-256-GCM encryption keys
  /mcp: official SDK, stateless Streamable HTTP, POST JSON responses
  grants: agent + service + key label, fresh D1 primary reads, no cache
  GitHub adapter: fixed origin, exact file/issue calls, bounded results
  service_request: generic proxy — Worker calls the key's website
       | D1 binding                         | HTTPS Bearer <key>
       v                                    v
D1 primary                            api.github.com, api.cloudflare.com,
  keys: service + label + website +         openrouter.ai, ... (any website)
        ciphertext + nonce + AAD identity
  agents: token hash
  grants: opened_at, expires_at, revoked_at
  audit: metadata only
  write_operations: durable dispatch reservations
       ^
       | fresh checks before each dispatch; no authorization cache
       |
Any MCP agent (Claude Code, Cursor, Cline, Codex, Pi, ...)
  holds: Worker URL + request-only bearer
  receives: selected tool results or unlock_required
  asks the admin when locked; cannot unlock itself
```

The DEK and the master are independent. An unlock authorizes use; it does not load a transient DEK or start an isolate timer. Worker restarts do not extend grants. No KV, Durable Objects, OAuth server, VM, Pages deployment, paid plan, or local stdio proxy is required. Static Assets serves the manual-entry page from the same Worker.

## Services, pre-filled

The frontend's service list is pre-filled from the services named in the [Rakazo](https://github.com/elie222/rakazo) project, plus the ones this vault itself runs on. Each fills in its API website automatically (editable — any website works):

| Service | Website |
| --- | --- |
| github | https://api.github.com |
| cloudflare | https://api.cloudflare.com |
| openrouter | https://openrouter.ai/api/v1 |
| openai | https://api.openai.com/v1 |
| anthropic | https://api.anthropic.com |
| google | https://generativelanguage.googleapis.com/v1beta |
| composio | https://backend.composio.dev |
| pipedream | https://api.pipedream.com |
| e2b | https://api.e2b.dev |
| daytona | https://app.daytona.io/api |
| boat | (fill in the website) |
| slack | https://slack.com/api |
| telegram | https://api.telegram.org |
| gmail | https://gmail.googleapis.com/gmail/v1 |
| google-calendar | https://www.googleapis.com/calendar/v3 |
| notion | https://api.notion.com |
| linear | https://api.linear.app |
| resend | https://api.resend.com |
| expo | https://exp.host |

Any other service works too: type its slug and website. Token type does not matter — classic PAT, fine-grained PAT, API key, all stored as an opaque value.

## Manual page

Open the Worker URL in a browser. One password field, two levels:

- **Human password** (owner-chosen): add, rotate, disable, delete and enable keys, and view the key list. Unlock, revoke and agents stay master-only.
- **Master password** (admin-held): everything — add, rotate, disable, enable, delete, unlock, revoke, agents.

Add a key asks for service, key name, website, key value — nothing else. Unlock for an agent asks for agent, service, key name — two hours. The signed-in state is a green banner ("Signed in as Key contributor" / "Signed in as Owner") with a Sign out button; the password form hides while signed in. Wrong password shows red "Password not recognized." Keys list shows service, label, website, status and ID. Secret values are never shown.

API docs live at `/llms.txt` and `/llm.txt` (identical), linked from the footer.

## API

Base URL: the exact configured `PUBLIC_ORIGIN`, no trailing slash. All responses `Cache-Control: no-store`. No secret retrieval/export endpoint exists. Full reference: `public/llms.txt`.

Auth: `Authorization: Bearer <credential>` on every authenticated call. Master is checked before human. Missing/invalid credentials return 401; a valid human attempting a master operation gets 403.

- `GET /whoami` → `{"role":"master"|"human"}`
- `GET /admin/keys` → `{"keys":[{"id","service","label","website","enc_version","enabled"}],"limit":100}`
- `POST /admin/keys` — `{"action":"add"|"rotate"|"disable"|"enable"|"delete","service","label","website","secret","request_id"}`. `disable`, `enable` and `delete` take only service, label, request_id. Rotate and disable revoke all live grants for the key; enable does not revive them. `delete` hard-deletes the key row plus its grants and write idempotency rows (audit history stays); it cannot be undone. Human sign-in can add, rotate, disable, enable and delete; unlock, revoke and agents stay master-only. A label must be unique per service. `secret` is 1–2048 printable ASCII, no spaces. `website` must start with `https://`.
- `POST /admin/agents` (master) — `{"id","token_hash","request_id"}`. `token_hash` is the lowercase hex SHA-256 of the agent's request-only bearer. The raw bearer is never stored.
- `POST /unlock` (master) — `{"agent_id","service","key_label","request_id"}` → a grant `{"id","agent_id","key_id","service","opened_at","expires_at","revoked_at"}` with `expires_at = opened_at + 7200`. Replaying the same `request_id` returns the original grant, never a fresh one. The key must exist and be enabled; the agent must exist and not be revoked.
- `POST /revoke` (master) — `{"target":"grant"|"agent"|"key","id","request_id"}`. Revoking an agent revokes its grants; disabling a key revokes its grants.
- `POST /mcp` — agent bearer only. Stateless Streamable HTTP, POST only (GET/DELETE return 405, batches rejected).

All POST admin bodies: `Content-Type: application/json`, ≤32768 bytes, strict JSON objects (no extra properties). `request_id` must be a UUID. Errors: `{"error":"<fixed_code>"}` with 400/401/403/404/405/409/413/415/503. No caught exception, upstream body, or credential is ever exposed. An untrusted host, mismatched `Origin`, or `Sec-Fetch-Site: cross-site` is refused. No CORS. Curl may omit Origin. Identifiers: 1–80 ASCII letters, digits, underscore or hyphen. Key names may also contain spaces (no leading, trailing, or double space).

## MCP tools (any agent)

Every MCP client needs only the Worker URL and its agent's request-only bearer. Ready-made setups live in `clients/` (and `pi/mcp.json.example` for Pi), and the Worker's own page has a "Connect your agent" card that builds the snippet for you. The common shape:

```json
{
  "mcpServers": {
    "vault": {
      "url": "https://<your-worker>.workers.dev/mcp",
      "headers": { "Authorization": "Bearer <agent-token>" }
    }
  }
}
```

Per client:

- **Claude Code** — `claude mcp add --transport http vault https://<your-worker>.workers.dev/mcp --header "Authorization: Bearer <agent-token>"` (see `clients/claude-code.md`)
- **Cursor** — `~/.cursor/mcp.json` with the `mcpServers` shape above (see `clients/cursor-mcp.json`)
- **Cline** — MCP settings with `"type": "streamableHttp"` plus the shape above (see `clients/cline-mcp.json`)
- **Codex** — `~/.codex/config.toml`: `[mcp_servers.vault]` with `url` and `bearer_token_env_var = "VAULT_AGENT_TOKEN"` (see `clients/codex-config.toml`)
- **Pi** — `~/.pi/agent/mcp.json` with `"type": "streamable-http"` plus the shape above (see `pi/mcp.json.example`)
- **Any other Streamable HTTP client** — URL + `Authorization` header, and send `Accept: application/json, text/event-stream` (without it the server answers 406 — correct per the MCP spec, not a vault bug). See `clients/generic.md`.

Tools:

- **`github_read_file`** — read one exact UTF-8 file (≤32 KiB) from a repo: `{key_label, repository, path}` plus optional `branch` (repo default branch when omitted). Paths under `.env`, `.git`, `secrets`, or ending `.pem`/`.key`/`.env`/`.ppk`, or named `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519` (plus `.pub`) are refused. Repository, branch and path come from chat.
- **`github_list_issues`** — list up to 20 issues: `{key_label, repository, page, state}`.
- **`github_create_issue`** — only registered when `ENABLE_GITHUB_WRITES=true`: `{key_label, repository, request_id, title, body}`. Durable request UUID; an uncertain write is never retried with a new UUID — the vault admin reconciles it.
- **`service_request`** — call any stored service: `{key_label, service, method, path, body?}`. The Worker calls the key's stored website with the decrypted key and returns the redacted response (sliced to 32768 characters). The key is never shown to the agent. Upstream fetch timeout is 25 seconds (see "Limits" below).

Every tool call re-checks the grant against D1 primary immediately before dispatch, and refuses if the key was rotated or disabled since. A locked call returns `{error:"unlock_required", service, label, instruction:"Ask the vault admin to unlock this exact key."}`. The agent cannot unlock itself.

## Security model

- **Keys are AES-256-GCM encrypted in D1.** The AAD binds each ciphertext to `['cf-vault', key id, service, label, enc_version]` — a ciphertext copied to another key, service, or label does not decrypt. Nonces are fresh per encryption. The DEK (`VAULT_DEK_V1`, optional `VAULT_DEK_V2`) lives only as a Worker secret; the raw master lives only with the vault admin. The Worker stores only `MASTER_SHA256` / `HUMAN_SHA256` verifiers.
- **No key ever leaves the Worker.** Tool results are redacted: `ghp_`/`github_pat_` token patterns are masked before short secrets, longest secret first, so a short secret inside a longer token cannot split it and leak the rest.
- **Grants are the only authorization.** A grant names one agent, one service, one key label, and expires exactly 7200 seconds after opening. Expiry is checked on every operation against D1 primary — no positive auth cache. Rotation/disable/revoke/delete kills live grants immediately (checked again before each dispatch).
- **Writes are safe.** Issue creation (the only write tool) is off unless `ENABLE_GITHUB_WRITES=true`, and uses a durable reservation: same request UUID + same fingerprint returns the stored outcome; a different fingerprint conflicts; an uncertain outcome is never silently retried.
- **Audit is metadata only.** Unlock/revoke/admin and sampled reads are logged (IDs, operation, status, request ID) — never bodies, keys, or upstream responses. Audit is capped (10,000 rows, 1,000/day) and pruned to 7 days.
- **Admin idempotency.** Every admin mutation carries a UUID `request_id`, recorded in `admin_requests`. Reuse returns 409. Unlock replays return the original grant.

## Setup

Prerequisites: a Cloudflare account (free tier), Node 20+, `wrangler`.

```bash
npm install
npm run check     # tsc --noEmit
npm test          # node tests, no network
```

1. Create the D1 database and apply migrations:
   ```bash
   npx wrangler d1 create cf-vault
   # put the returned database_id in wrangler.toml
   npx wrangler d1 migrations apply cf-vault --remote
   ```
2. Set secrets (never commit them):
   ```bash
   # 32 random bytes, base64:
   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
   npx wrangler secret put VAULT_DEK_V1
   # master: a long random string; store only its SHA-256 on the Worker:
   node -e "console.log(require('crypto').createHash('sha256').update('YOUR_MASTER_HERE').digest('hex'))"
   npx wrangler secret put MASTER_SHA256
   # optional second password for humans (key management; unlock/revoke/agents stay master-only):
   npx wrangler secret put HUMAN_SHA256
   ```
   Keep the raw master and the DEK backup offline (chmod 600). The master is admin-held; the human password is owner-chosen.
3. Set `PUBLIC_ORIGIN` in `wrangler.toml` to the real `https://<name>.<subdomain>.workers.dev` origin, and `ENABLE_GITHUB_WRITES` to `true` only if an agent may create issues.
4. Deploy: `npx wrangler deploy`.
5. Register the agent and the first key:
   ```bash
   # agent token: a long random string; store its SHA-256:
   node -e "console.log(require('crypto').createHash('sha256').update('AGENT_TOKEN').digest('hex'))"
   curl -X POST $ORIGIN/admin/agents -H "Authorization: Bearer $MASTER" \
     -H 'Content-Type: application/json' \
     -d '{"id":"my-agent","token_hash":"<sha256>","request_id":"<uuid>"}'
   ```
   Add the first key on the manual page (human password) or via `/admin/keys`.
6. Point your agent at the Worker (see "MCP tools (any agent)" above — the Worker's own page builds the snippet for you) and unlock:
   ```bash
   curl -X POST $ORIGIN/unlock -H "Authorization: Bearer $MASTER" \
     -H 'Content-Type: application/json' \
     -d '{"agent_id":"my-agent","service":"github","key_label":"work","request_id":"<uuid>"}'
   ```

## Free-tier notes

Workers Free: 100k requests/day, 10 ms CPU per request. D1 Free: 5M rows read/day, 100k rows written/day. The design stays inside both: stateless MCP (no session storage), D1 primary reads, sampled read-audit (~5%), bounded lists (100 keys, 20 issues), bounded bodies (32 KiB admin, 128 KiB upstream). No KV, Durable Objects, or paid add-ons.

## Limits

- **Upstream fetch timeout is 25 seconds** for `service_request` and the GitHub tools. A slow upstream returns a clean timeout error (`operation_failed` / `TimeoutError`).
- **A Workers request cannot run longer than ~30 seconds wall-clock** on the free tier, so the timeout cannot be raised past ~25 seconds — a longer value would be killed mid-flight instead of returning cleanly. Slow or down upstreams need a retry later, not a longer timeout.
- **Upstream responses are sliced to 32768 characters** before redaction. Large listings (e.g. a full model catalogue) arrive truncated mid-JSON; complete objects before the cut can still be used.
- **MCP clients must send `Accept: application/json, text/event-stream`**; without it the server answers 406. That is correct per the MCP spec.

## Lessons baked in

- **Workers fetch rejects `redirect: 'error'`.** Only `'follow'` or `'manual'` are valid at the edge. This vault uses `redirect: 'manual'` and treats any non-2xx response (including 3xx) as an upstream failure. The original v1 GitHub tools carried `redirect: 'error'` and could never complete a real upstream call — the bug only surfaced once grants were tested end to end with real keys.
- **Deploy propagation is not instant.** For a few seconds after deploy, edge nodes can serve the previous version. A surprising result right after a deploy is worth one retry before debugging.
- **The locked path is not the whole test.** A locked call returning `unlock_required` proves authorization; only a granted call against a real upstream proves the full chain (decrypt → fetch → response). Test both.
- **Upstream errors are mapped, not passed through.** A 403 or 429 from the upstream becomes `upstream_refused` (with `upstream_refused_retry_after_<seconds>` when the upstream sends one); any other upstream failure becomes `upstream_failed`. Upstream bodies are never returned — a 402 (no credits) and a provider outage both surface as `upstream_failed`, so check the provider's own dashboard (billing/credits) when priced calls fail fast while free ones hang.
- **The Worker reaches APIs a blocked machine cannot.** The Worker runs on Cloudflare's own network, so `service_request` can reach an API that returns 403 to a datacenter egress. When every direct request to a site fails — even no-auth, even the site root — the key was never evaluated; the egress is blocked, not the credentials. The vault is the route around it, not a retry of the same request.
- **Key names may contain spaces.** Labels allow letters, digits, spaces, `_` and `-` (no leading, trailing, or double space, 1–80). Pasted secrets are trimmed — mobile paste often adds a trailing space or newline.
- **Sensitive paths are blocked before authorization.** `github_read_file` refuses `.env`, `.git`, `secrets`, `.pem`/`.key`/`.p12`/`.pfx`/`.env` endings, `.ppk`, and private-key filenames (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, plus `.pub`) — even for a locked call, so the blocklist itself is testable without a grant.
- **Revoke takes `id`, not `grant_id`.** `POST /revoke` is `{"target":"grant"|"agent"|"key","id","request_id"}`. The MCP tools take `{key_label, repository, path}` — there is no `owner`/`repo` split. When a call fails with `invalid_request`, check the field names first; the test scripts got all three of these wrong before the vault did.

## Repository layout

```text
src/index.ts     Worker entry: origin checks, /mcp, /admin/*, static assets
src/admin.ts     whoami / unlock / revoke / admin/keys / admin/agents
src/auth.ts      bearer auth, admin roles, grant authorization
src/github.ts    GitHub tools (read file, list issues, create issue)
src/service.ts   generic service_request proxy
src/crypto.ts    AES-256-GCM encrypt/decrypt, SHA-256, redaction
src/audit.ts     audit log, sampling, pruning
src/types.ts     Env, zod validators, shared helpers
migrations/      0001_init.sql, 0002_multi_service.sql
tests/           security.test.ts (GCM binding, redaction, website, grants)
public/          index.html, manual.js, style.css, llms.txt, llm.txt
clients/         claude-code.md, cursor-mcp.json, cline-mcp.json, codex-config.toml, generic.md
pi/              mcp.json.example (Pi setup)
wrangler.toml    Worker + D1 + assets config (no secrets in repo)
```

## License

MIT.
