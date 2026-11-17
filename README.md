# cf-d1-vault

MIT-licensed TypeScript credential vault and stateless remote MCP gateway for Cloudflare Workers Free + D1. Pi holds a request-only bearer; Muse controls administration and exact two-hour grants. GitHub PATs remain inside the Worker. No deployment is performed by building or testing this repository.

## How the whole system fits together

```text
Trusted Muse administration environment / human browser
  holds: raw high-entropy master, upstream PAT during entry
  POST /admin/agents  -> register SHA-256 bearer hash + maximum policy
  POST /admin/keys    -> add / rotate / disable encrypted PAT rows
  POST /unlock        -> exact agent + github + label + scope, 7200 seconds
  POST /revoke        -> grant / agent / key
              | HTTPS Authorization: Bearer <MASTER_SECRET>
              v
Cloudflare Worker (trusted code and deployment boundary)
  MASTER_SHA256 secret: verifies Muse; raw master is not persisted
  VAULT_DEK_V1 / V2 secrets: independent AES-256-GCM encryption keys
  /mcp: official SDK, stateless Streamable HTTP, POST JSON responses
  policy: intersection(agent, grant, key), fresh D1 primary reads
  GitHub adapter: fixed origin, exact resource checks, bounded results
       | D1 binding                         | HTTPS Bearer <PAT>
       v                                    v
D1 primary                            api.github.com
  keys: ciphertext + nonce + AAD identity    file read / issue list
  agents: token hash + maximum policy       optional issue creation
  grants: opened_at, expires_at, revoked_at
  audit: metadata only
  write_operations: durable dispatch reservations
       ^
       | fresh checks before each dispatch; no authorization cache
       |
Pi ~/.pi/agent/mcp.json -> HTTPS /mcp
  holds: Worker URL + request-only bearer
  receives: selected tool results or unlock_required
  asks Muse when locked; cannot unlock itself
```

The DEK and the master are independent. An unlock authorizes operations; it does not load a transient DEK or start an isolate timer. Worker restarts do not extend grants. No KV, Durable Objects, OAuth server, VM, Pages deployment, paid plan, or local stdio proxy is required. Static Assets serves the manual-entry page from the same Worker.

## Requirements and pinned dependencies

Use Node.js 22.12 or newer, npm, Python 3, a Cloudflare account on Workers Free, a trusted Muse administration machine, and Pi with remote Streamable HTTP support. `package.json` pins `@modelcontextprotocol/sdk` 1.32.2, Wrangler 4.163.0, Zod 4.6.7, TypeScript 5.9.3, and Workers types 5.20261117.1. The SDK's documented `WebStandardStreamableHTTPServerTransport` uses Fetch Request/Response directly. There is one server and transport per request; no MCP protocol session is used as an authorization grant.

Run all project commands from the checkout:

```sh
cd /root/work/cf-vault
npm install --package-lock=false
npm run check
npm test
npm run build
```

`build` runs `wrangler deploy --dry-run`; it does not deploy. Tests use synthetic data and local cryptography. A successful bundle does not establish production CPU headroom or complete deployment acceptance.

## 1. Provision Cloudflare on the free tier

These steps are instructions for the trusted operator. They perform real Cloudflare changes when you choose to run them. Keep deploy credentials outside Pi and outside repositories Pi can modify through tools or CI.

### Login, create D1, and configure bindings

```sh
cd /root/work/cf-vault
npx wrangler login
npx wrangler whoami
npx wrangler d1 create cf-vault
```

Copy the returned database UUID. Replace the entire `wrangler.toml` with the following configuration, substituting the database UUID and your actual Worker origin. All angle-bracket values throughout this guide are placeholders to replace before use; none are credentials. Choose the Worker name before generating the origin. Do not use a trailing slash in `PUBLIC_ORIGIN`.

```toml
name = "cf-d1-vault"
main = "src/index.ts"
compatibility_date = "2026-11-17"
compatibility_flags = ["nodejs_compat"]
workers_dev = true

[assets]
directory = "./public"
binding = "ASSETS"
run_worker_first = true

[[d1_databases]]
binding = "DB"
database_name = "cf-vault"
database_id = "<D1_DATABASE_UUID>"
migrations_dir = "migrations"

[vars]
PUBLIC_ORIGIN = "https://cf-d1-vault.<YOUR_WORKERS_SUBDOMAIN>.workers.dev"
ENABLE_GITHUB_WRITES = "false"

[observability]
enabled = false
```

The Worker rejects a request whose URL origin differs from `PUBLIC_ORIGIN`, and rejects browser requests carrying a different Origin. Use the exact deployed origin, including a custom domain if configured. A trusted non-browser client may omit Origin. No cross-origin CORS permission is granted.

Apply the migration to the remote database, and inspect only table names:

```sh
cd /root/work/cf-vault
npx wrangler d1 migrations apply DB --remote
npx wrangler d1 execute DB --remote --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

### Generate and retain independent secrets

In Muse's trusted password manager, generate and save three independent values:

1. Master: at least 32 cryptographically random bytes, encoded as base64url or hex. Muse alone retains the raw value.
2. DEK: exactly 32 cryptographically random bytes, standard base64 encoded. Retain a recovery copy separately from database backups.
3. Pi request bearer: at least 32 cryptographically random bytes, base64url encoded. Give only this bearer to Pi.

Do not paste generated values into chats, source files, shell command lines, or this README. The helper accepts secrets through hidden interactive prompts. This command prompts for the retained master and DEK, hashes the master locally, and sends only the verifier and DEK to Wrangler through stdin:

```sh
cd /root/work/cf-vault
python3 scripts/admin.py provision
```

The helper uses `wrangler secret put MASTER_SHA256` and `wrangler secret put VAULT_DEK_V1`. Wrangler's `secret put` creates/deploys a Worker version; it is an actual remote administration operation. Follow its first-Worker creation prompt if necessary. Neither secret is a `[vars]` value. The raw master is never stored in D1 or a Worker binding. SHA-256 is appropriate here for a high-entropy random secret, not a human password.

Deploy the final bundle:

```sh
cd /root/work/cf-vault
npm run check
npm test
npm run build
npx wrangler deploy
```

Verify the origin and authentication rejection without sending any credential:

```sh
python3 - <<'PY'
import urllib.error
import urllib.request
origin = input('Exact HTTPS Worker origin: ').rstrip('/')
with urllib.request.urlopen(origin + '/') as response:
    assert response.headers.get('Cache-Control') == 'no-store'
    assert "default-src 'none'" in response.headers.get('Content-Security-Policy', '')
    print('Manual entry page:', response.status)
request = urllib.request.Request(origin + '/mcp', data=b'{}', headers={'Content-Type': 'application/json'})
try:
    urllib.request.urlopen(request)
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
    print('Unauthenticated MCP correctly refused:', error.code)
PY
```

## 2. Define exact policies and register Pi

All three policies use the same JSON format. Repository names are lowercase canonical `owner/repo`. Tools, repositories, branches and paths are exact strings; there are no globs, implicit defaults, or URL permissions. Empty branch/path lists allow no file reads, but can be used for issue-only policies. `github_list_issues` and `github_create_issue` check repository and operation; branch/path fields are irrelevant to issue operations.

Create a complete example policy; replace `example/project`, branches and paths with the intended resources before registration:

```sh
cd /root/work/cf-vault
python3 - <<'PY'
import json
from pathlib import Path
policy = {
    'allowed_tools': ['github_read_file', 'github_list_issues'],
    'resources': [{'repository': 'example/project', 'branches': ['main'], 'paths': ['README.md']}]
}
Path('policy.json').write_text(json.dumps(policy, indent=2) + '\n', encoding='utf-8')
PY
```

Policy files contain metadata, not secrets. You may use different files for the agent maximum, key maximum and narrower grant. Register the agent on Muse's machine; enter the saved request bearer and master at the hidden prompts:

```sh
cd /root/work/cf-vault
python3 scripts/admin.py agent --url https://vault.example.workers.dev --agent pi-main --policy policy.json --request-id 11111111-1111-4111-8111-111111111111
```

Replace the example origin with your actual origin in every helper command. `POST /admin/agents` stores only `SHA256(bearer)` and the policy. Agent creation is immutable: to rotate a bearer, revoke the old agent and register a new agent ID with a new random bearer. Never reactivate a revoked identity.

## 3. Put keys into the vault

### Muse administration path

Create a classic or fine-grained GitHub PAT in the trusted GitHub account. Both types work equally. Select only the needed upstream repositories and permissions where GitHub permits it: Contents read for file reads, Issues read for listing, Issues write only if deliberately enabling creation. GitHub organization approval/SSO rules still apply. The Worker cannot enlarge the PAT's actual GitHub permissions.

Add a labeled key from Muse's machine:

```sh
cd /root/work/cf-vault
python3 scripts/admin.py add --url https://vault.example.workers.dev --label work --policy policy.json --request-id 22222222-2222-4222-8222-222222222222
python3 scripts/admin.py list --url https://vault.example.workers.dev
```

The helper prompts for the PAT and master, sends `POST /admin/keys`, and prints metadata only. Encryption happens immediately inside the Worker: AES-256-GCM, fresh 96-bit nonce, 128-bit tag appended to ciphertext, AAD containing immutable ID/service/label/encryption version. D1 stores ciphertext, nonce, version and policy. `GET /admin/keys` returns no ciphertext, nonce or plaintext, just up to 100 metadata entries.

A second label such as `personal` must be added and unlocked independently. The exact `service,label` pair is unique. An add cannot overwrite it.

### Manual entry page

Open the exact Worker origin `/` or `/manual` in a trusted browser. Enter the master in the password field, choose `add`, enter `work`, paste the PAT, choose encryption version 1 and enter the complete policy JSON. Submit once. The page sends same-origin `POST /admin/keys` with the master bearer header and a random request UUID. It clears password fields after dispatch and on page exit and renders fixed status text through `textContent`.

The page has no third-party code, inline scripts, localStorage, cookies for authentication, analytics, or credential export. A restrictive CSP allows only its same-origin external script and connection. All responses carry `Cache-Control: no-store`. Browser extensions, password managers, developer tools and a compromised browser remain part of the trusted administration environment. Merely opening the page grants no administrative access.

### Rotate or disable a PAT

Use a new UUID for every distinct operation. Rotation preserves immutable key ID/service/label, encrypts the supplied replacement PAT with a fresh nonce, sets its policy and revokes every existing grant for that key. Disabling also revokes grants.

```sh
cd /root/work/cf-vault
python3 scripts/admin.py rotate --url https://vault.example.workers.dev --label work --policy policy.json --request-id 33333333-3333-4333-8333-333333333333
```

```sh
cd /root/work/cf-vault
python3 scripts/admin.py disable --url https://vault.example.workers.dev --label work --request-id 44444444-4444-4444-8444-444444444444
```

A failed GitHub request never selects another label or token. Rotate the upstream PAT in GitHub too when it may have been exposed.

## 4. Connect Pi to remote MCP

On the Pi host, create `~/.pi/agent/mcp.json` with this complete JSON, substituting the Worker URL and request-only bearer. If an MCP configuration already exists, merge this `vault` entry into its `mcpServers` object rather than overwriting other servers.

```json
{
  "mcpServers": {
    "vault": {
      "url": "https://vault.example.workers.dev/mcp",
      "headers": {
        "Authorization": "Bearer <REQUEST_ONLY_TOKEN>"
      },
      "exposure": "codemode",
      "description": "Scoped GitHub tools; ask Muse to unlock when a grant expires"
    }
  }
}
```

This is also supplied as `pi/mcp.json.example`. Pi receives neither PAT, raw master nor DEK. Protect the populated file:

```sh
mkdir -p "$HOME/.pi/agent"
chmod 700 "$HOME/.pi/agent"
chmod 600 "$HOME/.pi/agent/mcp.json"
```

Restart Pi to load the configuration and inspect the `vault` server through `/mcp`. Tool exposure is `codemode`; use Pi's documented MCP tool discovery/codemode interface to invoke the discovered tools. The installed Pi 1.5.2 documentation explicitly rejects the legacy `sse` transport. A URL selects remote Streamable HTTP. Do not add invented `transport`, `lifecycle` or `auth` fields, point to `/sse`, or start a legacy stdio proxy.

The Worker authenticates each HTTP request before the official SDK handles initialization, protocol negotiation, notifications, `tools/list` and `tools/call`. POST requests advertise `Accept: application/json, text/event-stream` as required by Streamable HTTP; this implementation selects JSON responses. This is still Streamable HTTP even though responses are JSON. It does not provide a standalone SSE listener, resumable session, or `Mcp-Session-Id`; GET and DELETE `/mcp` return 405. JSON-RPC batches are rejected. Pi's bearer authenticates discovery but tool execution requires a separate live grant.

An MCP tool-call argument example for `github_read_file` is complete JSON:

```json
{
  "key_label": "work",
  "repository": "example/project",
  "branch": "main",
  "path": "README.md"
}
```

## 5. Unlock, expiry, asking Muse and revocation

1. Pi tries a narrow tool with an explicit label. Without a matching live grant it receives an MCP `isError: true` result with `unlock_required`, service `github`, label `work`, and the instruction to ask Muse. It receives no PAT or master challenge.
2. Pi asks Muse for the exact service, label, operations and resources needed for the task. Muse reviews trusted task context and chooses the scope itself.
3. Muse sends the following command from its trusted environment. The helper sends `POST /unlock` using the raw master only in the HTTPS Authorization header.

```sh
cd /root/work/cf-vault
python3 scripts/admin.py unlock --url https://vault.example.workers.dev --agent pi-main --label work --policy policy.json --request-id 55555555-5555-4555-8555-555555555555
```

The complete request body generated for the example policy is:

```json
{
  "agent_id": "pi-main",
  "service": "github",
  "key_label": "work",
  "allowed_tools": ["github_read_file", "github_list_issues"],
  "resources": [
    {"repository": "example/project", "branches": ["main"], "paths": ["README.md"]}
  ],
  "request_id": "55555555-5555-4555-8555-555555555555"
}
```

4. The Worker verifies SHA-256 of the master, resolves the exact enabled key and unrevoked agent, checks the requested scope is a subset of both policies, and atomically inserts a mandatory audit event and grant. It sets `opened_at` from server Unix seconds and `expires_at = opened_at + 7200`. The response contains the grant ID, policy and absolute deadline; save the grant ID for revocation.
5. Pi retries the original tool using its existing request-only bearer. On every operation and again immediately before dispatch, the Worker reads the D1 primary and requires an enabled key, unrevoked agent, unrevoked matching grant, and `expires_at > server_now`. There is no positive authorization cache or replica read.
6. At exactly the deadline the grant fails. Pi's existing bearer cannot renew it; activity, MCP initialization and Worker restarts cannot extend it. Pi asks Muse again. A new explicit approval uses a new UUID and creates a new two-hour grant.

Replaying the same unlock request UUID returns the original grant without extending it, including if it is expired or revoked. Reusing it for different arguments returns a conflict. A two-hour grant is not an MCP transport session or a promise to keep a TCP connection open.

Revoke a specific grant by replacing the example ID with the ID returned by unlock:

```sh
cd /root/work/cf-vault
python3 scripts/admin.py revoke --url https://vault.example.workers.dev --target grant --id 66666666-6666-4666-8666-666666666666 --request-id 77777777-7777-4777-8777-777777777777
```

Revoke Pi's entire identity and all its grants:

```sh
cd /root/work/cf-vault
python3 scripts/admin.py revoke --url https://vault.example.workers.dev --target agent --id pi-main --request-id 88888888-8888-4888-8888-888888888888
```

`--target key --id <KEY_ID>` disables one exact key and revokes its grants. Metadata listing supplies key IDs. Revoke prevents subsequent admissions; it cannot retract an upstream request already transmitted, and a small race exists between the final D1 read and dispatch. Keep tools short and bounded. Another already-live grant can independently authorize the same scope; revoke the agent or key to remove all such grants.

## 6. How GitHub calls flow

For `github_read_file`, Pi provides label/repository/branch/path. The Worker maps the tool to service `github`, canonicalizes through strict schemas, rejects sensitive or ambiguous paths, and intersects agent, key and grant policies. It decrypts only that key row per call, constructs a GitHub Contents API URL at `https://api.github.com`, performs another fresh authorization read and attaches the PAT inside the Worker. Redirects are errors. No user URL, arbitrary headers, raw REST/GraphQL passthrough or arbitrary download tool exists.

The adapter sends `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, and a fixed User-Agent. A file must be UTF-8 and at most 32 KiB; metadata JSON is limited to 64 KiB. Hidden path segments, secret/credential filenames and common key extensions are blocked even when policy permits them. Matching is exact and encoded once; encoded traversal, `..`, backslashes and query delimiters are rejected.

`github_list_issues` accepts a label, exact repository, state and page. It asks for 20 entries, allows pages 1–10, excludes pull requests and returns only number, title and state. Response JSON is limited to 128 KiB. Every page is independently authorized. No issue body, Actions logs/artifacts or redirect URLs are exposed.

Selected result strings are scrubbed for the active PAT, configured encryption secrets, master verifier and recognizable GitHub token formats. Repository content can contain arbitrary unrelated secrets or prompt injection; scrubbing cannot guarantee their removal. Keep allowed paths narrow. Treat tool results as untrusted data.

A GitHub refusal, expired PAT, missing permission or unavailable `work` key is an error; `personal` is never tried. PATs belonging to one GitHub user generally share the 5,000/hour primary authenticated REST limit; secondary limits also apply. The adapter does not automatically retry. It uses bounded Retry-After guidance when returned and otherwise reports refusal; operators should observe GitHub rate-limit policy before retrying reads. Timeouts are bounded to 15 seconds.

### Deliberately enable issue creation

Writes are off by default and absent from tool discovery. To enable the single supported write, set `ENABLE_GITHUB_WRITES = "true"`, deliberately include `github_create_issue` in the agent, key and grant policies, provision an appropriately scoped PAT and deploy the reviewed change. Restart/reconnect Pi to refresh discovery. Existing agent policies are immutable, so register a new identity if its maximum policy must change. Key rotation changes key policy and revokes its grants.

A complete write policy is:

```json
{
  "allowed_tools": ["github_list_issues", "github_create_issue"],
  "resources": [
    {"repository": "example/project", "branches": [], "paths": []}
  ]
}
```

A complete `github_create_issue` argument object is:

```json
{
  "key_label": "work",
  "repository": "example/project",
  "request_id": "99999999-9999-4999-8999-999999999999",
  "title": "Example reviewed task",
  "body": "This example must be approved for the intended repository before execution."
}
```

The Worker atomically reserves a mandatory audit row and durable `(agent_id,request_id)` idempotency record before dispatch. The fingerprint hashes the exact arguments and key ID; raw bodies are not stored. A repeated identical request reports the existing status and never redispatches. A conflicting payload with the same ID is refused. A crash, timeout or result-log failure can leave `reserved`/`unknown` even if GitHub created the issue. Muse must reconcile against GitHub; Pi must never invent a new UUID to retry an uncertain write. There is no distributed transaction between D1 and GitHub. No credential creation, permission changes, workflow edits, deployments, commits or arbitrary write endpoint is exposed.

## API reference

Every admin route requires `Authorization: Bearer <MASTER_SECRET>`; Pi's request bearer is insufficient. POST bodies must be JSON, at most 32 KiB, with a UUID `request_id`. All schemas reject extra fields.

| Route | Method | Body / result |
| --- | --- | --- |
| `/mcp` | POST | Official MCP protocol; request-only bearer |
| `/unlock` | POST | `agent_id,service,key_label,allowed_tools,resources,request_id`; grant metadata |
| `/revoke` | POST | `target: grant/agent/key,id,request_id`; status |
| `/admin/agents` | POST | `id,token_hash,policy,request_id`; creates immutable identity |
| `/admin/keys` | GET | No body; metadata list, limit 100 |
| `/admin/keys` | POST | `action: add/rotate,service,label,secret,policy,enc_version,request_id` |
| `/admin/keys` | POST | `action: disable,service,label,request_id` |
| `/` or `/manual` | GET | Same-origin manual entry page |

Only `github` is implemented. No decrypt/export endpoint exists. A future service needs its own reviewed adapter, schemas and policy mapping. Error responses are fixed codes; caught exception objects, upstream error bodies, headers, credentials and raw arguments are never serialized.

## Local development and verification

Keep `PUBLIC_ORIGIN` set to `http://localhost:8787` for the supplied local config. `.dev.vars.example` documents the secret names; do not use its literal placeholder values as functional secrets. Use only synthetic local values. Never copy production secrets to the Pi development host. Apply the local migration and start the local Worker:

```sh
cd /root/work/cf-vault
npm run db:local
npm run dev
```

Wrangler reads an ignored `.dev.vars` when local secrets are needed. Local D1 state is under ignored `.wrangler/`. `npm test` covers GCM tampering/AAD/version rotation, nonce freshness, verifier handling, exact policies, sensitive paths and fail-closed authorization. `npm run check` enforces strict TypeScript; `npm run build` verifies the Worker bundle without deployment.

Before accepting a live deployment, use a synthetic/canary GitHub credential in a disposable repository to check initialization, notifications, listing and calls from installed Pi, admin rejection with Pi's bearer, service/label/agent substitution, exact expiry, revoke from a second connection and after redeploy, rotation, redirects/path bypasses, duplicate writes, D1 quota/audit failures, and credential leakage in results/logs. Run write acceptance only with explicit operator intent. Measure worst-case deployed CPU with SDK, crypto and largest allowed responses together; local wall-clock timing does not prove Free CPU compliance. This repository's local verification is not a production security audit.

## Free-tier budget, auditing and capacity

Official limits checked for this implementation: Workers Free has 100,000 requests/day, 10 ms CPU/request, 128 MB memory and 50 external subrequests/request. D1 Free has 5 million rows read/day, 100,000 rows written/day, 10 databases, 500 MB/database, 5 GB/account and 50 queries per invocation. Quotas are account-shared. Network wait is separate from CPU. D1 charges/counts rows scanned and index writes, not just SQL calls. Daily quotas reset at 00:00 UTC. Quota exhaustion refuses service; it never weakens checks or automatically upgrades the account.

Audit rows contain only timestamps, agent/key/grant IDs, operation, status and request ID. Successful admin changes and unlock/revoke are audited atomically with their D1 mutations; metadata listing reserves an audit first. Writes reserve before dispatch. Successful reads are sampled at approximately 5%. Failed authentication/invalid inputs are not persisted, limiting unauthenticated write amplification. No per-call last-used update, body logging or payload tracing is used.

Audit triggers cap insertion at 1,000 rows per UTC day and 10,000 total. Authenticated admin requests prune at most 100 audit rows older than seven days. Thus seven days is the eligible retention window; idle data may remain until the next admin maintenance request. Mandatory audit capacity exhaustion fails closed. Sampled read auditing is best-effort; authorization remains mandatory.

Write idempotency and admin request tombstones are capped at 10,000 each. Grants stop accepting new rows at 10,000. These records are intentionally not automatically removed: deleting request IDs makes old requests replayable. At capacity, pause new operations and plan explicit trusted archival/migration and an identity/request namespace rollover. Grant-cap counting is an application admission limit, not a transactional global counter under simultaneous unlocks. Audit/idempotency caps are database-enforced. Avoid busy loops, inspect D1 row metrics and keep this a small personal vault. An unauthenticated attacker can still exhaust Worker request quota.

## Recovery, rotation and security boundaries

To rotate the DEK, retain V1, create an independent V2 in the trusted password manager, and install it through the hidden Wrangler prompt:

```sh
cd /root/work/cf-vault
npx wrangler secret put VAULT_DEK_V2
```

Re-submit each PAT through `rotate --version 2` using new request IDs; this re-encrypts with fresh nonces and revokes old grants. Listing shows `enc_version`. Verify every row is on V2 and retain V1 for backups/Time Travel through the recovery window. Only then remove it:

```sh
cd /root/work/cf-vault
npx wrangler secret delete VAULT_DEK_V1
```

The V1 binding is optional in practice after every row moves to V2; code never decrypts V2 through V1. Do not delete an old DEK while any required backup still needs it. There is no key-export route or automatic bulk decrypt/re-encrypt route. Re-entering PATs through trusted administration is the supported migration procedure.

D1 Free Time Travel currently retains seven days. Restore only under maintenance: prevent Pi access, restore the database, revoke all restored grants and agents, rotate request bearers, and re-register identities before reopening. Restoring a snapshot can resurrect previously valid grants, audit gaps and old idempotency records. Never assume timestamp expiry alone repairs a rollback. Database backup plus matching DEK is required for ciphertext recovery; protect them separately.

Field encryption protects confidentiality against a D1 export alone. It does not protect authorization integrity against a D1 writer. Worker code, Cloudflare control plane/deployment, Muse's admin environment and browser are trusted; their compromise can expose runtime credentials. JavaScript cannot reliably zeroize strings, so plaintext is transient per-call memory with no secret cache. A stolen Pi bearer has its allowed authority during matching grants. Two hours bounds new credential use, not the lifetime of leaked content or created issues.

Keep the vault's deployment repository/CI and Cloudflare administration outside Pi's accessible tools. If Pi must never call GitHub directly, enforce network/tool egress restrictions on the Pi host: MCP configuration alone does not restrict shell/network access. Tool visibility and Pi permission prompts are UX controls; the Worker enforces authorization.

## Official references

- [Cloudflare remote MCP guide](https://developers.cloudflare.com/agents/model-context-protocol/guides/remote-mcp-server/)
- [Official SDK Fetch-native transport](https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.x/src/server/webStandardStreamableHttp.ts)
- [MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [D1 primary/read replication semantics](https://developers.cloudflare.com/d1/best-practices/read-replication/)
- [D1 API and atomic batches](https://developers.cloudflare.com/d1/worker-api/d1-database/)
- [Workers secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
- [Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
- [D1 limits](https://developers.cloudflare.com/d1/platform/limits/) and [pricing](https://developers.cloudflare.com/d1/platform/pricing/)
- [GitHub Contents API](https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28)
- [GitHub Issues API](https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28)

Pi configuration follows the installed Pi 1.5.2 `docs/mcp.md`. License: MIT; see `LICENSE`.
