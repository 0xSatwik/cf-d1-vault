# Any Streamable HTTP MCP client

The vault speaks plain MCP over Streamable HTTP, so any spec-compliant
client works — Claude Code, Cursor, Cline, Codex, Pi, the MCP Inspector,
or a client built on the official MCP SDK. No Pi-specific or
Muse-specific behaviour exists anywhere in the server.

- URL: `https://<your-worker>.workers.dev/mcp`
- Header: `Authorization: Bearer <agent-token>`
- Required header: `Accept: application/json, text/event-stream`
  (without it the server answers 406 — that is correct per the MCP spec,
  not a vault bug)
- POST only. GET/DELETE return 405. JSON batches are rejected.
- Tools: `github_read_file`, `github_list_issues`, `service_request`
  (plus `github_create_issue` only when `ENABLE_GITHUB_WRITES=true`).

The agent's token is request-only: it can call tools only inside a
2-hour grant opened by the vault admin (master password) for one service
+ one key label. A locked call returns
`{"error":"unlock_required","service","label",
"instruction":"Ask the vault admin to unlock this exact key."}`.
The agent never sees a key — the Worker decrypts and calls the upstream
API itself, and redacts token patterns from every response.

Per-client setups live in this folder: `claude-code.md`,
`cursor-mcp.json`, `cline-mcp.json`, `codex-config.toml`,
and `../pi/mcp.json.example` for Pi.
