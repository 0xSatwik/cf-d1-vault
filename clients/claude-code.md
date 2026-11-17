# Claude Code

One command (replace the worker URL and the token):

```bash
claude mcp add --transport http vault https://<your-worker>.workers.dev/mcp \
  --header "Authorization: Bearer <agent-token>"
```

Or add it to a `.mcp.json` file (project scope) or `~/.claude.json` (user scope):

```json
{
  "mcpServers": {
    "vault": {
      "type": "http",
      "url": "https://<your-worker>.workers.dev/mcp",
      "headers": { "Authorization": "Bearer <agent-token>" }
    }
  }
}
```

Then ask the vault admin to unlock a key for this agent
(`agent_id` is the name you registered the token under, e.g. `claude`).
A locked tool call returns `unlock_required` — the agent cannot unlock itself.
