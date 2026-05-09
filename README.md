# PocketBase Security MCP Server

> The only PocketBase auditor that **closes the loop**: scan, preview the fix, and apply the rule update — all from inside Claude Code, Cursor, or Cline. Active probe confirms every leak live with an anonymous fetch.

## Why this exists

Every other PocketBase auditor (there are basically zero) would just print findings and stop. This one is an **MCP server**: your AI coding agent can call it directly to audit, see what a fix would change, and patch the rule itself. No copy-paste between tabs.

## Tools

| Tool | What it does |
|---|---|
| `audit_project` | Scans the PocketBase instance, returns findings JSON. Active probe ON by default. Caches result. |
| `list_findings` | Lists cached findings by index, optionally filtered by severity. |
| `preview_fix` | Describes what `apply_fix` would change without calling the API. |
| `apply_fix` | PATCHes the collection rule. Requires `confirm: true` and an explicit `rule_value`. Re-audits and reports whether the finding is gone. |

## Install

```bash
npm install -g @perufitlife/pocketbase-security-mcp
```

Or via `npx` from the MCP config:

```json
{
  "mcpServers": {
    "pocketbase-security": {
      "command": "npx",
      "args": ["-y", "@perufitlife/pocketbase-security-mcp"],
      "env": {
        "POCKETBASE_URL": "https://my.pb.io",
        "POCKETBASE_ADMIN_EMAIL": "admin@me.io",
        "POCKETBASE_ADMIN_PASSWORD": "..."
      }
    }
  }
}
```

## Workflow inside Claude Code

```
> audit my pocketbase instance
[calls audit_project → returns 3 critical / 2 high]

> show me the criticals
[calls list_findings severity=critical]

> what would fixing finding 0 do?
[calls preview_fix finding_index=0]

> apply that fix with rule "@request.auth.id != \"\" && @request.auth.id = ownerId"
[calls apply_fix with confirm: true]
[re-audits, confirms the leak is closed]
```

## Differential vs every passive scanner

- **Active probe**: not just "this rule looks bad" — we actually fetch the data anonymously to confirm.
- **Auto-remediation**: zero copy-paste. The agent applies the fix.
- **Re-audit after fix**: instant verification, no manual re-run.

## License

MIT. Open source. Built by [@Perufitlife](https://github.com/Perufitlife).

For the standalone CLI, see https://github.com/Perufitlife/pocketbase-security-skill
For Supabase, see https://github.com/Perufitlife/supabase-security-mcp
