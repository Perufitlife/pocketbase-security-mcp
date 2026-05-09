#!/usr/bin/env node
// PocketBase Security MCP server — stdio transport.
//
// Tools:
//   audit_project        — scan, return findings JSON
//   list_findings        — list cached findings from last audit
//   preview_fix          — describe what a fix would change (no API call)
//   apply_fix            — actually patch the collection rule (requires confirm: true)
//
// Auth: pass POCKETBASE_URL + POCKETBASE_ADMIN_EMAIL + POCKETBASE_ADMIN_PASSWORD as env vars.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { audit } from "./audit.js";

const UA = "pocketbase-security-mcp/0.1";

const server = new McpServer({
  name: "pocketbase-security",
  version: "0.1.0",
});

const cache = new Map(); // url -> { result, ts, token }

function getCreds(provided) {
  return {
    url: provided?.url || process.env.POCKETBASE_URL,
    email: provided?.email || process.env.POCKETBASE_ADMIN_EMAIL,
    password: provided?.password || process.env.POCKETBASE_ADMIN_PASSWORD,
  };
}

function shortSummary(result) {
  const s = result.summary;
  return `${result.pocketbase_url}: ${s.critical}C / ${s.high}H / ${s.medium}M / ${s.low}L — ${result.findings.length} findings across ${result.n_user_collections} user collections (${result.active_probe.confirmed} CONFIRMED via active probe).`;
}

async function adminAuth(url, email, password) {
  const tryUrl = async (path) => {
    const r = await fetch(`${url}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify({ identity: email, password }),
    });
    if (!r.ok) return null;
    return (await r.json()).token;
  };
  return (await tryUrl("/api/collections/_superusers/auth-with-password")) || (await tryUrl("/api/admins/auth-with-password"));
}

server.registerTool(
  "audit_project",
  {
    description: "Scan a PocketBase instance for over-permissive API rules. Returns findings JSON with active-probe confirmation. Caches result for use by other tools.",
    inputSchema: {
      url: z.string().optional().describe("PocketBase base URL, e.g. https://my.pb.io. Optional if POCKETBASE_URL env var is set."),
      email: z.string().optional().describe("Admin email. Optional if POCKETBASE_ADMIN_EMAIL is set."),
      password: z.string().optional().describe("Admin password. Optional if POCKETBASE_ADMIN_PASSWORD is set."),
      no_probe: z.boolean().optional().describe("Skip the live anonymous probe."),
    },
  },
  async ({ url, email, password, no_probe }) => {
    const c = getCreds({ url, email, password });
    if (!c.url || !c.email || !c.password) {
      return { content: [{ type: "text", text: "Error: missing creds. Set POCKETBASE_URL, POCKETBASE_ADMIN_EMAIL, POCKETBASE_ADMIN_PASSWORD env vars or pass them as params." }], isError: true };
    }
    try {
      const result = await audit({ ...c, activeProbe: !no_probe });
      cache.set(c.url, { result, ts: Date.now(), creds: c });
      return { content: [{ type: "text", text: shortSummary(result) + "\n\n" + JSON.stringify(result, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Audit failed: ${e.message}` }], isError: true };
    }
  }
);

server.registerTool(
  "list_findings",
  {
    description: "List findings from the most recent audit, optionally filtered by severity.",
    inputSchema: {
      url: z.string().optional(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
    },
  },
  async ({ url, severity }) => {
    const c = getCreds({ url });
    const cached = cache.get(c.url);
    if (!cached) {
      return { content: [{ type: "text", text: `No cached audit for ${c.url}. Run audit_project first.` }], isError: true };
    }
    let findings = cached.result.findings;
    if (severity) findings = findings.filter((f) => f.severity === severity);
    const lines = findings.map((f, i) => `[${i}] ${f.severity.toUpperCase()} ${f.target}: ${f.title}${f.probe?.confirmed ? "  ★ CONFIRMED" : ""}`);
    return { content: [{ type: "text", text: lines.join("\n") || "(no findings)" }] };
  }
);

server.registerTool(
  "preview_fix",
  {
    description: "Describe what a fix would change WITHOUT calling the PocketBase API. Returns the rule field, current value, and proposed safer value.",
    inputSchema: {
      url: z.string().optional(),
      finding_index: z.number().describe("Index of the finding (from list_findings)."),
    },
  },
  async ({ url, finding_index }) => {
    const c = getCreds({ url });
    const cached = cache.get(c.url);
    if (!cached) return { content: [{ type: "text", text: `No cached audit for ${c.url}.` }], isError: true };
    const f = cached.result.findings[finding_index];
    if (!f) return { content: [{ type: "text", text: `No finding at index ${finding_index}.` }], isError: true };

    const proposed = f.check === "rule_empty_public" || f.check === "rule_too_permissive_auth"
      ? `@request.auth.id != "" && @request.auth.id = ownerId  // EDIT ownerId to match your collection's ownership field`
      : f.check === "rule_uses_dangerous_literal"
      ? `// Replace 'true' with a real ownership check, e.g. @request.auth.id = ownerId`
      : `// Manual fix in the PocketBase admin UI required for this finding type.`;

    return {
      content: [{
        type: "text",
        text: `Finding [${finding_index}]: ${f.title}\nCollection: ${f.details.collection}\nField: ${f.details.rule_field}\nCurrent value: ${JSON.stringify(f.details.rule_value)}\nProposed value:\n${proposed}\n\nNote: PocketBase rules are validated by the API on PATCH; if syntax is wrong it will reject. apply_fix will perform the PATCH after you set confirm: true.`
      }],
    };
  }
);

server.registerTool(
  "apply_fix",
  {
    description: "Apply a rule fix to the PocketBase collection via PATCH /api/collections/{id}. Requires confirm: true and rule_value (the new rule string). Re-runs the audit afterwards so you can verify the leak is closed.",
    inputSchema: {
      url: z.string().optional(),
      finding_index: z.number().describe("Index of the finding from list_findings."),
      rule_value: z.string().describe("The new rule expression for that rule field. Use empty string '' explicitly if you want public; usually you want an ownership check."),
      confirm: z.literal(true).describe("Must be exactly true. Prevents accidental writes."),
    },
  },
  async ({ url, finding_index, rule_value, confirm }) => {
    if (confirm !== true) {
      return { content: [{ type: "text", text: "Refused: set confirm: true to actually apply." }], isError: true };
    }
    const c = getCreds({ url });
    const cached = cache.get(c.url);
    if (!cached) return { content: [{ type: "text", text: `No cached audit. Run audit_project first.` }], isError: true };
    const f = cached.result.findings[finding_index];
    if (!f) return { content: [{ type: "text", text: `No finding at ${finding_index}.` }], isError: true };

    const collectionName = f.details.collection;
    const ruleField = f.details.rule_field;
    const token = await adminAuth(c.url, c.email, c.password);
    if (!token) return { content: [{ type: "text", text: "Admin auth failed." }], isError: true };

    // Need the collection ID — fetch list, find by name
    const colsRes = await fetch(`${c.url}/api/collections?perPage=200`, { headers: { Authorization: token, "User-Agent": UA } });
    if (!colsRes.ok) return { content: [{ type: "text", text: `List collections failed: ${colsRes.status}` }], isError: true };
    const cols = (await colsRes.json()).items || [];
    const target = cols.find((x) => x.name === collectionName);
    if (!target) return { content: [{ type: "text", text: `Collection ${collectionName} not found.` }], isError: true };

    const patchRes = await fetch(`${c.url}/api/collections/${target.id}`, {
      method: "PATCH",
      headers: { Authorization: token, "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify({ [ruleField]: rule_value === "" ? "" : rule_value }),
    });
    if (!patchRes.ok) {
      const body = await patchRes.text();
      return { content: [{ type: "text", text: `PATCH failed (${patchRes.status}): ${body.slice(0, 500)}` }], isError: true };
    }

    // Re-audit to confirm
    try {
      const fresh = await audit({ ...c, activeProbe: true });
      cache.set(c.url, { result: fresh, ts: Date.now(), creds: c });
      const stillThere = fresh.findings.some((nf) => nf.target === f.target);
      return {
        content: [{ type: "text", text: `Fix applied. ${stillThere ? "WARNING: same finding still present after re-audit." : "Re-audit confirms finding is gone."}\n${shortSummary(fresh)}` }],
      };
    } catch (e) {
      return { content: [{ type: "text", text: `Fix applied (PATCH 200) but re-audit failed: ${e.message}` }] };
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
