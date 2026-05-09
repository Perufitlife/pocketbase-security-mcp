#!/usr/bin/env node
// PocketBase Security Auditor — pure Node.js, no deps.
//
// Usage:
//   POCKETBASE_URL=https://my.pb.io POCKETBASE_ADMIN_EMAIL=a@b POCKETBASE_ADMIN_PASSWORD=xxx node audit.js
//   node audit.js --url https://my.pb.io --email a@b --password xxx [--no-probe] [--html report.html]

import { writeFileSync } from "node:fs";

const UA = "pocketbase-security/0.1";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  rule_empty_public: {
    severity: "critical",
    title: "API rule is empty — collection is fully public",
    explain: "An empty rule in PocketBase means the operation is allowed for everyone, anonymous included. Anyone can call this endpoint without auth.",
  },
  rule_too_permissive_auth: {
    severity: "high",
    title: "API rule is `@request.auth.id != ''` — any logged-in user passes",
    explain: "This rule lets ANY authenticated user (including a freshly self-signed-up anonymous one) read/write the entire collection. Tighten with ownership checks.",
  },
  collection_admin_auth_with_open_signup: {
    severity: "high",
    title: "Auth collection allows open signups AND has lax create rule",
    explain: "Anyone can self-register, then immediately exploit a lax create-rule on a sensitive collection. Combo doubles the exposure.",
  },
  rule_uses_dangerous_literal: {
    severity: "high",
    title: "API rule contains `true` literal — bypasses all checks",
    explain: "PocketBase evaluates the rule expression; `true` short-circuits everything. Often left over from local dev.",
  },
  oauth2_provider_misconfigured: {
    severity: "medium",
    title: "OAuth2 provider enabled without redirect URL whitelist",
    explain: "Open redirect attack vector — attacker crafts URL pointing to their domain to capture tokens.",
  },
  email_auth_no_verification: {
    severity: "medium",
    title: "Auth collection allows email signup without verification",
    explain: "Anyone can create accounts with fake emails to bypass email-gated logic.",
  },
  s3_settings_exposed: {
    severity: "low",
    title: "S3 storage configured but credentials may be logged at debug level",
    explain: "Verify PB_LOG_LEVEL is not set to debug in production.",
  },
};

async function adminAuth(url, email, password) {
  const r = await fetch(`${url}/api/collections/_superusers/auth-with-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": UA },
    body: JSON.stringify({ identity: email, password }),
  });
  if (!r.ok) {
    // Fallback to legacy /api/admins/ for PocketBase < 0.23
    const legacy = await fetch(`${url}/api/admins/auth-with-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify({ identity: email, password }),
    });
    if (!legacy.ok) throw new Error(`Admin auth failed: ${r.status}/${legacy.status}`);
    return (await legacy.json()).token;
  }
  return (await r.json()).token;
}

async function listCollections(url, token) {
  const r = await fetch(`${url}/api/collections?perPage=200`, {
    headers: { Authorization: token, "User-Agent": UA },
  });
  if (!r.ok) throw new Error(`List collections failed: ${r.status}`);
  const data = await r.json();
  return data.items || [];
}

// Active probe: hit the public endpoint anonymously to PROVE the leak.
async function probeAnonAccess(url, collectionName, action = "list") {
  try {
    const path = action === "list"
      ? `/api/collections/${encodeURIComponent(collectionName)}/records?perPage=1`
      : `/api/collections/${encodeURIComponent(collectionName)}/records`;
    const r = await fetch(`${url}${path}`, {
      headers: { "User-Agent": UA },
    });
    const status = r.status;
    if (!r.ok) {
      return { confirmed: false, status, reason: status === 401 || status === 403 ? "auth required" : `http ${status}` };
    }
    const body = await r.text();
    let row_count = 0;
    let columns = [];
    try {
      const parsed = JSON.parse(body);
      const items = parsed.items || (Array.isArray(parsed) ? parsed : []);
      row_count = items.length;
      if (items[0] && typeof items[0] === "object") columns = Object.keys(items[0]);
    } catch { /* non-JSON */ }
    return {
      confirmed: true,
      status,
      sample: { row_count, columns: columns.slice(0, 8), bytes_returned: body.length },
    };
  } catch (e) {
    return { confirmed: false, status: 0, reason: `network error: ${e.message}` };
  }
}

const RULE_FIELDS = [
  { name: "listRule", action: "list" },
  { name: "viewRule", action: "view" },
  { name: "createRule", action: "create" },
  { name: "updateRule", action: "update" },
  { name: "deleteRule", action: "delete" },
];

function classifyRule(ruleStr) {
  if (ruleStr === null || ruleStr === undefined || ruleStr === "") {
    return "empty_public";
  }
  const trimmed = String(ruleStr).trim();
  if (trimmed === "true" || trimmed === "1=1" || trimmed.endsWith("|| true") || trimmed.startsWith("true ||")) {
    return "dangerous_literal";
  }
  // @request.auth.id != "" or != '' — too permissive
  if (/^@request\.auth\.id\s*!=\s*['""]\s*['""]\s*$/.test(trimmed)) {
    return "too_permissive_auth";
  }
  return "ok";
}

export async function audit(opts) {
  const { url, email, password, activeProbe = true } = opts;
  if (!url || !email || !password) throw new Error("audit() requires { url, email, password }");

  const findings = [];
  const token = await adminAuth(url, email, password);
  const collections = await listCollections(url, token);

  let probed = 0;
  let confirmed = 0;

  for (const col of collections) {
    if (col.system) continue; // skip _superusers, _otps, etc

    for (const { name: ruleField, action } of RULE_FIELDS) {
      const ruleVal = col[ruleField];
      const verdict = classifyRule(ruleVal);
      if (verdict === "ok") continue;

      const checkKey = verdict === "empty_public" ? "rule_empty_public"
        : verdict === "too_permissive_auth" ? "rule_too_permissive_auth"
        : "rule_uses_dangerous_literal";

      const finding = {
        check: checkKey,
        ...CHECKS[checkKey],
        target: `${col.name}.${ruleField}`,
        details: {
          collection: col.name,
          collection_type: col.type,
          rule_field: ruleField,
          action,
          rule_value: ruleVal === "" ? "(empty string)" : ruleVal,
        },
        fix_sql: `// Edit ${col.name}.${ruleField} in PocketBase admin UI:
// Replace the current value with an ownership check, e.g.:
//   @request.auth.id != "" && @request.auth.id = ownerId
// Or for admin-only:
//   @request.auth.id != "" && @request.auth.collectionName = "_superusers"`,
      };

      // Probe ONLY for list/view rules — write rules need a body so we can't safely probe.
      if (activeProbe && (action === "list" || action === "view") && verdict !== "ok") {
        const probe = await probeAnonAccess(url, col.name, action);
        finding.probe = probe;
        probed++;
        if (probe.confirmed) confirmed++;
      }

      findings.push(finding);
    }

    // Auth collection-specific checks
    if (col.type === "auth") {
      if (col.options?.allowEmailAuth && !col.options?.requireEmail && col.createRule !== null) {
        // Open signup + lax create
        if (col.createRule === "" || col.createRule === null) {
          findings.push({
            check: "collection_admin_auth_with_open_signup",
            ...CHECKS.collection_admin_auth_with_open_signup,
            target: col.name,
            details: { allowEmailAuth: true, createRule: col.createRule },
            fix_sql: `// In ${col.name} settings, either disable email signup OR set createRule to admin-only:
//   @request.auth.id != "" && @request.auth.collectionName = "_superusers"`,
          });
        }
      }
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    pocketbase_url: url,
    scanned_at: new Date().toISOString(),
    scanned_by: "pocketbase-security v0.1",
    active_probe: { enabled: activeProbe, probed, confirmed },
    summary,
    n_collections_scanned: collections.length,
    n_user_collections: collections.filter((c) => !c.system).length,
    findings,
  };
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.error(`Usage: pocketbase-security [--url URL --email E --password P] [--no-probe] [--json|--html report.html]\n\nEnv vars: POCKETBASE_URL, POCKETBASE_ADMIN_EMAIL, POCKETBASE_ADMIN_PASSWORD\n\nDetects: empty rules (fully public), over-permissive @request.auth.id != "", dangerous literals, open signup combos.\nActive probe (default ON) hits the public API anonymously to PROVE leaks.`);
    process.exit(1);
  }

  const flag = (k) => args.includes(k) ? args[args.indexOf(k) + 1] : null;
  const url = flag("--url") || process.env.POCKETBASE_URL;
  const email = flag("--email") || process.env.POCKETBASE_ADMIN_EMAIL;
  const password = flag("--password") || process.env.POCKETBASE_ADMIN_PASSWORD;
  const activeProbe = !args.includes("--no-probe");

  if (!url || !email || !password) {
    console.error("Error: provide --url, --email, --password (or POCKETBASE_URL / POCKETBASE_ADMIN_EMAIL / POCKETBASE_ADMIN_PASSWORD env vars)");
    process.exit(1);
  }

  const result = await audit({ url, email, password, activeProbe });

  const htmlIdx = args.indexOf("--html");
  if (htmlIdx !== -1) {
    const out = args[htmlIdx + 1] || "report.html";
    const { renderHtml } = await import("./report.js");
    writeFileSync(out, renderHtml(result));
    console.error(`HTML report written to ${out}`);
    console.error(`Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium${result.active_probe.enabled ? ` (${result.active_probe.confirmed} CONFIRMED via active probe)` : ""}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
