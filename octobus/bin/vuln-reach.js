#!/usr/bin/env node
/**
 * OctoBus capability: vuln-reach / CheckReachability.
 *
 * Consumes the SAME rule files and repository evidence as the Python
 * reachability.py (single source of truth in workspace/):
 *   workspace/rules/*.yaml   rules (version ranges, sinks, preconditions)
 *   workspace/repo/*.json    dependency inventory + code usage evidence
 *   workspace/alerts/*.json  normalized alert contracts
 */
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WS = path.join(ROOT, "workspace");

function readJson(rel) {
  return JSON.parse(readFileSync(path.join(WS, rel), "utf8"));
}

function readYaml(rel) {
  return parseYaml(readFileSync(path.join(WS, rel), "utf8"));
}

function versionTuple(v) {
  return String(v)
    .trim()
    .toLowerCase()
    .split(".")
    .map((part) => {
      const m = /^(\d+)/.exec(part);
      return m ? parseInt(m[1], 10) : 0;
    });
}

function parseConstraint(text) {
  const m = /^(<=|>=|<|>|==|=)?\s*([0-9][0-9a-zA-Z._-]*)/.exec(String(text).trim());
  if (!m) return [null, null];
  return [m[1] || "=", versionTuple(m[2])];
}

function cmpVersion(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

function versionInRange(version, spec) {
  if (!spec || !String(spec).trim()) return true;
  const v = versionTuple(version);
  return String(spec)
    .split(",")
    .every((part) => {
      const [op, target] = parseConstraint(part);
      if (target == null) return true;
      const c = cmpVersion(v, target);
      if (op === "<") return c < 0;
      if (op === "<=") return c <= 0;
      if (op === ">") return c > 0;
      if (op === ">=") return c >= 0;
      return c === 0;
    });
}

function resolveEvidencePath(evidence, p) {
  let current = [evidence];
  for (const seg of p.split(".")) {
    const next = [];
    if (seg.endsWith("[*]")) {
      const key = seg.slice(0, -3);
      for (const item of current) {
        if (item && typeof item === "object" && Array.isArray(item[key])) next.push(...item[key]);
      }
    } else {
      for (const item of current) {
        if (item && typeof item === "object" && seg in item) next.push(item[seg]);
      }
    }
    current = next;
  }
  return current;
}

function sinkPatterns(ruleSinks) {
  return (ruleSinks || [])
    .map((s) => (s && typeof s === "object" ? String(s.api || "") : String(s)))
    .filter(Boolean);
}

export function judge(alert, rule, dep, evidence) {
  const checks = { preconditions: {} };
  const evidenceItems = [];
  const installed = dep ? dep.version || "" : "";

  if (dep) {
    checks.versionMatch = versionInRange(installed, rule.affected_versions || "");
    evidenceItems.push({
      ruleId: rule.rule_id,
      check: "version_match",
      detail: checks.versionMatch
        ? `${dep.package} ${installed} in ${rule.affected_versions || "*"}`
        : `${dep.package} ${installed} NOT in ${rule.affected_versions || "*"}`,
    });
  } else {
    checks.versionMatch = false;
    evidenceItems.push({
      ruleId: rule.rule_id,
      check: "version_match",
      detail: "package not found in dependency inventory",
    });
  }

  const patterns = sinkPatterns(rule.sinks);
  if (patterns.length === 0) {
    checks.sinkPresent = true;
    evidenceItems.push({
      ruleId: rule.rule_id,
      check: "sink_present",
      detail: "rule defines no fixed sink API; sink check skipped",
    });
    for (const u of (evidence && evidence.usage) || []) {
      evidenceItems.push({
        ruleId: rule.rule_id,
        check: "usage",
        detail: `${u.file || ""}:${u.line || ""} ${u.api || ""} - ${u.context || ""}`,
      });
    }
  } else if (evidence) {
    const sinkApis = (evidence.sinks || []).map((e) => e.api || "");
    const matched = sinkApis.filter((s) => patterns.includes(s));
    checks.sinkPresent = matched.length > 0;
    evidenceItems.push({
      ruleId: rule.rule_id,
      check: "sink_present",
      detail: checks.sinkPresent ? `sink hit: ${matched.join(", ")}` : "no rule-defined sink call found",
    });
    if (checks.sinkPresent) {
      for (const e of evidence.sinks || []) {
        if (patterns.includes(e.api)) {
          evidenceItems.push({
            ruleId: rule.rule_id,
            check: "sink_call",
            detail: `${e.file || ""}:${e.line || ""} ${e.api || ""} - ${e.context || ""}`,
          });
        }
      }
    }
  } else {
    checks.sinkPresent = false;
    evidenceItems.push({
      ruleId: rule.rule_id,
      check: "sink_present",
      detail: "no evidence in usage.json for this package",
    });
  }

  let precondMet = true;
  for (const pc of rule.preconditions || []) {
    const values = resolveEvidencePath(evidence || {}, pc.evidence_path);
    let ok = null;
    if (values.length === 0) {
      ok = null;
      precondMet = false;
      evidenceItems.push({
        ruleId: rule.rule_id,
        check: `precondition:${pc.id}`,
        detail: `${pc.description} - evidence missing`,
      });
    } else {
      ok = values.some((v) => v === pc.expect);
      precondMet = precondMet && ok;
      evidenceItems.push({
        ruleId: rule.rule_id,
        check: `precondition:${pc.id}`,
        detail: `${pc.description} - ${ok ? "met" : "NOT met"} (values: ${JSON.stringify(values)})`,
      });
    }
    checks.preconditions[pc.id] = ok;
  }

  let verdict;
  let reason;
  if (!checks.versionMatch) {
    verdict = "not_reachable";
    reason = "installed version outside affected range";
  } else if (!checks.sinkPresent) {
    verdict = "not_reachable";
    reason = "no rule-defined sink call found";
  } else if (Object.values(checks.preconditions).some((v) => v === false)) {
    verdict = "not_reachable";
    const failed = (rule.preconditions || [])
      .filter((pc) => checks.preconditions[pc.id] === false)
      .map((pc) => pc.description);
    reason = "precondition not met: " + failed.join("; ");
  } else if (Object.values(checks.preconditions).some((v) => v === null)) {
    verdict = "unknown";
    reason = "precondition evidence missing";
  } else {
    verdict = "reachable";
    reason = "version hit, sink present and all preconditions met";
  }

  let confidence = "medium";
  if (verdict === "not_reachable" && !checks.versionMatch) confidence = "high";
  else if (verdict === "reachable") {
    confidence = evidenceItems.some((e) => /\.java:\d+/.test(e.detail)) ? "high" : "medium";
  } else if (verdict === "unknown") confidence = "low";

  return {
    cveId: alert.advisory.cve_id,
    ghsaId: alert.advisory.ghsa_id,
    package: alert.vulnerability.package,
    installedVersion: installed,
    affectedVersions: rule.affected_versions || "",
    verdict,
    confidence,
    reason,
    evidence: evidenceItems,
    fix: rule.fix || [],
  };
}

export function checkReachabilityHandler(ctx) {
  const req = ctx.request || {};
  const cve = String(req.cveId || "").trim();
  const alertNumber = Number(req.alertNumber || 0);

  const alertFiles = readdirSync(path.join(WS, "alerts")).filter(
    (f) => f.endsWith(".json") && f !== "index.json",
  );
  const alerts = alertFiles.map((f) => readJson(path.join("alerts", f)));
  const alert = alerts.find(
    (a) => (cve && a.advisory.cve_id === cve) || (alertNumber && a.alert.number === alertNumber),
  );

  if (!alert) {
    return {
      cveId: cve,
      verdict: "unknown",
      confidence: "low",
      reason: `alert not found in workspace (cve=${cve}, number=${alertNumber})`,
      evidence: [],
      fix: [],
    };
  }

  const rules = {};
  for (const f of readdirSync(path.join(WS, "rules")).filter(
    (f) => f.endsWith(".yaml") && f !== "verdict.yaml",
  )) {
    const doc = readYaml(path.join("rules", f));
    for (const r of doc.rules || []) rules[r.cve] = r;
  }
  const rule = rules[alert.advisory.cve_id];
  if (!rule) {
    return {
      cveId: alert.advisory.cve_id,
      ghsaId: alert.advisory.ghsa_id,
      package: alert.vulnerability.package,
      verdict: "unknown",
      confidence: "low",
      reason: "no rule for this CVE",
      evidence: [],
      fix: [],
    };
  }

  const deps = readJson(path.join("repo", "dependencies.json")).dependencies || [];
  const usage = readJson(path.join("repo", "usage.json")).evidence || {};
  const dep = deps.find((d) => d.package === alert.vulnerability.package);
  return judge(alert, rule, dep, usage[alert.vulnerability.package]);
}

async function main() {
  const { defineService, runServiceMain } = await import("@chaitin-ai/octobus-sdk");
  const service = defineService({
    handlers: {
      "vulnreach.v1.VulnReachService/CheckReachability": checkReachabilityHandler,
    },
  });
  runServiceMain(service);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
