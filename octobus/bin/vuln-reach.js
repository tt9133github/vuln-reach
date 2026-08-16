#!/usr/bin/env node
/** OctoBus capability using the same rules and evidence as the Python engine. */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGED_WORKSPACE = path.join(ROOT, "workspace");
const WS = process.env.VULN_REACH_WORKSPACE ||
  (existsSync(PACKAGED_WORKSPACE) ? PACKAGED_WORKSPACE : path.resolve(ROOT, "../workspace"));
const STATUS = new Map([[true, "pass"], [false, "fail"], [null, "unknown"]]);

const readJson = (rel) => JSON.parse(readFileSync(path.join(WS, rel), "utf8"));
const readYaml = (rel) => parseYaml(readFileSync(path.join(WS, rel), "utf8"));

export function versionTuple(value) {
  const text = String(value ?? "").trim();
  if (!/^\d+(?:\.\d+)*$/.test(text)) return null;
  return /^\d+(?:\.\d+)*/.exec(text)[0].split(".").map(Number);
}

function compareVersions(left, right) {
  const size = Math.max(left.length, right.length);
  for (let index = 0; index < size; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

function parseConstraint(value) {
  const match = /^\s*(<=|>=|<|>|==|=)?\s*(\d+(?:\.\d+)*)\s*$/.exec(String(value));
  if (!match) return null;
  return [match[1] || "=", versionTuple(match[2])];
}

export function versionInRange(version, spec) {
  const current = versionTuple(version);
  const constraints = String(spec ?? "").split(",").map(parseConstraint);
  if (!current || !spec || constraints.some((value) => value === null)) return null;
  for (const [operator, target] of constraints) {
    const comparison = compareVersions(current, target);
    if (operator === "<" && comparison >= 0) return false;
    if (operator === "<=" && comparison > 0) return false;
    if (operator === ">" && comparison <= 0) return false;
    if (operator === ">=" && comparison < 0) return false;
    if (["=", "=="].includes(operator) && comparison !== 0) return false;
  }
  return true;
}

function resolveEvidencePath(evidence, dottedPath) {
  let current = [evidence];
  for (const segment of dottedPath.split(".")) {
    const expand = segment.endsWith("[*]");
    const key = expand ? segment.slice(0, -3) : segment;
    const next = [];
    for (const item of current) {
      if (!item || typeof item !== "object" || !(key in item)) continue;
      if (expand && Array.isArray(item[key])) next.push(...item[key]);
      else if (!expand) next.push(item[key]);
    }
    current = next;
  }
  return current;
}

const sinkPatterns = (sinks) => (sinks || []).map((item) =>
  typeof item === "object" ? String(item.api || "") : String(item)).filter(Boolean);

function evidenceItem(ruleId, check, value, detail, fields = {}) {
  return { ruleId, check, status: STATUS.get(value), detail, ...Object.fromEntries(Object.entries(fields).filter(([, item]) => item !== undefined && item !== "")) };
}

function checkSink(evidence, patterns) {
  if (patterns.length === 0) return [true, "rule has no fixed sink API; usage evidence is evaluated by preconditions", evidence?.usage || []];
  if (!evidence) return [null, "package usage evidence is missing", []];
  const matches = (evidence.sinks || []).filter((item) => patterns.includes(item.api));
  if (matches.length > 0) return [true, `matched ${matches.length} rule-defined sink call(s)`, matches];
  if (evidence.sink_scan_complete === true) return [false, "complete sink scan found no rule-defined call", []];
  return [null, "no matching sink found, but sink scan completeness is not established", []];
}

export function judge(alert, rule, dep, evidence, source = {}) {
  const installed = dep?.version || "";
  let versionMatch;
  let versionDetail;
  if (dep) {
    versionMatch = versionInRange(installed, rule.affected_versions);
    versionDetail = `${dep.package} ${installed} against ${rule.affected_versions || ""}`;
  } else if (source.authoritative === true) {
    versionMatch = false;
    versionDetail = "package absent from authoritative dependency inventory";
  } else {
    versionMatch = null;
    versionDetail = "package absent and dependency inventory is not authoritative";
  }

  const patterns = sinkPatterns(rule.sinks);
  const [sinkPresent, sinkDetail, matches] = checkSink(evidence, patterns);
  const checks = { versionMatch, sinkPresent, preconditions: {} };
  const items = [
    evidenceItem(rule.rule_id, "version_match", versionMatch, versionDetail, { observed: installed, expected: rule.affected_versions }),
    evidenceItem(rule.rule_id, "sink_present", sinkPresent, sinkDetail, { expected: patterns.join(", ") }),
  ];
  for (const match of matches) {
    items.push(evidenceItem(rule.rule_id, patterns.length > 0 ? "sink_call" : "usage", true, match.context || "matched code usage", { file: match.file, line: match.line, observed: match.api }));
  }
  for (const precondition of rule.preconditions || []) {
    const values = resolveEvidencePath(evidence || {}, precondition.evidence_path);
    const result = values.length === 0 ? null : values.some((value) => value === precondition.expect);
    checks.preconditions[precondition.id] = result;
    let location = {};
    if (precondition.evidence_path.startsWith("entry_points[*].")) {
      const key = precondition.evidence_path.split(".", 2)[1];
      const matchedEntry = (evidence?.entry_points || []).find((entry) => entry[key] === precondition.expect) || {};
      location = { file: matchedEntry.file, line: matchedEntry.line };
    }
    items.push(evidenceItem(rule.rule_id, `precondition:${precondition.id}`, result, precondition.description, { observed: JSON.stringify(values), expected: JSON.stringify(precondition.expect), ...location }));
  }

  const allChecks = [versionMatch, sinkPresent, ...Object.values(checks.preconditions)];
  let verdict;
  let reason;
  if (allChecks.some((value) => value === false)) [verdict, reason] = ["not_reachable", "at least one required condition is explicitly false"];
  else if (allChecks.some((value) => value === null)) [verdict, reason] = ["unknown", "one or more required conditions lack trustworthy evidence"];
  else [verdict, reason] = ["reachable", "version, sink and all exploit preconditions are established"];
  const located = items.some((item) => item.file && item.line);
  const confidence = verdict === "unknown" ? "low" : (located ? "high" : "medium");

  return {
    cveId: alert.advisory.cve_id, ghsaId: alert.advisory.ghsa_id,
    alertNumber: alert.alert.number, package: alert.vulnerability.package,
    installedVersion: installed, affectedVersions: rule.affected_versions || "",
    fixedVersion: rule.fixed_version || "", ruleId: rule.rule_id,
    sourceCommit: source.commit || "", scope: rule.scope || "component API boundary",
    limitations: rule.limitations || [],
    checks: {
      versionMatch: STATUS.get(checks.versionMatch),
      sinkPresent: STATUS.get(checks.sinkPresent),
      preconditions: Object.entries(checks.preconditions).map(([id, value]) => ({ id, status: STATUS.get(value) })),
    },
    verdict, confidence, reason,
    evidence: items, fix: rule.fix || [],
  };
}

function unknownResponse(request, reason) {
  return { cveId: request.cveId || "", alertNumber: Number(request.alertNumber || 0), verdict: "unknown", confidence: "low", reason, evidence: [], fix: [], limitations: [] };
}

export function checkReachabilityHandler(ctx) {
  const request = ctx.request || {};
  const cve = String(request.cveId || "").trim();
  const alertNumber = Number(request.alertNumber || 0);
  if ((cve && alertNumber) || (!cve && !alertNumber)) return unknownResponse(request, "provide exactly one selector: cveId or alertNumber");
  const alerts = readdirSync(path.join(WS, "alerts"))
    .filter((file) => file.endsWith(".json") && file !== "index.json")
    .map((file) => readJson(path.join("alerts", file)));
  const alert = cve ? alerts.find((item) => item.advisory.cve_id === cve) : alerts.find((item) => item.alert.number === alertNumber);
  if (!alert) return unknownResponse(request, "alert not found in workspace");

  const rules = new Map();
  for (const file of readdirSync(path.join(WS, "rules")).filter((item) => item.endsWith(".yaml") && item !== "verdict.yaml")) {
    for (const rule of readYaml(path.join("rules", file)).rules || []) {
      if (!rule.cve || rules.has(rule.cve)) throw new Error(`missing or duplicate CVE rule: ${rule.cve}`);
      rules.set(rule.cve, rule);
    }
  }
  const rule = rules.get(alert.advisory.cve_id);
  if (!rule) return unknownResponse(request, "no rule for this CVE");
  const dependencyDoc = readJson(path.join("repo", "dependencies.json"));
  const usage = readJson(path.join("repo", "usage.json")).evidence || {};
  const dep = (dependencyDoc.dependencies || []).find((item) => item.package === alert.vulnerability.package);
  return judge(alert, rule, dep, usage[alert.vulnerability.package], dependencyDoc.source || {});
}

async function main() {
  const { defineService, runServiceMain } = await import("@chaitin-ai/octobus-sdk");
  runServiceMain(defineService({ handlers: { "vulnreach.v1.VulnReachService/CheckReachability": checkReachabilityHandler } }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => { console.error(error); process.exit(1); });
}
