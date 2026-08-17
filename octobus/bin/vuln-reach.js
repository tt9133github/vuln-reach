#!/usr/bin/env node
/** OctoBus capability for reproducible evidence collection and reachability decisions. */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";
import { buildSnapshot, resolveSnapshot } from "../lib/snapshot.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGED_WORKSPACE = path.join(ROOT, "workspace");
const DEFAULT_WORKSPACE = process.env.VULN_REACH_WORKSPACE || "/data/projects/vuln-reach/workspace";
const RULES_WORKSPACE = existsSync(path.join(PACKAGED_WORKSPACE, "rules"))
  ? PACKAGED_WORKSPACE
  : path.resolve(ROOT, "../workspace");
const STATUS = new Map([[true, "pass"], [false, "fail"], [null, "unknown"]]);

const readJsonAt = (root, rel) => JSON.parse(readFileSync(path.join(root, rel), "utf8"));
const readRuleYaml = (rel) => parseYaml(readFileSync(path.join(RULES_WORKSPACE, rel), "utf8"));

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

function signalValues(evidence, signal = {}) {
  const paths = signal.evidence_paths || (signal.evidence_path ? [signal.evidence_path] : []);
  return paths.flatMap((item) => resolveEvidencePath(evidence || {}, item));
}

function signalEstablished(evidence, signal = {}) {
  const values = signalValues(evidence, signal);
  if (values.length === 0) return null;
  if (signal.field) {
    const observed = values
      .filter((item) => item && typeof item === "object" && signal.field in item)
      .map((item) => item[signal.field]);
    if (observed.length === 0) return null;
    return signal.expect === undefined ? true : observed.some((item) => item === signal.expect);
  }
  if (signal.expect !== undefined) {
    if (values.some((item) => item === signal.expect)) return true;
    const unknownValues = new Set(signal.unknown_values || ["unknown"]);
    return values.every((item) => unknownValues.has(item)) ? null : false;
  }
  return true;
}

function attackPathEstablished(evidence, signal = {}) {
  const states = (signal.all || []).map((item) => signalEstablished(evidence, item));
  if (states.length === 0 || states.some((item) => item === null)) return null;
  return states.every(Boolean);
}

const FALLBACK_LEVELS = {
  L0: { definition: "漏洞版本存在，但完整扫描未发现组件使用", governance_action: "记录后降级处置，并评估移除未使用依赖" },
  L1: { definition: "组件使用已确认，尚未证明到达危险函数", governance_action: "常规治理；保留扫描完整性证据" },
  L2: { definition: "危险函数调用已确认，尚未证明外部输入到达危险参数", governance_action: "进入专项复核，检查真实入口与数据流" },
  L3: { definition: "分析边界外的调用者可控输入到达危险函数，但完整利用前提尚未全部成立", governance_action: "高优先级整改并核查配置、gadget、网络与权限条件" },
  L4: { definition: "版本、外部入口、危险函数与全部利用前提形成完整攻击路径", governance_action: "按紧急事件处置：立即缓解、升级并验证阻断" },
};

export function classifyReachabilityLevel(rule, evidence, versionMatch, policy = {}) {
  if (versionMatch === false) {
    return { level: "NA", reason: "installed version is outside the vulnerable range", governanceAction: "按版本证据关闭该告警或复核告警数据" };
  }
  if (versionMatch === null) {
    return { level: "unknown", reason: "vulnerable component version is not established", governanceAction: "补齐权威依赖与版本证据" };
  }

  const signals = rule.level_evidence || {};
  const requiredSignals = ["component_usage", "dangerous_sink", "external_input_to_sink", "complete_attack_path"];
  const missingSignals = requiredSignals.filter((name) => !signals[name]);
  if (missingSignals.length > 0) {
    return {
      level: "unknown",
      reason: `rule does not define required level evidence: ${missingSignals.join(", ")}`,
      governanceAction: "补齐规则证据映射后重新分级",
      checks: {
        componentUsage: "unknown",
        dangerousSink: "unknown",
        externalInputToSink: "unknown",
        completeAttackPath: "unknown",
      },
    };
  }
  const componentUsage = signalEstablished(evidence, signals.component_usage);
  const dangerousSink = signalEstablished(evidence, signals.dangerous_sink);
  const externalInput = signalEstablished(evidence, signals.external_input_to_sink);
  const completeAttackPath = attackPathEstablished(evidence, signals.complete_attack_path);
  let level = "unknown";
  let reason = "source evidence is insufficient to establish even Level 0";

  if (completeAttackPath === true && externalInput === true && dangerousSink === true) {
    level = "L4";
    reason = "external entry, dangerous sink and every rule-defined exploit prerequisite are established";
  } else if (externalInput === true && dangerousSink === true) {
    level = "L3";
    reason = "caller-controlled input from outside the analysis boundary reaches the dangerous sink, but the complete exploit path is not established";
  } else if (dangerousSink === true) {
    level = "L2";
    reason = "a dangerous sink call is established, but external-input control of its argument is not established";
  } else if (componentUsage === true) {
    level = "L1";
    reason = "component use is established, but no dangerous sink call is established";
  } else if (evidence?.component_usage_scan_complete === true || evidence?.sink_scan_complete === true) {
    level = "L0";
    reason = "the vulnerable component is installed and a complete source scan found no component use";
  }

  const configured = policy?.reachability_levels?.levels?.[level] || FALLBACK_LEVELS[level] || {};
  return {
    level,
    reason,
    governanceAction: configured.governance_action || "补齐证据后重新分级",
    checks: {
      componentUsage: STATUS.get(componentUsage),
      dangerousSink: STATUS.get(dangerousSink),
      externalInputToSink: STATUS.get(externalInput),
      completeAttackPath: STATUS.get(completeAttackPath),
    },
  };
}

const sinkPatterns = (sinks) => (sinks || []).map((item) =>
  typeof item === "object" ? String(item.api || "") : String(item)).filter(Boolean);

function evidenceItem(ruleId, check, value, detail, fields = {}) {
  return { ruleId, check, status: STATUS.get(value), detail, ...Object.fromEntries(Object.entries(fields).filter(([, item]) => item !== undefined && item !== "")) };
}

function checkSink(evidence, patterns) {
  if (patterns.length === 0) return [true, "rule has no fixed sink API; usage evidence is evaluated by preconditions", evidence?.usage || []];
  if (!evidence) return [null, "package usage evidence is missing", []];
  const candidates = [...(evidence.sinks || []), ...(evidence.usage || [])];
  const matches = candidates.filter((item) => patterns.includes(item.api));
  if (matches.length > 0) return [true, `matched ${matches.length} rule-defined sink call(s)`, matches];
  if (evidence.sink_scan_complete === true) return [false, "complete sink scan found no rule-defined call", []];
  return [null, "no matching sink found, but sink scan completeness is not established", []];
}

export function judge(alert, rule, dep, evidence, source = {}, snapshotId = "", policy = {}) {
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
  const level = classifyReachabilityLevel(rule, evidence, versionMatch, policy);

  return {
    cveId: alert.advisory.cve_id, ghsaId: alert.advisory.ghsa_id,
    alertNumber: alert.alert.number, alertState: alert.alert.state || "",
    advisorySeverity: alert.advisory.severity || "", package: alert.vulnerability.package,
    installedVersion: installed, affectedVersions: rule.affected_versions || "",
    fixedVersion: rule.fixed_version || "", ruleId: rule.rule_id,
    sourceCommit: source.commit || "", snapshotId, scope: rule.scope || "component API boundary",
    limitations: rule.limitations || [],
    checks: {
      versionMatch: STATUS.get(checks.versionMatch),
      sinkPresent: STATUS.get(checks.sinkPresent),
      preconditions: Object.entries(checks.preconditions).map(([id, value]) => ({ id, status: STATUS.get(value) })),
    },
    verdict, confidence, reason,
    reachabilityLevel: level.level,
    levelReason: level.reason,
    governanceAction: level.governanceAction,
    levelChecks: level.checks,
    evidence: items, fix: rule.fix || [],
  };
}

export function requestSelector(request = {}) {
  const alertNumberValue = (value) => {
    const number = Number(value ?? 0);
    return Number.isInteger(number) && number > 0 ? number : 0;
  };
  const selector = request?.selector;
  if (selector && typeof selector === "object" && Object.prototype.hasOwnProperty.call(selector, "case")) {
    if (selector.case === "cveId") return { cveId: String(selector.value ?? "").trim(), alertNumber: 0 };
    if (selector.case === "alertNumber") return { cveId: "", alertNumber: alertNumberValue(selector.value) };
    return { cveId: "", alertNumber: 0 };
  }
  return {
    cveId: String(request?.cveId ?? "").trim(),
    alertNumber: alertNumberValue(request?.alertNumber),
  };
}

function unknownResponse(request, reason, snapshotId = request?.snapshotId || "") {
  const selector = requestSelector(request);
  return {
    cveId: selector.cveId, alertNumber: selector.alertNumber, snapshotId,
    verdict: "unknown", confidence: "low", reason,
    reachabilityLevel: "unknown", levelReason: reason,
    governanceAction: "补齐证据后重新分级", levelChecks: {},
    evidence: [], fix: [], limitations: [],
  };
}

export function checkReachabilityAt(snapshotRoot, request, snapshotId = "", alertRoot = snapshotRoot) {
  const { cveId: cve, alertNumber } = requestSelector(request);
  if ((cve && alertNumber) || (!cve && !alertNumber)) return unknownResponse(request, "provide exactly one selector: cveId or alertNumber", snapshotId);
  const alerts = readdirSync(path.join(alertRoot, "alerts"))
    .filter((file) => file.endsWith(".json") && file !== "index.json")
    .map((file) => readJsonAt(alertRoot, path.join("alerts", file)));
  const alert = cve ? alerts.find((item) => item.advisory.cve_id === cve) : alerts.find((item) => item.alert.number === alertNumber);
  if (!alert) return unknownResponse(request, "alert not found in workspace", snapshotId);

  const rules = new Map();
  for (const file of readdirSync(path.join(RULES_WORKSPACE, "rules")).filter((item) => item.endsWith(".yaml") && item !== "verdict.yaml")) {
    for (const rule of readRuleYaml(path.join("rules", file)).rules || []) {
      if (!rule.cve || rules.has(rule.cve)) throw new Error(`missing or duplicate CVE rule: ${rule.cve}`);
      rules.set(rule.cve, rule);
    }
  }
  const rule = rules.get(alert.advisory.cve_id);
  if (!rule) return unknownResponse(request, "no rule for this CVE", snapshotId);
  const policy = readRuleYaml(path.join("rules", "verdict.yaml"));
  const dependencyDoc = readJsonAt(snapshotRoot, path.join("repo", "dependencies.json"));
  const usage = readJsonAt(snapshotRoot, path.join("repo", "usage.json")).evidence || {};
  const dep = (dependencyDoc.dependencies || []).find((item) => item.package === alert.vulnerability.package);
  return judge(alert, rule, dep, usage[alert.vulnerability.package], dependencyDoc.source || {}, snapshotId, policy);
}

export function checkReachabilityHandler(ctx) {
  const request = ctx.request || {};
  try {
    const workspacePath = ctx.config?.workspacePath || DEFAULT_WORKSPACE;
    const { snapshotId, snapshotRoot } = resolveSnapshot(workspacePath, request.snapshotId || "");
    return checkReachabilityAt(snapshotRoot, request, snapshotId);
  } catch (error) {
    return unknownResponse(request, `snapshot unavailable: ${error.message}`);
  }
}

export async function buildRepositoryEvidenceHandler(ctx) {
  return buildSnapshot({
    workspacePath: ctx.config?.workspacePath || DEFAULT_WORKSPACE,
    sourcesPath: path.join(ROOT, "sources.yaml"),
    alertsPath: path.join(ROOT, "inputs", "alerts"),
  });
}

async function main() {
  const { defineService, runServiceMain } = await import("@chaitin-ai/octobus-sdk");
  runServiceMain(defineService({ handlers: {
    "vulnreach.v1.VulnReachService/BuildRepositoryEvidence": buildRepositoryEvidenceHandler,
    "vulnreach.v1.VulnReachService/CheckReachability": checkReachabilityHandler,
  } }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => { console.error(error); process.exit(1); });
}
