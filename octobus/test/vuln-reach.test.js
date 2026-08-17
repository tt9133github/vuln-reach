import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkReachabilityAt, classifyReachabilityLevel, judge, requestSelector, versionInRange } from "../bin/vuln-reach.js";
import { analyzeSourceUsage, parseMavenDependencies } from "../lib/snapshot.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const FIXTURE = path.join(ROOT, "tests", "fixtures", "workspace");
const INPUTS = path.join(ROOT, "inputs");

test("strict version parser does not fail open", () => {
  assert.equal(versionInRange("not-a-version", "< 2.0"), null);
  assert.equal(versionInRange("1.2.31-SNAPSHOT", "< 2.0"), null);
  assert.equal(versionInRange("1.2.31", "< nonsense"), null);
  assert.equal(versionInRange("1.2.31", ">= 1.2.25, < 1.2.83"), true);
});

test("fixed analysis fixture produces expected verdicts", () => {
  const firstFastjson = checkReachabilityAt(FIXTURE, { cveId: "CVE-2025-70974" }, "fixture", INPUTS);
  const secondFastjson = checkReachabilityAt(FIXTURE, { cveId: "CVE-2022-25845" }, "fixture", INPUTS);
  const velocity = checkReachabilityAt(FIXTURE, { cveId: "CVE-2020-13936" }, "fixture", INPUTS);
  assert.equal(firstFastjson.verdict, "reachable");
  assert.equal(firstFastjson.alertState, "open");
  assert.ok(firstFastjson.advisorySeverity);
  assert.equal(secondFastjson.verdict, "reachable");
  assert.equal(velocity.verdict, "unknown");
  assert.equal(firstFastjson.reachabilityLevel, "L3");
  assert.equal(secondFastjson.reachabilityLevel, "L3");
  assert.equal(velocity.reachabilityLevel, "L2");
  assert.equal(checkReachabilityAt(FIXTURE, { selector: { case: "cveId", value: "CVE-2025-70974" } }, "fixture", INPUTS).verdict, "reachable");
  assert.equal(checkReachabilityAt(FIXTURE, { selector: { case: "alertNumber", value: 1 } }, "fixture", INPUTS).verdict, "unknown");
});

test("enterprise levels represent the highest proven attack-chain stage", () => {
  const rule = {
    level_evidence: {
      component_usage: { evidence_path: "usage[*]" },
      dangerous_sink: { evidence_path: "sinks[*]" },
      external_input_to_sink: { evidence_path: "flows[*].external", expect: true },
      complete_attack_path: { all: [
        { evidence_path: "flows[*].external", expect: true },
        { evidence_path: "runtime.exploitable", expect: true },
      ] },
    },
  };
  const level = (evidence, version = true) => classifyReachabilityLevel(rule, evidence, version).level;
  assert.equal(level({ component_usage_scan_complete: true, usage: [], sinks: [] }), "L0");
  assert.equal(level({ usage: [{ api: "ordinary" }], sinks: [] }), "L1");
  assert.equal(level({ usage: [{ api: "ordinary" }], sinks: [{ api: "danger" }] }), "L2");
  assert.equal(level({ sinks: [{ api: "danger" }], flows: [{ external: true }] }), "L3");
  assert.equal(level({ sinks: [{ api: "danger" }], flows: [{ external: true }], runtime: { exploitable: true } }), "L4");
  assert.equal(level({}, true), "unknown");
  assert.equal(level({}, false), "NA");
});

test("missing level knowledge fails closed instead of becoming L0", () => {
  const result = classifyReachabilityLevel(
    { level_evidence: {} },
    { component_usage_scan_complete: true, sink_scan_complete: true },
    true,
  );
  assert.equal(result.level, "unknown");
  assert.match(result.reason, /does not define required level evidence/);
});

test("selector parser supports protobuf-es oneof and flat compatibility requests", () => {
  assert.deepEqual(requestSelector({ selector: { case: "cveId", value: " CVE-2025-70974 " } }), { cveId: "CVE-2025-70974", alertNumber: 0 });
  assert.deepEqual(requestSelector({ selector: { case: "alertNumber", value: 3 } }), { cveId: "", alertNumber: 3 });
  assert.deepEqual(requestSelector({ cveId: " CVE-2025-70974 " }), { cveId: "CVE-2025-70974", alertNumber: 0 });
  assert.deepEqual(requestSelector({ alertNumber: "invalid" }), { cveId: "", alertNumber: 0 });
});

test("request requires exactly one selector", () => {
  assert.equal(checkReachabilityAt(FIXTURE, {}, "", INPUTS).verdict, "unknown");
  assert.match(checkReachabilityAt(FIXTURE, { cveId: "CVE-2025-70974", alertNumber: 1 }, "", INPUTS).reason, /exactly one/);
  assert.match(checkReachabilityAt(FIXTURE, { selector: { case: undefined }, cveId: "CVE-2025-70974" }, "", INPUTS).reason, /exactly one/);
});

test("minimal Maven parser resolves direct dependencies", () => {
  const dependencies = parseMavenDependencies(`
    <project><properties><fastjson.version>1.2.31</fastjson.version></properties><dependencies>
      <dependency><groupId>com.alibaba</groupId><artifactId>fastjson</artifactId><version>\${fastjson.version}</version></dependency>
    </dependencies></project>`);
  assert.deepEqual(dependencies.map((item) => [item.package, item.version]), [["com.alibaba:fastjson", "1.2.31"]]);
});

test("source scanner derives fastjson flow and internal Velocity templates", () => {
  const files = {
    "src/main/java/Example.java": `public class Example {
      public void entry(String input) { parse(input); }
      private void parse(String value) { value = value.trim(); JSONObject.parseObject(value); }
      protected String getTemplatePath() { return "/vm/index.vm"; }
      void render() { velocityEngine.getTemplate(getTemplatePath()); }
    }`,
    "src/main/resources/vm/index.vm": "ok",
  };
  const evidence = analyzeSourceUsage(files);
  assert.equal(evidence["com.alibaba:fastjson"].entry_points[0].sink_argument_controlled, true);
  assert.equal(evidence["org.apache.velocity:velocity"].template_control, "internal");
});

test("incomplete negative evidence remains unknown", () => {
  const syntheticAlert = { alert: { number: 1 }, advisory: { cve_id: "CVE-X", ghsa_id: "GHSA-X" }, vulnerability: { package: "g:a" } };
  const syntheticRule = { rule_id: "rule-x", affected_versions: "< 2.0", sinks: [{ api: "danger" }], preconditions: [] };
  const result = judge(syntheticAlert, syntheticRule, { package: "g:a", version: "1.0" }, { sinks: [] }, { authoritative: true });
  assert.equal(result.verdict, "unknown");
  assert.equal(result.checks.sinkPresent, "unknown");
});

test("Velocity requires its rule-defined dangerous API", () => {
  const alert = { alert: { number: 1, state: "open" }, advisory: { cve_id: "CVE-V", ghsa_id: "GHSA-V", severity: "high" }, vulnerability: { package: "g:v" } };
  const rule = {
    rule_id: "velocity-test", affected_versions: "< 2.0",
    sinks: [{ api: "VelocityEngine.getTemplate(String)" }],
    preconditions: [{ id: "controlled", description: "controlled template", evidence_path: "template_control", expect: "attacker_controlled" }],
    level_evidence: {
      component_usage: { evidence_path: "usage[*]" },
      dangerous_sink: { evidence_path: "usage[*]", field: "api", expect: "VelocityEngine.getTemplate(String)" },
      external_input_to_sink: { evidence_path: "template_control", expect: "attacker_controlled" },
      complete_attack_path: { all: [{ evidence_path: "runtime.exploitable", expect: true }] },
    },
  };
  const result = judge(alert, rule, { package: "g:v", version: "1.0" }, {
    sink_scan_complete: true,
    usage: [{ api: "VelocityEngine.init(Properties)" }],
    template_control: "attacker_controlled",
  }, { authoritative: true });
  assert.equal(result.verdict, "not_reachable");
  assert.equal(result.checks.sinkPresent, "fail");
});
