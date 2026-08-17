import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkReachabilityAt, judge, versionInRange } from "../bin/vuln-reach.js";
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
  assert.equal(checkReachabilityAt(FIXTURE, { cveId: "CVE-2025-70974" }, "fixture", INPUTS).verdict, "reachable");
  assert.equal(checkReachabilityAt(FIXTURE, { cveId: "CVE-2022-25845" }, "fixture", INPUTS).verdict, "reachable");
  assert.equal(checkReachabilityAt(FIXTURE, { cveId: "CVE-2020-13936" }, "fixture", INPUTS).verdict, "unknown");
});

test("request requires exactly one selector", () => {
  assert.equal(checkReachabilityAt(FIXTURE, {}, "", INPUTS).verdict, "unknown");
  assert.match(checkReachabilityAt(FIXTURE, { cveId: "CVE-2025-70974", alertNumber: 1 }, "", INPUTS).reason, /exactly one/);
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
