import test from "node:test";
import assert from "node:assert/strict";
import { checkReachabilityHandler, judge, versionInRange } from "../bin/vuln-reach.js";

test("strict version parser does not fail open", () => {
  assert.equal(versionInRange("not-a-version", "< 2.0"), null);
  assert.equal(versionInRange("1.2.31-SNAPSHOT", "< 2.0"), null);
  assert.equal(versionInRange("1.2.31", "< nonsense"), null);
  assert.equal(versionInRange("1.2.31", ">= 1.2.25, < 1.2.83"), true);
});

test("curated workspace produces expected verdicts", () => {
  assert.equal(checkReachabilityHandler({ request: { cveId: "CVE-2025-70974" } }).verdict, "reachable");
  assert.equal(checkReachabilityHandler({ request: { cveId: "CVE-2022-25845" } }).verdict, "reachable");
  assert.equal(checkReachabilityHandler({ request: { cveId: "CVE-2020-13936" } }).verdict, "not_reachable");
});

test("request requires exactly one selector", () => {
  assert.equal(checkReachabilityHandler({ request: {} }).verdict, "unknown");
  assert.match(checkReachabilityHandler({ request: { cveId: "CVE-2025-70974", alertNumber: 1 } }).reason, /exactly one/);
});

test("incomplete negative evidence remains unknown", () => {
  const syntheticAlert = { alert: { number: 1 }, advisory: { cve_id: "CVE-X", ghsa_id: "GHSA-X" }, vulnerability: { package: "g:a" } };
  const syntheticRule = { rule_id: "rule-x", affected_versions: "< 2.0", sinks: [{ api: "danger" }], preconditions: [] };
  const result = judge(syntheticAlert, syntheticRule, { package: "g:a", version: "1.0" }, { sinks: [] }, { authoritative: true });
  assert.equal(result.verdict, "unknown");
  assert.equal(result.checks.sinkPresent, "unknown");
});
