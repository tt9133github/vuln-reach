import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildSnapshot } from "../lib/snapshot.js";
import { checkReachabilityAt } from "../bin/vuln-reach.js";

const enabled = process.env.VULN_REACH_LIVE_SOURCE === "1";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("optional public codeload end-to-end smoke", { skip: !enabled }, async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "vuln-reach-live-"));
  try {
    const workspace = path.join(temp, "workspace");
    const result = await buildSnapshot({
      workspacePath: workspace,
      sourcesPath: path.join(ROOT, "sources.yaml"),
      alertsPath: path.join(ROOT, "inputs", "alerts"),
    });
    assert.equal(result.resolvedCommit, "d253e2585d9cc702037b43edb7cff5752a1281bc");
    assert.equal(result.alertCount, 3);
    assert.ok(result.sourceFileCount >= 20);
    const snapshot = path.join(temp, "workspace", "runtime", "snapshots", result.snapshotId);
    const usage = JSON.parse(fs.readFileSync(path.join(snapshot, "repo", "usage.json"), "utf8"));
    assert.equal(usage.evidence["com.alibaba:fastjson"].sinks[0].line, 114);
    assert.equal(usage.evidence["com.alibaba:fastjson"].entry_points[0].line, 16);
    assert.equal(usage.evidence["org.apache.velocity:velocity"].template_control, undefined);
    assert.equal(checkReachabilityAt(snapshot, { cveId: "CVE-2025-70974" }, result.snapshotId).verdict, "reachable");
    assert.equal(checkReachabilityAt(snapshot, { cveId: "CVE-2022-25845" }, result.snapshotId).verdict, "reachable");
    assert.equal(checkReachabilityAt(snapshot, { cveId: "CVE-2020-13936" }, result.snapshotId).verdict, "unknown");
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
