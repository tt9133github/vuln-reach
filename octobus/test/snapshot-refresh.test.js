import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { buildSnapshot } from "../lib/snapshot.js";

test("build creates an immutable snapshot from fixed alerts and a source archive", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "vuln-reach-snapshot-"));
  const workspace = path.join(temp, "workspace");
  const sources = path.join(temp, "sources.yaml");
  const alertsPath = path.join(temp, "inputs", "alerts");
  fs.mkdirSync(alertsPath, { recursive: true });
  fs.writeFileSync(sources, `repos:\n  - owner: example\n    repo: demo\n    branch: main\n    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    ecosystem: maven\n`);
  const pom = `<project><dependencies><dependency><groupId>com.alibaba</groupId><artifactId>fastjson</artifactId><version>1.2.31</version></dependency></dependencies></project>`;
  const java = `public class Example {
    public void parse(String input) {
      JSONObject.parseObject(input);
    }
  }`;
  const alert = {
    schema_version: "vuln-alert/1.0",
    alert: { number: 4, state: "open", html_url: "https://example.invalid/4" },
    repo: { owner: "example", name: "demo", branch: "main", ecosystem: "maven" },
    advisory: {
      cve_id: "CVE-2025-70974", ghsa_id: "GHSA-jm7w-5684-pvh8", summary: "demo", severity: "critical",
    },
    vulnerability: {
      package: "com.alibaba:fastjson", ecosystem: "maven",
      vulnerable_version_range: "< 1.2.48", first_patched_version: "1.2.48",
      vulnerable_manifest_path: "pom.xml",
    },
  };
  const alertText = `${JSON.stringify(alert, null, 2)}\n`;
  const indexText = `${JSON.stringify({ alerts: [{ file: "CVE-2025-70974.json" }] }, null, 2)}\n`;
  fs.writeFileSync(path.join(alertsPath, "CVE-2025-70974.json"), alertText);
  fs.writeFileSync(path.join(alertsPath, "index.json"), indexText);
  fs.writeFileSync(path.join(temp, "inputs", "manifest.json"), JSON.stringify({
    schema_version: "vuln-reach-input/1.0", repository: "example/demo", captured_at: "2026-01-01T00:00:00Z",
    files: {
      "CVE-2025-70974.json": createHash("sha256").update(alertText).digest("hex"),
      "index.json": createHash("sha256").update(indexText).digest("hex"),
    },
  }));
  const tarEntry = (name, content) => {
    const data = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, "utf8");
    header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header[156] = "0".charCodeAt(0);
    return Buffer.concat([header, data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
  };
  const archive = gzipSync(Buffer.concat([
    tarEntry("demo-aaaaaaaaaaaa/pom.xml", pom),
    tarEntry("demo-aaaaaaaaaaaa/src/main/java/Example.java", java),
    Buffer.alloc(1024),
  ]));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(archive, { status: 200, headers: { "content-type": "application/gzip" } });
  try {
    const result = await buildSnapshot({ workspacePath: workspace, sourcesPath: sources, alertsPath });
    assert.equal(result.alertCount, 1);
    assert.equal(result.resolvedCommit, "a".repeat(40));
    const pointer = JSON.parse(fs.readFileSync(path.join(workspace, "runtime", "current.json"), "utf8"));
    assert.equal(pointer.snapshot_id, result.snapshotId);
    const snapshot = path.join(workspace, "runtime", "snapshots", result.snapshotId);
    const dependencies = JSON.parse(fs.readFileSync(path.join(snapshot, "repo", "dependencies.json"), "utf8"));
    const usage = JSON.parse(fs.readFileSync(path.join(snapshot, "repo", "usage.json"), "utf8"));
    assert.equal(dependencies.dependencies[0].version, "1.2.31");
    assert.equal(usage.evidence["com.alibaba:fastjson"].entry_points[0].sink_argument_controlled, true);
    assert.equal(usage.evidence["com.alibaba:fastjson"].component_usage_scan_complete, true);
    assert.equal(fs.existsSync(path.join(snapshot, "source", "src", "main", "java", "Example.java")), true);
  } finally {
    globalThis.fetch = originalFetch;
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
