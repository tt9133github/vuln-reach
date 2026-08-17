import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import { parse as parseYaml } from "yaml";

const CODELOAD = "https://codeload.github.com";
const MAX_SOURCE_FILES = 500;
const MAX_BLOB_BYTES = 512 * 1024;
const MAX_ARCHIVE_BYTES = 50 * 1024 * 1024;

function tarText(buffer, start, length) {
  return buffer.subarray(start, start + length).toString("utf8").replace(/\0.*$/s, "").trim();
}

function selectedSource(file) {
  return file === "pom.xml" || file.endsWith(".java") || file.endsWith(".vm") || file.endsWith(".properties");
}

function extractSourceFiles(tarBuffer) {
  const files = {};
  for (let offset = 0; offset + 512 <= tarBuffer.length;) {
    const header = tarBuffer.subarray(offset, offset + 512);
    if (header.every((value) => value === 0)) break;
    const name = tarText(header, 0, 100);
    const prefix = tarText(header, 345, 155);
    const fullName = prefix ? `${prefix}/${name}` : name;
    const sizeText = tarText(header, 124, 12);
    const size = Number.parseInt(sizeText || "0", 8);
    if (!Number.isFinite(size) || size < 0) throw new Error("invalid tar entry size");
    const type = String.fromCharCode(header[156] || 48);
    const dataStart = offset + 512;
    const relative = fullName.split("/").slice(1).join("/");
    if ((type === "0" || type === "\0") && selectedSource(relative)) {
      if (!relative || relative.split("/").includes("..")) throw new Error("unsafe source archive path");
      if (size > MAX_BLOB_BYTES) throw new Error(`source file too large: ${relative}`);
      files[relative] = tarBuffer.subarray(dataStart, dataStart + size).toString("utf8");
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return files;
}

async function fetchRepositoryFiles(repoConfig) {
  const { owner, repo } = repoConfig;
  const commit = String(repoConfig.commit || "");
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("sources.yaml must pin an exact 40-character commit SHA");
  const archiveUrl = `${CODELOAD}/${owner}/${repo}/tar.gz/${commit}`;
  const response = await fetch(archiveUrl, { headers: { "User-Agent": "vuln-reach-agent" }, signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`public source archive returned HTTP ${response.status}`);
  const compressed = Buffer.from(await response.arrayBuffer());
  if (compressed.length > MAX_ARCHIVE_BYTES) throw new Error("compressed source archive exceeds safety limit");
  const archive = gunzipSync(compressed);
  if (archive.length > MAX_ARCHIVE_BYTES) throw new Error("expanded source archive exceeds safety limit");
  const files = extractSourceFiles(archive);
  if (Object.keys(files).length === 0 || Object.keys(files).length > MAX_SOURCE_FILES) {
    throw new Error(`source file count ${Object.keys(files).length} is outside safe range 1..${MAX_SOURCE_FILES}`);
  }
  if (!("pom.xml" in files)) throw new Error("pinned repository does not contain pom.xml");
  return { commit, files, archiveUrl };
}

function tagValue(xml, tag) {
  const match = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`).exec(xml);
  return match ? match[1].trim() : "";
}

export function parseMavenDependencies(pomXml) {
  const clean = pomXml.replace(/<!--[\s\S]*?-->/g, "");
  const propertiesBlock = tagValue(clean, "properties");
  const properties = {};
  for (const match of propertiesBlock.matchAll(/<([A-Za-z0-9_.-]+)>([^<]+)<\/\1>/g)) {
    properties[match[1]] = match[2].trim();
  }
  const dependenciesBlock = tagValue(clean, "dependencies");
  if (!dependenciesBlock) throw new Error("pom.xml has no direct dependencies block");
  const dependencies = [];
  for (const match of dependenciesBlock.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const block = match[1];
    const groupId = tagValue(block, "groupId");
    const artifactId = tagValue(block, "artifactId");
    let version = tagValue(block, "version");
    const property = /^\$\{([^}]+)\}$/.exec(version);
    if (property) version = properties[property[1]] || "";
    if (!groupId || !artifactId || !version) {
      throw new Error(`unresolved direct Maven dependency: ${groupId}:${artifactId}:${version || "<version>"}`);
    }
    dependencies.push({
      groupId,
      artifactId,
      package: `${groupId}:${artifactId}`,
      version,
      scope: tagValue(block, "scope") || "compile",
      optional: tagValue(block, "optional") === "true",
      transitive: false,
    });
  }
  if (dependencies.length === 0) throw new Error("pom.xml direct dependency inventory is empty");
  return dependencies;
}

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

function sourceLocation(files, predicate) {
  const result = [];
  for (const [file, content] of Object.entries(files)) {
    if (!file.endsWith(".java")) continue;
    const lines = content.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (predicate(line)) result.push({ file, line: index + 1, text: line.trim() });
    });
  }
  return result;
}

function javaMethods(content) {
  const lines = content.split(/\r?\n/);
  const methods = [];
  const signature = /^\s*(public|protected|private)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\], ?]+\s+(\w+)\s*\(([^)]*)\)/;
  for (let index = 0; index < lines.length; index += 1) {
    const match = signature.exec(lines[index]);
    if (!match) continue;
    let openLine = index;
    while (openLine < lines.length && !lines[openLine].includes("{")) openLine += 1;
    if (openLine === lines.length) continue;
    let depth = 0;
    let end = openLine;
    for (; end < lines.length; end += 1) {
      depth += (lines[end].match(/\{/g) || []).length;
      depth -= (lines[end].match(/\}/g) || []).length;
      if (depth === 0) break;
    }
    const params = match[3].split(",").map((item) => item.trim()).filter(Boolean).map((item) => {
      const parts = item.replace(/\bfinal\s+/, "").trim().split(/\s+/);
      return { type: parts.slice(0, -1).join(" "), name: parts.at(-1) };
    });
    methods.push({ visibility: match[1], name: match[2], params, start: index + 1, end: end + 1, lines });
  }
  return methods;
}

function containingMethod(methods, line) {
  return methods.find((method) => line >= method.start && line <= method.end);
}

function publicPathToSink(methods, sinkMethod, sinkVariable, sinkLine) {
  const visited = new Set();
  function walk(method, variable, suffix) {
    const key = `${method.name}:${variable}`;
    if (visited.has(key)) return null;
    visited.add(key);
    const ownParam = method.params.find((param) => param.name === variable);
    if (ownParam && method.visibility === "public" && /String/.test(ownParam.type)) {
      return { method, param: ownParam, flow: [method.start, ...suffix] };
    }
    const targetIndex = method.params.findIndex((param) => param.name === variable);
    if (targetIndex < 0) return null;
    for (const caller of methods) {
      for (let line = caller.start; line <= caller.end; line += 1) {
        const call = new RegExp(`\\b${method.name}\\s*\\(([^)]*)\\)`).exec(caller.lines[line - 1]);
        if (!call || line === method.start) continue;
        const args = call[1].split(",").map((value) => value.trim());
        const argument = args[targetIndex];
        if (!argument || !/^\w+$/.test(argument)) continue;
        const found = walk(caller, argument, [line, method.start, ...suffix]);
        if (found) return found;
      }
    }
    return null;
  }
  return walk(sinkMethod, sinkVariable, [sinkLine]);
}

function analyzeFastjson(files) {
  const imports = sourceLocation(files, (line) => /import\s+com\.alibaba\.fastjson\./.test(line));
  const sinks = [];
  const entryPoints = [];
  for (const [file, content] of Object.entries(files)) {
    if (!file.endsWith(".java")) continue;
    const methods = javaMethods(content);
    const sinkPattern = /\b(JSON|JSONObject)\.(parseObject|parseArray|parse)\s*\(\s*(\w+)/g;
    for (const match of content.matchAll(sinkPattern)) {
      const line = lineOf(content, match.index);
      const method = containingMethod(methods, line);
      const api = `${match[1]}.${match[2]}(String)`;
      sinks.push({ api, file, line, context: match[0].trim() });
      if (!method) continue;
      const pathResult = publicPathToSink(methods, method, match[3], line);
      if (pathResult) {
        entryPoints.push({
          name: `${pathResult.method.name}(${pathResult.method.params.map((item) => `${item.type} ${item.name}`).join(", ")})`,
          file,
          line: pathResult.method.start,
          sink_argument_controlled: true,
          external_exposure: "unknown",
          flow: [...new Set(pathResult.flow)],
          note: "public component API String parameter reaches a fastjson parsing sink; network exposure and exploitability are not asserted",
        });
      }
    }
  }
  return {
    sink_scan_complete: true,
    sinks,
    imports: imports.map(({ file, line }) => ({ file, lines: String(line) })),
    entry_points: entryPoints,
  };
}

function analyzeVelocity(files) {
  const usage = [];
  for (const item of sourceLocation(files, (line) => /\.getTemplate\s*\(/.test(line))) {
    usage.push({ api: "VelocityEngine.getTemplate(String)", file: item.file, line: item.line, context: item.text });
  }
  for (const item of sourceLocation(files, (line) => /\.init\s*\(/.test(line) && /velocity/i.test(line))) {
    usage.push({ api: "VelocityEngine.init(Properties)", file: item.file, line: item.line, context: item.text });
  }
  const templatePaths = [];
  for (const [file, content] of Object.entries(files)) {
    if (!file.endsWith(".java")) continue;
    for (const match of content.matchAll(/getTemplatePath\s*\(\s*\)\s*\{[\s\S]*?return\s+"([^"]+)"\s*;/g)) {
      templatePaths.push({ file, path: match[1], line: lineOf(content, match.index) });
    }
  }
  const resourcePaths = new Set(Object.keys(files)
    .filter((file) => file.startsWith("src/main/resources/"))
    .map((file) => `/${file.slice("src/main/resources/".length)}`));
  const evidence = { sink_scan_complete: true, usage };
  if (usage.some((item) => item.api === "VelocityEngine.getTemplate(String)") &&
      templatePaths.length > 0 && templatePaths.every((item) => resourcePaths.has(item.path))) {
    evidence.template_control = "internal";
    evidence.template_paths = templatePaths;
    evidence.note = "all detected getTemplatePath overrides return classpath resources present in the pinned commit";
  }
  return evidence;
}

export function analyzeSourceUsage(files) {
  const javaFiles = Object.keys(files).filter((file) => file.endsWith(".java"));
  if (javaFiles.length === 0) throw new Error("repository contains no Java source files");
  return {
    "com.alibaba:fastjson": analyzeFastjson(files),
    "org.apache.velocity:velocity": analyzeVelocity(files),
  };
}

function writeJson(file, value) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function safeAlertName(alert) {
  const id = alert.advisory.cve_id || alert.advisory.ghsa_id || `alert-${alert.alert.number}`;
  return `${id.replace(/[^A-Za-z0-9._-]/g, "_")}.json`;
}

function loadStaticAlerts(alertsPath, repoConfig) {
  const inputRoot = path.resolve(alertsPath, "..");
  const manifest = JSON.parse(readFileSync(path.join(inputRoot, "manifest.json"), "utf8"));
  const expectedRepo = `${repoConfig.owner}/${repoConfig.repo}`;
  if (manifest.repository !== expectedRepo) throw new Error(`alert input repository differs from ${expectedRepo}`);
  for (const [file, expected] of Object.entries(manifest.files || {})) {
    const content = readFileSync(path.join(alertsPath, file), "utf8").replace(/\r\n/g, "\n");
    const actual = createHash("sha256").update(content, "utf8").digest("hex");
    if (actual !== expected) throw new Error(`static alert input checksum mismatch: ${file}`);
  }
  const alerts = Object.keys(manifest.files || {})
    .filter((file) => file !== "index.json" && file.endsWith(".json"))
    .sort()
    .map((file) => JSON.parse(readFileSync(path.join(alertsPath, file), "utf8")));
  if (alerts.length === 0) throw new Error("static alert input is empty");
  for (const alert of alerts) {
    if (alert.schema_version !== "vuln-alert/1.0" ||
        `${alert.repo?.owner}/${alert.repo?.name}` !== expectedRepo ||
        !alert.advisory?.cve_id || !alert.vulnerability?.package) {
      throw new Error("invalid static alert input contract");
    }
  }
  const index = JSON.parse(readFileSync(path.join(alertsPath, "index.json"), "utf8"));
  const indexedFiles = new Set((index.alerts || []).map((item) => item.file));
  const actualFiles = new Set(alerts.map(safeAlertName));
  if (indexedFiles.size !== actualFiles.size || [...actualFiles].some((file) => !indexedFiles.has(file))) {
    throw new Error("static alert index differs from alert files");
  }
  return { alerts, manifest };
}

export async function buildSnapshot({ workspacePath, sourcesPath, alertsPath }) {
  const sources = parseYaml(readFileSync(sourcesPath, "utf8"));
  const repos = sources.repos || [];
  if (repos.length !== 1) throw new Error("minimal implementation requires exactly one configured repository");
  const repoConfig = repos[0];
  const collectedAt = new Date().toISOString();
  const { alerts, manifest: inputManifest } = loadStaticAlerts(alertsPath, repoConfig);
  const { commit, files, archiveUrl } = await fetchRepositoryFiles(repoConfig);
  const dependencies = parseMavenDependencies(files["pom.xml"]);
  const evidence = analyzeSourceUsage(files);
  const names = alerts.map(safeAlertName);
  if (new Set(names).size !== names.length) throw new Error("multiple alerts resolve to the same CVE/GHSA file name");

  const inputDigest = createHash("sha256").update(JSON.stringify(inputManifest.files)).digest("hex");
  const digest = createHash("sha256").update(inputDigest).update(commit).digest("hex").slice(0, 12);
  const timestamp = collectedAt.replace(/[-:.TZ]/g, "").slice(0, 14);
  const snapshotId = `${timestamp}-${commit.slice(0, 12)}-${digest}`;
  const runtimeRoot = path.resolve(workspacePath, "runtime");
  const snapshotsRoot = path.join(runtimeRoot, "snapshots");
  const finalDir = path.join(snapshotsRoot, snapshotId);
  const tempDir = path.join(snapshotsRoot, `.${snapshotId}.tmp`);
  mkdirSync(snapshotsRoot, { recursive: true });
  if (existsSync(finalDir) || existsSync(tempDir)) throw new Error(`snapshot already exists: ${snapshotId}`);
  mkdirSync(tempDir, { recursive: true });
  try {
    writeJson(path.join(tempDir, "input-manifest.json"), inputManifest);
    alerts.forEach((alert, index) => writeJson(path.join(tempDir, "alerts", names[index]), alert));
    writeJson(path.join(tempDir, "alerts", "index.json"), {
      schema_version: "vuln-alert/1.0",
      alerts: alerts.map((alert, index) => ({
        file: names[index], alert_number: alert.alert.number, state: alert.alert.state,
        cve_id: alert.advisory.cve_id, ghsa_id: alert.advisory.ghsa_id,
        package: alert.vulnerability.package, severity: alert.advisory.severity,
        repo: `${repoConfig.owner}/${repoConfig.repo}`,
      })),
    });
    for (const [file, content] of Object.entries(files)) {
      const target = path.join(tempDir, "source", ...file.split("/"));
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, content, "utf8");
    }
    const source = {
      url: `https://github.com/${repoConfig.owner}/${repoConfig.repo}`,
      ref: repoConfig.commit || repoConfig.branch,
      commit,
      collected_at: collectedAt,
      method: "public GitHub codeload archive plus bounded Maven and Java source analysis",
      authoritative: true,
    };
    writeJson(path.join(tempDir, "repo", "dependencies.json"), {
      schema_version: "repo-deps/2.0", repo: `${repoConfig.owner}/${repoConfig.repo}`,
      branch: repoConfig.branch || "", manifest: "pom.xml", source, dependencies,
    });
    writeJson(path.join(tempDir, "repo", "usage.json"), {
      schema_version: "repo-usage/2.0", repo: `${repoConfig.owner}/${repoConfig.repo}`,
      branch: repoConfig.branch || "", manifest: "pom.xml", source, evidence,
    });
    writeJson(path.join(tempDir, "provenance.json"), {
      schema_version: "vuln-reach-snapshot/1.0", snapshot_id: snapshotId, collected_at: collectedAt,
      repository: `${repoConfig.owner}/${repoConfig.repo}`, requested_ref: repoConfig.commit || repoConfig.branch,
      resolved_commit: commit, source_archive: archiveUrl,
      alert_input: "repository static input", alert_input_captured_at: inputManifest.captured_at,
      alert_input_sha256: inputDigest,
      alert_count: alerts.length, dependency_count: dependencies.length,
      source_file_count: Object.keys(files).length, java_file_count: Object.keys(files).filter((file) => file.endsWith(".java")).length,
      source_sha256: createHash("sha256").update(Object.entries(files).sort().map(([name, value]) => `${name}\0${value}`).join("\0")).digest("hex"),
    });
    renameSync(tempDir, finalDir);
    const pointerTmp = path.join(runtimeRoot, "current.json.tmp");
    writeJson(pointerTmp, { snapshot_id: snapshotId, relative_path: `snapshots/${snapshotId}` });
    renameSync(pointerTmp, path.join(runtimeRoot, "current.json"));
  } catch (error) {
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
  return {
    snapshotId,
    repository: `${repoConfig.owner}/${repoConfig.repo}`,
    resolvedCommit: commit,
    collectedAt,
    inputCapturedAt: inputManifest.captured_at,
    alertCount: alerts.length,
    dependencyCount: dependencies.length,
    sourceFileCount: Object.keys(files).length,
  };
}

export function resolveSnapshot(workspacePath, requestedId = "") {
  const runtimeRoot = path.resolve(workspacePath, "runtime");
  let snapshotId = String(requestedId || "").trim();
  if (!snapshotId) {
    const pointer = JSON.parse(readFileSync(path.join(runtimeRoot, "current.json"), "utf8"));
    snapshotId = String(pointer.snapshot_id || "");
  }
  if (!/^[0-9A-Za-z._-]+$/.test(snapshotId)) throw new Error("invalid snapshot id");
  const snapshotRoot = path.join(runtimeRoot, "snapshots", snapshotId);
  if (!existsSync(path.join(snapshotRoot, "provenance.json"))) throw new Error(`snapshot not found: ${snapshotId}`);
  return { snapshotId, snapshotRoot };
}
