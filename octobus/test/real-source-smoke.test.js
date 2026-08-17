import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { analyzeSourceUsage, parseMavenDependencies } from "../lib/snapshot.js";

const checkout = process.env.VULN_REACH_REAL_REPO || "";

test("optional pinned-repository source smoke", { skip: !checkout }, () => {
  const files = {};
  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === ".git") continue;
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(file);
      else if (file.endsWith("pom.xml") || [".java", ".vm", ".properties"].some((suffix) => file.endsWith(suffix))) {
        files[path.relative(checkout, file).replaceAll("\\", "/")] = fs.readFileSync(file, "utf8");
      }
    }
  }
  walk(checkout);
  const dependencies = parseMavenDependencies(files["pom.xml"]);
  const evidence = analyzeSourceUsage(files);
  assert.equal(dependencies.find((item) => item.package === "com.alibaba:fastjson")?.version, "1.2.31");
  assert.equal(evidence["com.alibaba:fastjson"].sinks[0].file, "src/main/java/com/prism/pom/api/DependencyTreeUtil.java");
  assert.equal(evidence["com.alibaba:fastjson"].sinks[0].line, 114);
  assert.equal(evidence["com.alibaba:fastjson"].entry_points[0].line, 16);
  assert.equal(evidence["com.alibaba:fastjson"].entry_points[0].sink_argument_controlled, true);
  assert.equal(evidence["org.apache.velocity:velocity"].usage[0].line, 133);
  assert.equal(evidence["org.apache.velocity:velocity"].template_control, undefined);
});
