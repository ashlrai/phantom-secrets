import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const workflowPath = ".github/workflows/publish-mcp-registry.yml";
const scriptPath = ".github/scripts/publish-mcp-registry.mjs";

function read(relativePath) {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

test("MCP registry publisher admits only this repository on release refs or default-branch dispatch", () => {
  const workflow = read(workflowPath);
  const jobsAt = workflow.indexOf("\njobs:\n");
  assert.ok(jobsAt > 0, "workflow has a jobs block");
  const top = workflow.slice(0, jobsAt);

  assert.match(top, /^permissions:\n  contents: read\n/m);
  assert.doesNotMatch(top, /id-token/);
  assert.equal(workflow.match(/id-token:\s*write/g)?.length, 1);
  assert.match(workflow, /permissions:\n {6}contents: read\n {6}id-token: write/);
  assert.match(workflow, /github\.repository == 'ashlrai\/phantom-secrets'/);
  assert.match(workflow, /github\.event_name == 'release' && startsWith\(github\.ref, 'refs\/tags\/v'\)/);
  assert.match(workflow, /github\.event_name == 'push' && startsWith\(github\.ref, 'refs\/tags\/v'\)/);
  assert.match(
    workflow,
    /github\.event_name == 'workflow_dispatch' && github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/,
  );
  assert.doesNotMatch(workflow, /ashlrai\/ashlr-hub|refs\/heads\/master/);
  assert.doesNotMatch(workflow, /secrets\./);
  assert.doesNotMatch(workflow, /pull_request_target:|self-hosted/);

  const uses = [...workflow.matchAll(/^ {8}uses: (\S+)@([0-9a-f]{40}) # /gm)];
  assert.deepEqual(
    uses.map((match) => match[1]),
    ["actions/checkout", "actions/setup-node"],
  );
  assert.match(workflow, /mcp-registry\/server\.json/);
  assert.match(workflow, /io\.github\.ashlrai\/phantom-secrets-mcp/);
  assert.match(workflow, /npm-mcp\/package\.json/);
});

test("publisher script reads this repo manifest and the same repository and ref guards", () => {
  const registry = JSON.parse(read("mcp-registry/server.json"));
  const npmMcp = JSON.parse(read("npm-mcp/package.json"));
  const script = read(scriptPath);
  const packageEntry = registry.packages.find((entry) => entry.identifier === "phantom-secrets-mcp");

  assert.equal(registry.name, "io.github.ashlrai/phantom-secrets-mcp");
  assert.equal(packageEntry.version, registry.version);
  assert.equal(npmMcp.name, "phantom-secrets-mcp");
  assert.equal(npmMcp.version, registry.version);
  assert.match(script, /export const SERVER = 'io\.github\.ashlrai\/phantom-secrets-mcp'/);
  assert.match(script, /export const PACKAGE = 'phantom-secrets-mcp'/);
  assert.match(script, /mcp-registry\/server\.json/);
  assert.match(script, /ashlrai\/phantom-secrets/);
  assert.match(script, /GITHUB_REPOSITORY !== 'ashlrai\/phantom-secrets'/);
  assert.match(script, /event === 'release' && releaseTag/);
  assert.match(script, /event === 'push' && releaseTag/);
  assert.match(script, /event === 'workflow_dispatch' && ref === 'refs\/heads\/main'/);
  assert.doesNotMatch(script, /ashlrai\/ashlr-hub|refs\/heads\/master/);
  assert.doesNotMatch(script, /secrets\./);
});
