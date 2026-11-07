const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const webRoot = path.resolve(__dirname, "..");

test("agent console renders copy-paste commands and client setup", () => {
  const source = fs.readFileSync(path.join(webRoot, "src/components/landing/AgentQuickstart.tsx"), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: "AgentQuickstart.tsx",
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, require);
  const html = renderToStaticMarkup(React.createElement(exports.AgentQuickstart));
  for (const snippet of [
    "phantom status --json",
    "phantom list --json",
    "phantom setup --client claude",
    "phantom setup --client cursor",
    "phantom setup --client codex",
    "llms.txt",
    "llms-full.txt",
    "Claude",
    "Cursor",
    "Codex",
  ]) {
    assert.ok(html.includes(snippet), snippet);
  }
  assert.match(source, /\["mcp", "serve"\]/);
  assert.match(source, /\[mcp_servers\.phantom\]/);
  assert.equal([...html.matchAll(/role="tab"/g)].length, 5);
  assert.doesNotMatch(html, /sk-|ghp_|phc_/);
});
