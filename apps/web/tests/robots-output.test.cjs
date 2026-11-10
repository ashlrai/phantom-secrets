const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const { resolveRobots } = require("next/dist/build/webpack/loaders/metadata/resolve-route-data.js");

const filename = path.resolve(__dirname, "../src/app/robots.ts");
const compiled = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const route = { exports: {} };
new Function("exports", "module", compiled)(route.exports, route);

test("robots metadata allows crawlers, excludes the API, and identifies the sitemap", () => {
  assert.deepEqual(route.exports.default(), {
    rules: { userAgent: "*", allow: "/", disallow: ["/api/"] },
    sitemap: "https://phm.dev/sitemap.xml",
    host: "https://phm.dev",
  });
});

test("Next serializes the crawler rules and absolute sitemap location", () => {
  const output = resolveRobots(route.exports.default());
  assert.deepEqual(output.trim().split(/\r?\n/), [
    "User-Agent: *",
    "Allow: /",
    "Disallow: /api/",
    "",
    "Host: https://phm.dev",
    "Sitemap: https://phm.dev/sitemap.xml",
  ]);
});
