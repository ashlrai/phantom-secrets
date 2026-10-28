import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { extractReadmeMcpToolNames } from "./readme-mcp-catalog.mjs";

const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");

test("README MCP catalog extraction is identical for LF and CRLF checkouts", () => {
  const lfNames = extractReadmeMcpToolNames(readme.replace(/\r\n?/g, "\n"));
  const crlfNames = extractReadmeMcpToolNames(
    readme.replace(/\r\n?/g, "\n").replace(/\n/g, "\r\n")
  );

  assert.equal(lfNames.length, 54);
  assert.deepEqual(crlfNames, lfNames);
});

test("README MCP catalog extraction fails closed when boundaries are absent", () => {
  assert.throws(
    () => extractReadmeMcpToolNames("# Phantom\r\n\r\nNo catalog here\r\n"),
    /README MCP catalog boundaries are missing/
  );
});

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
const source = read("crates/phantom-mcp/src/server.rs");
// Match registrations, not arbitrary references or helper methods. Fail closed
// if registration syntax changes so a parser update accompanies that change.
const registrations = [...source.matchAll(/#\[tool\([\s\S]*?\)\]\s*(?:pub\s+)?(?:async\s+)?fn\s+(phantom_[a-z_]+)\s*\(/g)]
  .map((match) => match[1]);
const sourceNames = [...registrations].sort();
const documentedNames = (text) => [...text.matchAll(/`(phantom_[a-z_]+)`/g)]
  .map((match) => match[1]);

test("MCP catalogs match every Rust tool registration exactly", () => {
  assert.ok(sourceNames.length > 0, "no Rust registrations parsed");
  assert.equal(registrations.length, (source.match(/#\[tool\(/g) ?? []).length);
  assert.equal(new Set(sourceNames).size, sourceNames.length, "duplicate registration");
  assert.deepEqual(extractReadmeMcpToolNames(readme), sourceNames);
  const registry = JSON.parse(read("mcp-registry/server.json"));
  assert.deepEqual(registry.tools.map((tool) => tool.name).sort(), sourceNames);
  const listing = read("mcp-registry/README.md").split("<!-- tool-catalog:start -->")[1]
    ?.split("<!-- tool-catalog:end -->")[0];
  assert.ok(listing, "registry catalog boundaries missing");
  assert.deepEqual(documentedNames(listing).sort(), sourceNames);
});

for (const file of ["AGENTS.md", "CLAUDE.md"]) {
  test(`${file} references only registered MCP tools`, () => {
    const names = documentedNames(read(file));
    assert.ok(names.length > 0, "no documented tools found");
    for (const name of names) assert.ok(sourceNames.includes(name), `unknown tool: ${name}`);
  });
}

test("documented setup clients match the source enum", () => {
  const setup = read("crates/phantom-cli/src/commands/setup.rs");
  const body = setup.split("pub enum Client {")[1]?.split("\n}")[0];
  assert.ok(body, "setup Client enum missing");
  const clients = [...body.matchAll(/(?:#\[value\(name = "([a-z-]+)"[^\n]*\)\]\s*)?^    ([A-Z][A-Za-z]+),/gm)]
    .map((match) => match[1] ?? match[2].toLowerCase()).sort();
  assert.ok(clients.length > 0, "no setup clients parsed");
  for (const file of ["README.md", "AGENTS.md"]) {
    const examples = [...read(file).matchAll(/^phantom setup --client ([a-z]+)\s+#/gm)]
      .map((match) => match[1]);
    assert.deepEqual([...new Set(examples)].sort(), clients, `${file} setup examples drifted`);
  }
});
