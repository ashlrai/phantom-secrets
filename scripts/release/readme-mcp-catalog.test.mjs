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
