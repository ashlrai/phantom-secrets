#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Consume `git ls-files -z`, not the working tree: npm ci may already have
// replaced a tracked dependency symlink with an ignored directory.
export function assertDependencyIndexClean(index) {
  if (index !== "" && !index.endsWith("\0")) {
    throw new Error("expected a NUL-terminated Git index listing");
  }
  const paths = index === "" ? [] : index.slice(0, -1).split("\0");
  if (paths.some((path) => path === "")) {
    throw new Error("Git index listing contains an empty path");
  }
  if (paths.some((path) => path.split("/").includes("node_modules"))) {
    throw new Error("generated node_modules paths must not be tracked");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assertDependencyIndexClean(readFileSync(0, "utf8"));
  console.log("dependency index is clean");
}
