// Package-local release identity, validated before any cache, download or execution.
const VERSION = require("../package.json").version;

const SEMVER_SOURCE =
  "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)" +
  "(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?" +
  "(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?";

if (typeof VERSION !== "string" || new RegExp(`^${SEMVER_SOURCE}$`).exec(VERSION)?.[0] !== VERSION) {
  throw new Error("invalid packaged Phantom version");
}

module.exports = Object.freeze({ VERSION, SEMVER_SOURCE });
