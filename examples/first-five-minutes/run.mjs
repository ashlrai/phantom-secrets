#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const exampleRoot = dirname(fileURLToPath(import.meta.url));
const placeholder = "<enter-in-trusted-terminal>";

function requireContract(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function parseEnvironment(source) {
  const entries = source
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => {
      const separator = line.indexOf("=");
      requireContract(separator > 0, `invalid environment entry: ${line}`);
      const name = line.slice(0, separator);
      requireContract(/^[A-Z][A-Z0-9_]*$/u.test(name), `invalid environment key: ${name}`);
      return [name, line.slice(separator + 1)];
    });

  const seen = new Set();
  for (const [name] of entries) {
    requireContract(!seen.has(name), `duplicate environment key: ${name}`);
    seen.add(name);
  }

  return entries;
}

function main() {
  const environmentSource = readFileSync(join(exampleRoot, ".env.example"), "utf8");
  const policySource = readFileSync(join(exampleRoot, "policy.json"), "utf8");
  const environmentEntries = parseEnvironment(environmentSource);
  const environment = new Map(environmentEntries);
  const policy = JSON.parse(policySource);
  const expectedEnvironmentKeys = ["BILLING_API_TOKEN", "PUBLIC_API_BASE"];
  const expectedPolicyKeys = [
    "agent_may_read_secret_values",
    "mutations",
    "network",
    "provider_acceptance",
    "secret_names",
    "task",
  ];

  requireContract(
    JSON.stringify([...environment.keys()].sort()) ===
      JSON.stringify([...expectedEnvironmentKeys].sort()),
    "the example environment schema changed"
  );
  requireContract(
    environment.get("BILLING_API_TOKEN") === placeholder,
    "the secret must remain a trusted-terminal placeholder"
  );
  requireContract(
    environment.get("PUBLIC_API_BASE") === "https://api.example.invalid",
    "public configuration must use the reserved offline example domain"
  );
  requireContract(
    policy !== null && !Array.isArray(policy) && typeof policy === "object",
    "the policy must be an object"
  );
  requireContract(
    JSON.stringify(Object.keys(policy).sort()) === JSON.stringify(expectedPolicyKeys),
    "the policy schema changed"
  );
  requireContract(
    policySource.replace(/\r\n/gu, "\n") === `${JSON.stringify(policy, null, 2)}\n`,
    "the policy must use canonical unique-key JSON"
  );
  requireContract(
    policy.task === "Inspect billing integration configuration",
    "the policy task changed"
  );
  requireContract(
    JSON.stringify(policy.secret_names) === JSON.stringify(["BILLING_API_TOKEN"]),
    "the policy secret-name inventory does not match the environment"
  );
  requireContract(policy.agent_may_read_secret_values === false, "secret-value access must be denied");
  requireContract(policy.network === "denied", "network access must be denied");
  requireContract(policy.mutations === "denied", "mutations must be denied");
  requireContract(
    policy.provider_acceptance === "not-tested",
    "provider acceptance must remain explicitly untested"
  );

  const output = [
    "Phantom first-five-minutes walkthrough",
    "PASS environment contract is value-free",
    `  agent-visible secret names: ${policy.secret_names.join(", ")}`,
    "  agent-visible secret values: 0",
    "PASS delegation policy is closed",
    "  network requests: 0",
    "  mutations: 0",
    "  persisted token mappings: 0",
    "LIMIT provider acceptance: not claimed",
    "NEXT use Phantom's trusted-terminal quickstart for a real project",
  ];

  process.stdout.write(`${output.join("\n")}\n`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`ERROR ${message}\n`);
  process.exitCode = 1;
}
