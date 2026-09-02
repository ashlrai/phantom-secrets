import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  validateSigningInputs,
  validateSigningPolicy,
  validateSigningReceipt,
} from "./signing-readiness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const fixtureRoot = join(repoRoot, "scripts/release/fixtures/signing");

function json(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function clone(value) {
  return structuredClone(value);
}

const disabledPolicy = json(join(repoRoot, ".github/release-signing-policy.json"));
const requiredPolicy = json(join(fixtureRoot, "required-policy.json"));
const inputs = json(join(fixtureRoot, "signing-inputs.json"));
const receipt = json(join(fixtureRoot, "valid-SIGNING-RECEIPTS.json"));
const receiptSchema = json(join(repoRoot, "scripts/release/signing-receipt.schema.json"));

test("committed policy is closed and explicitly disables every signing platform", () => {
  assert.deepEqual(validateSigningPolicy(disabledPolicy), {
    schema_version: 1,
    state: "disabled",
    signing_performed: false,
  });
  assert.deepEqual(disabledPolicy.macos, { state: "disabled" });
  assert.deepEqual(disabledPolicy.windows, { state: "disabled" });
});

test("policy accepts only complete disabled or complete required states", () => {
  assert.equal(validateSigningPolicy(requiredPolicy).state, "required");

  for (const state of ["optional", "auto", "enabled"]) {
    const candidate = clone(disabledPolicy);
    candidate.state = state;
    assert.throws(() => validateSigningPolicy(candidate), /disabled.*required/);
  }

  const mixed = clone(disabledPolicy);
  mixed.state = "required";
  assert.throws(() => validateSigningPolicy(mixed), /policy\.macos/);

  const missingSecret = clone(requiredPolicy);
  delete missingSecret.macos.secrets.notarytool_key_p8;
  assert.throws(() => validateSigningPolicy(missingSecret), /must contain exactly/);

  const missingVariable = clone(requiredPolicy);
  delete missingVariable.windows.variables.azure_client_id;
  assert.throws(() => validateSigningPolicy(missingVariable), /must contain exactly/);

  const unexpected = clone(requiredPolicy);
  unexpected.windows.mode = "automatic";
  assert.throws(() => validateSigningPolicy(unexpected), /must contain exactly/);

  const controlCharacter = clone(requiredPolicy);
  controlCharacter.macos.signer_subject += "\nAuthorization: example";
  assert.throws(() => validateSigningPolicy(controlCharacter), /bounded, single-line/);

  const invalidTeam = clone(requiredPolicy);
  invalidTeam.macos.team_id = "example123";
  assert.throws(() => validateSigningPolicy(invalidTeam), /team_id is invalid/);
});

test("signing inputs bind the exact ordered eight-binary set", () => {
  assert.deepEqual(validateSigningInputs(inputs), {
    release_tag: "v9.9.9",
    source_sha: "0123456789abcdef0123456789abcdef01234567",
    artifact_count: 8,
  });

  const missing = clone(inputs);
  missing.artifacts.pop();
  assert.throws(() => validateSigningInputs(missing), /exact ordered signing input set/);

  const reordered = clone(inputs);
  [reordered.artifacts[0], reordered.artifacts[1]] = [reordered.artifacts[1], reordered.artifacts[0]];
  assert.throws(() => validateSigningInputs(reordered), /exact ordered signing input set/);

  for (const releaseTag of [
    "v01.2.3",
    "v1.2.3-.",
    "v1.2.3-01",
    "v1.2.3-alpha..beta",
  ]) {
    const invalidTag = clone(inputs);
    invalidTag.release_tag = releaseTag;
    assert.throws(() => validateSigningInputs(invalidTag), /release_tag is invalid/);
  }

  const schemaTagPattern = new RegExp(receiptSchema.properties.release_tag.pattern);
  assert.match("v0.0.0", schemaTagPattern);
  assert.match("v1.2.3", schemaTagPattern);
  for (const releaseTag of ["v01.2.3", "v1.2.3-.", "v1.2.3-01", "v1.2.3-alpha..beta"]) {
    assert.doesNotMatch(releaseTag, schemaTagPattern);
  }
});

test("sanitized receipt fixture binds digests, identities, notarization, and timestamps", () => {
  assert.deepEqual(validateSigningReceipt(receipt, { policy: requiredPolicy, inputs }), {
    release_tag: "v9.9.9",
    source_sha: "0123456789abcdef0123456789abcdef01234567",
    signed_target_count: 4,
    signed_binary_count: 8,
  });
  assert.equal(receiptSchema.additionalProperties, false);
  assert.equal(receiptSchema.$defs.target_receipt.additionalProperties, false);
  assert.equal(receiptSchema.$defs.binary_receipt.additionalProperties, false);
  assert.equal(receiptSchema.properties.targets.minItems, 4);
  assert.equal(receiptSchema.properties.targets.maxItems, 4);
  assert.equal(receiptSchema.properties.targets.prefixItems.length, 4);
  assert.equal(receiptSchema.properties.targets.items, false);
});

test("receipt validation fails closed on mismatched immutable evidence", () => {
  const cases = [];

  const digest = clone(receipt);
  digest.targets[0].binaries[0].unsigned_sha256 = "f".repeat(64);
  cases.push([digest, /unsigned_sha256/]);

  const subject = clone(receipt);
  subject.targets[2].signer_subject = "CN=Different Organization";
  cases.push([subject, /signer_subject/]);

  const team = clone(receipt);
  team.targets[0].evidence.team_id = "DIFFERENT1";
  cases.push([team, /team_id/]);

  const notary = clone(receipt);
  notary.targets[0].evidence.notarization_status = "In Progress";
  cases.push([notary, /notarization_status/]);

  const notaryOrder = clone(receipt);
  notaryOrder.targets[1].evidence.accepted_at = "2030-01-01T00:07:00Z";
  cases.push([notaryOrder, /timestamps are out of order/]);

  const stapling = clone(receipt);
  stapling.targets[0].evidence.stapling = "stapled";
  cases.push([stapling, /stapling/]);

  const hardenedRuntime = clone(receipt);
  hardenedRuntime.targets[1].evidence.hardened_runtime = false;
  cases.push([hardenedRuntime, /hardened_runtime/]);

  const secureTimestamp = clone(receipt);
  secureTimestamp.targets[0].evidence.secure_timestamp_verified = false;
  cases.push([secureTimestamp, /secure_timestamp_verified/]);

  const submittedMember = clone(receipt);
  submittedMember.targets[1].evidence.submission_members[0].signed_sha256 = "f".repeat(64);
  cases.push([submittedMember, /submission_members.*signed_sha256/]);

  const timestamp = clone(receipt);
  timestamp.targets[3].evidence.timestamp_status = "unknown";
  cases.push([timestamp, /timestamp_status/]);

  const timestampOrder = clone(receipt);
  timestampOrder.targets[2].evidence.timestamped_at = "2030-01-01T00:12:00Z";
  cases.push([timestampOrder, /must not follow signature verification/]);

  const timestampAuthority = clone(receipt);
  timestampAuthority.targets[3].evidence.timestamp_authority =
    "http://user:password@timestamp.acs.microsoft.com/?token=example";
  cases.push([timestampAuthority, /reviewed credential-free timestamp authority/]);

  const impossibleCalendarDate = clone(receipt);
  impossibleCalendarDate.targets[0].evidence.accepted_at = "2030-02-31T00:04:00Z";
  cases.push([impossibleCalendarDate, /accepted_at is invalid/]);

  for (const [candidate, expectation] of cases) {
    assert.throws(() => validateSigningReceipt(candidate, { policy: requiredPolicy, inputs }), expectation);
  }
});

test("disabled policy cannot claim or validate signed evidence", () => {
  const claimingPolicy = clone(disabledPolicy);
  claimingPolicy.signing_performed = true;
  assert.throws(
    () => validateSigningPolicy(claimingPolicy),
    /must contain exactly/
  );
  assert.throws(
    () => validateSigningReceipt(receipt, { policy: disabledPolicy, inputs }),
    /disabled signing policy cannot validate a signing receipt/
  );
});

test("release workflows remain unsigned and preserve their existing authority graph", () => {
  const release = readFileSync(join(repoRoot, ".github/workflows/release.yml"), "utf8");
  const build = readFileSync(join(repoRoot, ".github/workflows/release-build.yml"), "utf8");
  const rehearsal = readFileSync(join(repoRoot, ".github/workflows/release-rehearsal.yml"), "utf8");
  const workflows = `${release}\n${build}\n${rehearsal}`;

  assert.match(release, /^on:\n  push:\n    tags:\n      - 'v\*'$/m);
  assert.deepEqual(
    [...release.matchAll(/^  ([a-z][a-z0-9-]+):$/gm)].map((match) => match[1]),
    ["push", "build-and-verify", "attest", "release"]
  );
  assert.deepEqual(
    [...build.matchAll(/^  ([a-z][a-z0-9_-]+):$/gm)].map((match) => match[1]),
    ["workflow_call", "verify-source", "build", "native-acceptance", "verify-artifacts"]
  );

  const idTokenWrites = workflows.match(/id-token:\s*write/g) ?? [];
  assert.equal(idTokenWrites.length, 1, "only GitHub artifact attestation may request OIDC");
  const attestStart = release.indexOf("\n  attest:\n");
  const releaseStart = release.indexOf("\n  release:\n", attestStart);
  const attest = release.slice(attestStart, releaseStart);
  assert.match(attest, /id-token: write/);
  assert.match(attest, /uses: actions\/attest@/);

  const forbiddenIdentifiers = [
    "release-sign-macos",
    "release-sign-windows",
    "APPLE_DEVELOPER_ID_CERTIFICATE_P12",
    "APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD",
    "APPLE_NOTARYTOOL_KEY_P8",
    "APPLE_DEVELOPER_ID_APPLICATION",
    "APPLE_TEAM_ID",
    "APPLE_NOTARYTOOL_KEY_ID",
    "APPLE_NOTARYTOOL_ISSUER_ID",
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_ARTIFACT_SIGNING_ENDPOINT",
    "AZURE_ARTIFACT_SIGNING_ACCOUNT_NAME",
    "AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME",
    "SIGNING-RECEIPTS.json",
    "release-signing-policy.json",
  ];
  for (const identifier of forbiddenIdentifiers) assert.doesNotMatch(workflows, new RegExp(identifier));

  assert.doesNotMatch(
    workflows,
    /\b(?:codesign|notarytool|signtool)\b|azure\/artifact-signing|azure-artifact-signing|apple-actions|trusted-signing/i
  );
});
