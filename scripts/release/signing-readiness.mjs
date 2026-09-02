const SHA256 = /^[0-9a-f]{64}$/;
const SOURCE_SHA = /^[0-9a-f]{40}$/;
const RELEASE_TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

const SIGNED_TARGETS = [
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "aarch64-pc-windows-msvc",
  "x86_64-pc-windows-msvc",
];
const BINARIES = ["phantom", "phantom-mcp"];

const REQUIRED_MACOS_SECRETS = {
  certificate_p12: "APPLE_DEVELOPER_ID_CERTIFICATE_P12",
  certificate_password: "APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD",
  notarytool_key_p8: "APPLE_NOTARYTOOL_KEY_P8",
};
const REQUIRED_MACOS_VARIABLES = {
  developer_id_application: "APPLE_DEVELOPER_ID_APPLICATION",
  team_id: "APPLE_TEAM_ID",
  notarytool_key_id: "APPLE_NOTARYTOOL_KEY_ID",
  notarytool_issuer_id: "APPLE_NOTARYTOOL_ISSUER_ID",
};
const REQUIRED_WINDOWS_VARIABLES = {
  azure_client_id: "AZURE_CLIENT_ID",
  azure_tenant_id: "AZURE_TENANT_ID",
  azure_subscription_id: "AZURE_SUBSCRIPTION_ID",
  endpoint: "AZURE_ARTIFACT_SIGNING_ENDPOINT",
  account_name: "AZURE_ARTIFACT_SIGNING_ACCOUNT_NAME",
  certificate_profile: "AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME",
};

function fail(message) {
  throw new Error(message);
}

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  object(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} must contain exactly: ${wanted.join(", ")}`);
  }
}

function exactLiteral(value, expected, label) {
  if (value !== expected) fail(`${label} must be ${JSON.stringify(expected)}`);
}

function nonempty(value, label) {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 256 ||
    /[\u0000-\u001f\u007f-\u009f]/.test(value)
  ) {
    fail(`${label} must be a bounded, single-line, non-empty string`);
  }
}

function safeTimestampAuthority(value, label) {
  nonempty(value, label);
  let url;
  try {
    url = new URL(value);
  } catch {
    fail(`${label} must be a valid timestamp URL`);
  }
  if (
    value !== "http://timestamp.acs.microsoft.com" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.origin === "null"
  ) {
    fail(`${label} must be the reviewed credential-free timestamp authority`);
  }
}

function pattern(value, expression, label) {
  if (typeof value !== "string" || !expression.test(value)) fail(`${label} is invalid`);
}

function timestamp(value, label) {
  const match = typeof value === "string" ? value.match(RFC3339) : null;
  if (!match) fail(`${label} is invalid`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = ""] = match;
  const [year, month, day, hour, minute, second] = [
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
  ].map(Number);
  if (hour > 23 || minute > 59 || second > 59) fail(`${label} is invalid`);
  const milliseconds = Number(fraction.padEnd(3, "0").slice(0, 3));
  const parsed = new Date(0);
  parsed.setUTCFullYear(year, month - 1, day);
  parsed.setUTCHours(hour, minute, second, milliseconds);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day ||
    parsed.getUTCHours() !== hour ||
    parsed.getUTCMinutes() !== minute ||
    parsed.getUTCSeconds() !== second
  ) {
    fail(`${label} is invalid`);
  }
  return parsed.getTime();
}

function exactMap(value, expected, label) {
  exactKeys(value, Object.keys(expected), label);
  for (const [key, expectedValue] of Object.entries(expected)) {
    exactLiteral(value[key], expectedValue, `${label}.${key}`);
  }
}

function validateDisabledPlatform(value, label) {
  exactKeys(value, ["state"], label);
  exactLiteral(value.state, "disabled", `${label}.state`);
}

function validateRequiredMacos(value) {
  exactKeys(value, ["state", "environment", "signer_subject", "team_id", "secrets", "variables"], "policy.macos");
  exactLiteral(value.state, "required", "policy.macos.state");
  exactLiteral(value.environment, "release-sign-macos", "policy.macos.environment");
  nonempty(value.signer_subject, "policy.macos.signer_subject");
  pattern(value.team_id, /^[A-Z0-9]{10}$/, "policy.macos.team_id");
  exactMap(value.secrets, REQUIRED_MACOS_SECRETS, "policy.macos.secrets");
  exactMap(value.variables, REQUIRED_MACOS_VARIABLES, "policy.macos.variables");
}

function validateRequiredWindows(value) {
  exactKeys(value, ["state", "environment", "runner", "signer_subject", "artifact_signing_account", "certificate_profile", "timestamp_authority", "signed_targets", "variables"], "policy.windows");
  exactLiteral(value.state, "required", "policy.windows.state");
  exactLiteral(value.environment, "release-sign-windows", "policy.windows.environment");
  exactLiteral(value.runner, "windows-latest", "policy.windows.runner");
  nonempty(value.signer_subject, "policy.windows.signer_subject");
  nonempty(value.artifact_signing_account, "policy.windows.artifact_signing_account");
  nonempty(value.certificate_profile, "policy.windows.certificate_profile");
  safeTimestampAuthority(value.timestamp_authority, "policy.windows.timestamp_authority");
  if (!Array.isArray(value.signed_targets)) fail("policy.windows.signed_targets must be an array");
  const expected = ["aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc"];
  if (JSON.stringify(value.signed_targets) !== JSON.stringify(expected)) {
    fail(`policy.windows.signed_targets must equal ${JSON.stringify(expected)}`);
  }
  exactMap(value.variables, REQUIRED_WINDOWS_VARIABLES, "policy.windows.variables");
}

export function validateSigningPolicy(policy) {
  exactKeys(policy, ["schema_version", "kind", "state", "macos", "windows"], "policy");
  exactLiteral(policy.schema_version, 1, "policy.schema_version");
  exactLiteral(policy.kind, "phantom_release_signing_policy", "policy.kind");
  if (policy.state !== "disabled" && policy.state !== "required") {
    fail('policy.state must be "disabled" or "required"');
  }

  if (policy.state === "disabled") {
    validateDisabledPlatform(policy.macos, "policy.macos");
    validateDisabledPlatform(policy.windows, "policy.windows");
  } else {
    validateRequiredMacos(policy.macos);
    validateRequiredWindows(policy.windows);
  }

  return { schema_version: 1, state: policy.state, signing_performed: false };
}

export function validateSigningInputs(inputs) {
  exactKeys(inputs, ["schema_version", "kind", "release_tag", "source_sha", "artifacts"], "inputs");
  exactLiteral(inputs.schema_version, 1, "inputs.schema_version");
  exactLiteral(inputs.kind, "phantom_unsigned_signing_inputs", "inputs.kind");
  pattern(inputs.release_tag, RELEASE_TAG, "inputs.release_tag");
  pattern(inputs.source_sha, SOURCE_SHA, "inputs.source_sha");
  if (!Array.isArray(inputs.artifacts)) fail("inputs.artifacts must be an array");

  const expectedPairs = SIGNED_TARGETS.flatMap((target) => BINARIES.map((binary) => `${target}/${binary}`));
  const actualPairs = [];
  for (const [index, artifact] of inputs.artifacts.entries()) {
    const label = `inputs.artifacts[${index}]`;
    exactKeys(artifact, ["target", "binary", "sha256"], label);
    if (!SIGNED_TARGETS.includes(artifact.target)) fail(`${label}.target is invalid`);
    if (!BINARIES.includes(artifact.binary)) fail(`${label}.binary is invalid`);
    pattern(artifact.sha256, SHA256, `${label}.sha256`);
    actualPairs.push(`${artifact.target}/${artifact.binary}`);
  }
  if (JSON.stringify(actualPairs) !== JSON.stringify(expectedPairs)) {
    fail("inputs.artifacts must contain the exact ordered signing input set");
  }
  return { release_tag: inputs.release_tag, source_sha: inputs.source_sha, artifact_count: 8 };
}

function validateBinaryReceipts(binaries, target, inputs, label) {
  if (!Array.isArray(binaries) || binaries.length !== BINARIES.length) {
    fail(`${label} must contain exactly two binary receipts`);
  }
  for (const [index, receipt] of binaries.entries()) {
    const binaryLabel = `${label}[${index}]`;
    exactKeys(receipt, ["name", "unsigned_sha256", "signed_sha256"], binaryLabel);
    exactLiteral(receipt.name, BINARIES[index], `${binaryLabel}.name`);
    pattern(receipt.unsigned_sha256, SHA256, `${binaryLabel}.unsigned_sha256`);
    pattern(receipt.signed_sha256, SHA256, `${binaryLabel}.signed_sha256`);
    const approved = inputs.artifacts.find((item) => item.target === target && item.binary === receipt.name);
    exactLiteral(receipt.unsigned_sha256, approved.sha256, `${binaryLabel}.unsigned_sha256`);
    if (receipt.signed_sha256 === receipt.unsigned_sha256) {
      fail(`${binaryLabel}.signed_sha256 must differ from the unsigned digest`);
    }
  }
}

function validateMacEvidence(evidence, verifiedAt, binaries, policy, label) {
  exactKeys(evidence, ["kind", "team_id", "hardened_runtime", "secure_timestamp_verified", "notarization_status", "submission_id", "submission_container_sha256", "submission_members", "submitted_at", "accepted_at", "stapling"], label);
  exactLiteral(evidence.kind, "macos", `${label}.kind`);
  exactLiteral(evidence.team_id, policy.macos.team_id, `${label}.team_id`);
  exactLiteral(evidence.hardened_runtime, true, `${label}.hardened_runtime`);
  exactLiteral(evidence.secure_timestamp_verified, true, `${label}.secure_timestamp_verified`);
  exactLiteral(evidence.notarization_status, "Accepted", `${label}.notarization_status`);
  pattern(evidence.submission_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i, `${label}.submission_id`);
  pattern(evidence.submission_container_sha256, SHA256, `${label}.submission_container_sha256`);
  if (!Array.isArray(evidence.submission_members) || evidence.submission_members.length !== BINARIES.length) {
    fail(`${label}.submission_members must contain exactly two members`);
  }
  for (const [index, member] of evidence.submission_members.entries()) {
    const memberLabel = `${label}.submission_members[${index}]`;
    exactKeys(member, ["name", "signed_sha256"], memberLabel);
    exactLiteral(member.name, BINARIES[index], `${memberLabel}.name`);
    exactLiteral(member.signed_sha256, binaries[index].signed_sha256, `${memberLabel}.signed_sha256`);
  }
  exactLiteral(evidence.stapling, "not_applicable_raw_binary", `${label}.stapling`);
  const submittedAt = timestamp(evidence.submitted_at, `${label}.submitted_at`);
  const acceptedAt = timestamp(evidence.accepted_at, `${label}.accepted_at`);
  if (submittedAt > acceptedAt || acceptedAt > verifiedAt) fail(`${label} notarization timestamps are out of order`);
}

function validateWindowsEvidence(evidence, verifiedAt, policy, label) {
  exactKeys(evidence, ["kind", "account_name", "certificate_profile", "timestamp_status", "timestamp_authority", "timestamped_at"], label);
  exactLiteral(evidence.kind, "windows", `${label}.kind`);
  exactLiteral(evidence.account_name, policy.windows.artifact_signing_account, `${label}.account_name`);
  exactLiteral(evidence.certificate_profile, policy.windows.certificate_profile, `${label}.certificate_profile`);
  exactLiteral(evidence.timestamp_status, "valid", `${label}.timestamp_status`);
  safeTimestampAuthority(evidence.timestamp_authority, `${label}.timestamp_authority`);
  exactLiteral(evidence.timestamp_authority, policy.windows.timestamp_authority, `${label}.timestamp_authority`);
  if (timestamp(evidence.timestamped_at, `${label}.timestamped_at`) > verifiedAt) {
    fail(`${label}.timestamped_at must not follow signature verification`);
  }
}

export function validateSigningReceipt(receipt, { policy, inputs }) {
  validateSigningPolicy(policy);
  validateSigningInputs(inputs);
  if (policy.state !== "required") fail("a disabled signing policy cannot validate a signing receipt");
  exactKeys(receipt, ["schema_version", "kind", "policy_state", "release_tag", "source_sha", "generated_at", "targets"], "receipt");
  exactLiteral(receipt.schema_version, 1, "receipt.schema_version");
  exactLiteral(receipt.kind, "phantom_signing_receipts", "receipt.kind");
  exactLiteral(receipt.policy_state, "required", "receipt.policy_state");
  exactLiteral(receipt.release_tag, inputs.release_tag, "receipt.release_tag");
  exactLiteral(receipt.source_sha, inputs.source_sha, "receipt.source_sha");
  const generatedAt = timestamp(receipt.generated_at, "receipt.generated_at");
  if (!Array.isArray(receipt.targets) || receipt.targets.length !== SIGNED_TARGETS.length) {
    fail("receipt.targets must contain the exact four signed targets");
  }

  for (const [index, targetReceipt] of receipt.targets.entries()) {
    const label = `receipt.targets[${index}]`;
    exactKeys(targetReceipt, ["target", "signer_subject", "signature_verified", "verified_at", "binaries", "evidence"], label);
    const target = SIGNED_TARGETS[index];
    exactLiteral(targetReceipt.target, target, `${label}.target`);
    exactLiteral(targetReceipt.signature_verified, true, `${label}.signature_verified`);
    const isMac = target.endsWith("apple-darwin");
    exactLiteral(targetReceipt.signer_subject, isMac ? policy.macos.signer_subject : policy.windows.signer_subject, `${label}.signer_subject`);
    const verifiedAt = timestamp(targetReceipt.verified_at, `${label}.verified_at`);
    if (verifiedAt > generatedAt) fail(`${label}.verified_at must not follow receipt.generated_at`);
    validateBinaryReceipts(targetReceipt.binaries, target, inputs, `${label}.binaries`);
    if (isMac) validateMacEvidence(targetReceipt.evidence, verifiedAt, targetReceipt.binaries, policy, `${label}.evidence`);
    else validateWindowsEvidence(targetReceipt.evidence, verifiedAt, policy, `${label}.evidence`);
  }

  return { release_tag: receipt.release_tag, source_sha: receipt.source_sha, signed_target_count: 4, signed_binary_count: 8 };
}

export const signingReadinessContract = Object.freeze({
  signedTargets: Object.freeze([...SIGNED_TARGETS]),
  binaries: Object.freeze([...BINARIES]),
});
