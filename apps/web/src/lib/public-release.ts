export const PUBLIC_RELEASE_VERSION = "0.7.9";
export const PUBLIC_RELEASE_TAG = `v${PUBLIC_RELEASE_VERSION}`;
// Bound after reconciling the annotated tag, immutable GitHub release, all 19
// hosted assets, six native acceptance rows, attestations, and installer blobs.
export const PUBLIC_RELEASE_EVIDENCE_STATE = "bound";
export const PUBLIC_RELEASE_URL =
  `https://github.com/ashlrai/phantom-secrets/releases/tag/${PUBLIC_RELEASE_TAG}`;
export const PUBLIC_RELEASE_WORKFLOW_URL =
  "https://github.com/ashlrai/phantom-secrets/actions/runs/34153902556";
export const PUBLIC_RELEASE_TAG_OBJECT =
  "d047d0b8a4c64005590a6ab0c42ad9af6c3abb13";
export const PUBLIC_RELEASE_SOURCE_COMMIT =
  "7a51ce512ec4aee12cc29ff859036af63fbe93db";
// SHA-256 of the exact raw installer blobs at PUBLIC_RELEASE_SOURCE_COMMIT.
// public-claims.test.cjs hashes the repository bytes so installer drift fails CI.
export const PUBLIC_RELEASE_UNIX_INSTALLER_SHA256 =
  "b317eb9b3aa07532c6d8f21eda354bd5fb89dea94f9d0d06d3e7bb291cd136ca";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256 =
  "33e30a556283871ed8e9c1f3bd8a8c079f94f88dc2383d8c1d6667f14caca8f5";
export const PUBLIC_RELEASE_UNIX_INSTALLER_BLOB_OID =
  "783625e6daaa726475f420114a7fdf90a6448b64";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_BLOB_OID =
  "f7cb7bf5186c2339196d55041d4f99279700b0d8";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const SHA1_PATTERN = /^[a-f0-9]{40}$/;
const WORKFLOW_URL_PATTERN =
  /^https:\/\/github\.com\/ashlrai\/phantom-secrets\/actions\/runs\/\d+$/;

if (
  String(PUBLIC_RELEASE_EVIDENCE_STATE) !== "bound" ||
  !WORKFLOW_URL_PATTERN.test(PUBLIC_RELEASE_WORKFLOW_URL) ||
  !SHA1_PATTERN.test(PUBLIC_RELEASE_TAG_OBJECT) ||
  !SHA1_PATTERN.test(PUBLIC_RELEASE_SOURCE_COMMIT) ||
  !SHA1_PATTERN.test(PUBLIC_RELEASE_UNIX_INSTALLER_BLOB_OID) ||
  !SHA1_PATTERN.test(PUBLIC_RELEASE_WINDOWS_INSTALLER_BLOB_OID) ||
  !SHA256_PATTERN.test(PUBLIC_RELEASE_UNIX_INSTALLER_SHA256) ||
  !SHA256_PATTERN.test(PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256)
) {
  throw new Error(
    `Public ${PUBLIC_RELEASE_TAG} evidence is not bound to the immutable release`,
  );
}

export const PUBLIC_RELEASE_RECEIPT =
  `phantom ${PUBLIC_RELEASE_VERSION}\nphantom-mcp ${PUBLIC_RELEASE_VERSION}`;
