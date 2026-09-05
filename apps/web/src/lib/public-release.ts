export const PUBLIC_RELEASE_VERSION = "0.7.8";
export const PUBLIC_RELEASE_TAG = `v${PUBLIC_RELEASE_VERSION}`;
// Bound after reconciling the annotated tag, immutable GitHub release, all 19
// hosted assets, six native acceptance rows, attestations, and installer blobs.
export const PUBLIC_RELEASE_EVIDENCE_STATE = "bound";
export const PUBLIC_RELEASE_URL =
  `https://github.com/ashlrai/phantom-secrets/releases/tag/${PUBLIC_RELEASE_TAG}`;
export const PUBLIC_RELEASE_WORKFLOW_URL =
  "https://github.com/ashlrai/phantom-secrets/actions/runs/33952398697";
export const PUBLIC_RELEASE_TAG_OBJECT =
  "2dac7ce68a3f7a831cd243bf869074373b4858e3";
export const PUBLIC_RELEASE_SOURCE_COMMIT =
  "f065b13462f9eaf27e0443f8911f021575b7c409";
// SHA-256 of the exact raw installer blobs at PUBLIC_RELEASE_SOURCE_COMMIT.
// public-claims.test.cjs hashes the repository bytes so installer drift fails CI.
export const PUBLIC_RELEASE_UNIX_INSTALLER_SHA256 =
  "13aa95ec6aa8f06a220b6a47028dca2b486f29f1ba4efceca119d543c5e52779";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256 =
  "cc12d8626b595d82c3f639fa5ffc3187ef6960c89af78a37299497a2e7209e64";
export const PUBLIC_RELEASE_UNIX_INSTALLER_BLOB_OID =
  "2491a28e37d602d9ada1e27a9f47a20bce388415";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_BLOB_OID =
  "e8166dc40ebbc73d9b0e2ef4dbdf238676775e5d";

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
