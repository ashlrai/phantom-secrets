export const PUBLIC_RELEASE_VERSION = "0.8.7";
export const PUBLIC_RELEASE_TAG = `v${PUBLIC_RELEASE_VERSION}`;
// Bound after reconciling the annotated tag, immutable GitHub release, all 19
// hosted assets, six native acceptance rows, attestations, and installer blobs.
export const PUBLIC_RELEASE_EVIDENCE_STATE = "bound";
export const PUBLIC_RELEASE_URL =
  `https://github.com/ashlrai/phantom-secrets/releases/tag/${PUBLIC_RELEASE_TAG}`;
export const PUBLIC_RELEASE_WORKFLOW_URL =
  "https://github.com/ashlrai/phantom-secrets/actions/runs/42262099223";
export const PUBLIC_RELEASE_TAG_OBJECT =
  "60f78437316cdfbd5c5aef43f7a1947a9e35b11f";
export const PUBLIC_RELEASE_SOURCE_COMMIT =
  "a6a0413991c0bd7f3d6601f467c0b5770d0dce0c";
// SHA-256 of the exact raw installer blobs at PUBLIC_RELEASE_SOURCE_COMMIT.
// public-claims.test.cjs hashes the repository bytes so installer drift fails CI.
export const PUBLIC_RELEASE_UNIX_INSTALLER_SHA256 =
  "44ab25b1a5b99d7a1a3bb484ea17b323f89a47e43092ca4de4903a9ede6ba72e";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256 =
  "7b8549e6cd0d213b7e4e12ace3513f964952d460f1717602d16022f6411b4b5e";
export const PUBLIC_RELEASE_UNIX_INSTALLER_BLOB_OID =
  "018ca537e0b9fe80f109f154c38456d9c71f7f95";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_BLOB_OID =
  "6b52d955f5fa6bc33048d0ec6bdf1fb0a3cc6f59";

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
