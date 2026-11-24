export const PUBLIC_RELEASE_VERSION = "0.8.11";
export const PUBLIC_RELEASE_TAG = `v${PUBLIC_RELEASE_VERSION}`;
// Bound after reconciling the annotated tag, immutable GitHub release, all 19
// hosted assets, six native acceptance rows, attestations, and installer blobs.
export const PUBLIC_RELEASE_EVIDENCE_STATE = "bound";
export const PUBLIC_RELEASE_URL =
  `https://github.com/ashlrai/phantom-secrets/releases/tag/${PUBLIC_RELEASE_TAG}`;
export const PUBLIC_RELEASE_WORKFLOW_URL =
  "https://github.com/ashlrai/phantom-secrets/actions/runs/43947823026";
export const PUBLIC_RELEASE_TAG_OBJECT =
  "0d913358f49e0a3edb0d01d7063cc3660223c54c";
export const PUBLIC_RELEASE_SOURCE_COMMIT =
  "2c93e578d8d1a8097b32c1cd89292e339681b77c";
// SHA-256 of the exact raw installer blobs at PUBLIC_RELEASE_SOURCE_COMMIT.
// public-claims.test.cjs hashes the repository bytes so installer drift fails CI.
export const PUBLIC_RELEASE_UNIX_INSTALLER_SHA256 =
  "094525f7982caaf534c1a19b2581dbee69a4b766687b593d5adda3f0ba9464a4";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256 =
  "db11ec07928802b5d951824af1c4bc9dfed8c7775b466d781f403a449152323c";
export const PUBLIC_RELEASE_UNIX_INSTALLER_BLOB_OID =
  "b0a39d87a1d3d84263d64c380a986e6b55434293";
export const PUBLIC_RELEASE_WINDOWS_INSTALLER_BLOB_OID =
  "22ac5bea9144241eadf26f585c2ebdb9f72d0904";

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
