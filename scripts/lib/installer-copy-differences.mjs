import assert from "node:assert/strict";

// Shared inventory of the two checked-in Unix installer copies and their
// reviewed differences; docs/installer-copy-comparison.md carries the prose
// record. Each entry pins one changed region exactly: `minus` lines exist
// only in the repository copy and `plus` lines replace them in the web copy.
// Any drift beyond this list — an added, removed, or reworded line — fails
// the copy checks.

export const repositoryCopy = "scripts/install.sh";
export const webCopy = "apps/web/public/install.sh";
export const installerCopies = [repositoryCopy, webCopy];

export const approvedDifferences = [
  {
    name: "the repository copy targets the next candidate tag while the web copy stays bound to the evidenced release",
    minus: ['CANDIDATE_TAG="v0.8.6"'],
    plus: ['CANDIDATE_TAG="v0.7.9"'],
  },
  {
    name: "the repository copy extracts the release archive with tar --no-same-owner",
    minus: [
      "# --no-same-owner: as root, tar would otherwise keep the release runner's uid on the installed binaries.",
      'tar --no-same-owner -xzf "$archive_path" -C "$candidate_dir" || die "could not extract release archive"',
    ],
    plus: [
      'tar -xzf "$archive_path" -C "$candidate_dir" || die "could not extract release archive"',
    ],
  },
];

// Latin-1 is a reversible byte mapping here, not a text encoding assumption:
// decoding UTF-8 would collapse distinct invalid bytes into the same U+FFFD.
export function normalizeInstallerCopy(source, side) {
  assert.ok(Buffer.isBuffer(source), "installer parity requires raw bytes");
  assert.ok(side === "minus" || side === "plus", "unknown installer copy side");
  let output = source.toString("latin1");
  const marker = "# @@ reviewed-difference:";
  assert.ok(!output.includes(marker), "installer contains a reserved parity marker");
  for (const entry of approvedDifferences) {
    const region = entry[side].join("\n");
    const index = output.indexOf(region);
    assert.ok(
      index >= 0 && output.indexOf(region, index + 1) < 0,
      `"${entry.name}" must appear exactly once in ${side === "minus" ? repositoryCopy : webCopy}`,
    );
    assert.ok(
      (index === 0 || output[index - 1] === "\n") &&
        (index + region.length === output.length || output[index + region.length] === "\n"),
      `"${entry.name}" must occupy complete lines`,
    );
    output = output.replace(region, `${marker} ${entry.name} @@`);
  }
  return Buffer.from(output, "latin1");
}

export function assertInstallerCopyParity(repository, web) {
  assert.ok(
    normalizeInstallerCopy(repository, "minus").equals(normalizeInstallerCopy(web, "plus")),
    `${repositoryCopy} and ${webCopy} diverge outside the reviewed differences; ` +
      "re-review the copies and update scripts/lib/installer-copy-differences.mjs",
  );
}
