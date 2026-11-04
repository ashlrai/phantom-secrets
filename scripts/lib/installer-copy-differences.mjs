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
    minus: ['CANDIDATE_TAG="v0.8.1"'],
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
