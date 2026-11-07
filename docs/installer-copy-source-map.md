# Unix installer copy source map

Reviewed 2026-11-06 against the checked-in [repository installer](../scripts/install.sh)
and [web installer](../apps/web/public/install.sh). This maps source files,
not a deployed website or a release asset. Line links are a snapshot; update
them and this comparison when either copy changes.

| Purpose | Repository copy | Web copy |
| --- | --- | --- |
| Initial staging and lock state | [lines 28–35](../scripts/install.sh#L28-L35) | [lines 28–35](../apps/web/public/install.sh#L28-L35) |
| Lock release, rollback, stage cleanup, and traps | [lines 90–139](../scripts/install.sh#L90-L139) | [lines 90–139](../apps/web/public/install.sh#L90-L139) |
| Lock acquisition and stale-lock handling | [lines 206–303](../scripts/install.sh#L206-L303) | [lines 206–303](../apps/web/public/install.sh#L206-L303) |
| Destination validation and lock acquisition | [lines 450–460](../scripts/install.sh#L450-L460) | [lines 450–460](../apps/web/public/install.sh#L450-L460) |
| Create private stage, download and candidate directories | [lines 462–468](../scripts/install.sh#L462-L468) | [lines 462–468](../apps/web/public/install.sh#L462-L468) |
| Download, verify, extract, and prepare candidate | [lines 470–524](../scripts/install.sh#L470-L524) | [lines 470–524](../apps/web/public/install.sh#L470-L524) |
| Backup, promote, and validate live installation | [lines 526–552](../scripts/install.sh#L526-L552) | [lines 526–552](../apps/web/public/install.sh#L526-L552) |
| PATH startup-file update function | [lines 305–428](../scripts/install.sh#L305-L428) | [lines 305–428](../apps/web/public/install.sh#L305-L428) |
| PATH check and update call | [lines 554–556](../scripts/install.sh#L554-L556) | [lines 554–556](../apps/web/public/install.sh#L554-L556) |

The complete files match. Both copies pin `CANDIDATE_TAG="v0.8.7"`
for the evidenced release. Both copies extract the
release archive with `tar --no-same-owner` and carry the same explanatory
comment, so a root-run install never keeps the release runner's uid on the
installed binaries. Stage creation, extraction, the PATH function, and its
call site are byte-identical across copies, and every line number below is
identical in both files.

Both installers stage beside the resolved installation directory, check lock
ownership around promotion, and attempt rollback and cleanup on ordinary
failure. PATH setup occurs after promotion, uses separate temporary files, and
warns on failure instead of rolling back the install. See the detailed
[staging review](installer-staging.md), [PATH review](installer-path-review.md),
and [copy comparison](installer-copy-comparison.md) for behavior and limits.
The web copy is tied to separately reviewed release evidence; this map does
not authorize replacing it with the repository copy.

Run `node --test scripts/installer-copy-source-map.test.mjs` to check the
linked ranges, the mapped PATH equality, and the documented differences.
