# Unix installer copy source map

Reviewed 2026-11-03 against the checked-in [repository installer](../scripts/install.sh)
and [web installer](../apps/web/public/install.sh). This maps source files,
not a deployed website or a release asset. Line links are a snapshot; update
them and this comparison when either copy changes.

| Purpose | Repository copy | Web copy |
| --- | --- | --- |
| Initial staging and lock state | [lines 28–35](../scripts/install.sh#L28-L35) | [lines 28–35](../apps/web/public/install.sh#L28-L35) |
| Lock release, rollback, stage cleanup, and traps | [lines 90–139](../scripts/install.sh#L90-L139) | [lines 90–139](../apps/web/public/install.sh#L90-L139) |
| Lock acquisition and stale-lock handling | [lines 206–303](../scripts/install.sh#L206-L303) | [lines 206–303](../apps/web/public/install.sh#L206-L303) |
| Destination validation and lock acquisition | [lines 425–435](../scripts/install.sh#L425-L435) | [lines 425–435](../apps/web/public/install.sh#L425-L435) |
| Create private stage, download and candidate directories | [lines 437–443](../scripts/install.sh#L437-L443) | [lines 437–443](../apps/web/public/install.sh#L437-L443) |
| Download, verify, extract, and prepare candidate | [lines 445–499](../scripts/install.sh#L445-L499) | [lines 445–498](../apps/web/public/install.sh#L445-L498) |
| Backup, promote, and validate live installation | [lines 501–527](../scripts/install.sh#L501-L527) | [lines 500–526](../apps/web/public/install.sh#L500-L526) |
| PATH startup-file update function | [lines 305–403](../scripts/install.sh#L305-L403) | [lines 305–403](../apps/web/public/install.sh#L305-L403) |
| PATH check and update call | [lines 529–531](../scripts/install.sh#L529-L531) | [lines 528–530](../apps/web/public/install.sh#L528-L530) |

The complete files differ in two places. The repository copy pins
`CANDIDATE_TAG="v0.8.1"` for the next release candidate while the web copy
stays bound to the evidenced `v0.7.9` release. During extraction, the
repository copy uses `tar --no-same-owner` and explains why; the web copy
omits both the option and comment. When run as root, that option can change
the extracted files' ownership. Stage creation, the PATH function, and its
call site are byte-identical across copies; the web copy's line numbers after
the extraction point shift by one because it omits the comment line.

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
