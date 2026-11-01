# Unix installer copy source map

Reviewed 2026-10-31 against the checked-in [repository installer](../scripts/install.sh)
and [web installer](../apps/web/public/install.sh). This maps source files,
not a deployed website or a release asset. Line links are a snapshot; update
them and this comparison when either copy changes.

| Purpose | Repository copy | Web copy |
| --- | --- | --- |
| Initial staging and lock state | [lines 28–35](../scripts/install.sh#L28-L35) | [lines 28–35](../apps/web/public/install.sh#L28-L35) |
| Lock release, rollback, stage cleanup, and traps | [lines 90–139](../scripts/install.sh#L90-L139) | [lines 90–139](../apps/web/public/install.sh#L90-L139) |
| Lock acquisition and stale-lock handling | [lines 206–303](../scripts/install.sh#L206-L303) | [lines 206–303](../apps/web/public/install.sh#L206-L303) |
| Destination validation and lock acquisition | [lines 425–435](../scripts/install.sh#L425-L435) | [lines 425–435](../apps/web/public/install.sh#L425-L435) |
| Create private stage, download and candidate directories | [lines 437–443](../scripts/install.sh#L437-L443) | [lines 437–441](../apps/web/public/install.sh#L437-L441) |
| Download, verify, extract, and prepare candidate | [lines 445–499](../scripts/install.sh#L445-L499) | [lines 443–496](../apps/web/public/install.sh#L443-L496) |
| Backup, promote, and validate live installation | [lines 501–527](../scripts/install.sh#L501-L527) | [lines 498–524](../apps/web/public/install.sh#L498-L524) |
| PATH startup-file update function | [lines 305–403](../scripts/install.sh#L305-L403) | [lines 305–403](../apps/web/public/install.sh#L305-L403) |
| PATH check and update call | [lines 529–531](../scripts/install.sh#L529-L531) | [lines 526–528](../apps/web/public/install.sh#L526-L528) |

The complete files differ in two places. In stage creation, the repository
copy adds explicit `die` messages for `mktemp`, `chmod`, and `mkdir` failures;
the web copy relies on Bash's `set -e` and the commands' diagnostics. During
extraction, the repository copy uses `tar --no-same-owner` and explains why;
the web copy omits both the option and comment. When run as root, that option
can change the extracted files' ownership. The PATH function and its call
site are byte-identical across copies; the call-site line numbers differ
because of the preceding staging changes.

Both installers stage beside the resolved installation directory, check lock
ownership around promotion, and attempt rollback and cleanup on ordinary
failure. PATH setup occurs after promotion, uses separate temporary files, and
warns on failure instead of rolling back the install. See the detailed
[staging review](installer-staging.md), [PATH review](installer-path-review.md),
and [copy comparison](installer-copy-comparison.md) for behavior and limits.
The web copy is tied to separately reviewed release evidence; this map does
not authorize replacing it with the repository copy.

Run `node --test scripts/installer-copy-source-map.test.mjs` to check the
linked ranges, the mapped PATH equality, and the documented staging differences.
