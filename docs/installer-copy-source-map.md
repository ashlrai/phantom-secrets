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
| Destination validation and lock acquisition | [lines 431–441](../scripts/install.sh#L431-L441) | [lines 431–441](../apps/web/public/install.sh#L431-L441) |
| Create private stage, download and candidate directories | [lines 443–449](../scripts/install.sh#L443-L449) | [lines 443–449](../apps/web/public/install.sh#L443-L449) |
| Download, verify, extract, and prepare candidate | [lines 451–505](../scripts/install.sh#L451-L505) | [lines 451–504](../apps/web/public/install.sh#L451-L504) |
| Backup, promote, and validate live installation | [lines 507–533](../scripts/install.sh#L507-L533) | [lines 506–532](../apps/web/public/install.sh#L506-L532) |
| PATH startup-file update function | [lines 305–409](../scripts/install.sh#L305-L409) | [lines 305–409](../apps/web/public/install.sh#L305-L409) |
| PATH check and update call | [lines 535–537](../scripts/install.sh#L535-L537) | [lines 534–536](../apps/web/public/install.sh#L534-L536) |

The complete files differ in two places. The repository copy pins
`CANDIDATE_TAG="v0.8.1"` for the next release candidate while the web copy
stays bound to the evidenced `v0.7.9` release. During extraction, the
repository copy uses `tar --no-same-owner` and explains why; the web copy
omits both the option and comment. When run as root, that option can change
the extracted files' ownership. The PATH function and its call site are
byte-identical across copies; the call-site line numbers differ because the
repository copy's extraction comment adds one line.

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
