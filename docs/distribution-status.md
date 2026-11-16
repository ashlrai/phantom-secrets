# Distribution status

Package publication and native acceptance are separate evidence. The source
candidate identity for this tree is v0.8.10; it is not a publication claim. On
November 6, 2026, the exact
[v0.8.7 release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.8.7)
was published at 18:17:06 UTC and qualified from source
`a6a0413991c0bd7f3d6601f467c0b5770d0dce0c`; annotated tag object
`60f78437316cdfbd5c5aef43f7a1947a9e35b11f` binds that source:
[full CI](https://github.com/ashlrai/phantom-secrets/actions/runs/42262122760)
and the [release workflow](https://github.com/ashlrai/phantom-secrets/actions/runs/42262099223)
completed, all six native archive targets passed acceptance, and the 19 public
assets were verified. Both exact npm `0.8.7` packages had verified registry
signatures and source provenance. This review was recorded on November 6.
This receipt binds that immutable release;
later source changes and local default aliases are separate observations.
The dated `0.7.9` records below remain historical, and an unpinned command can
change independently.

The repository's October 12, 2026 README snapshot records:

| Channel | Recorded version | Evidence limit |
| --- | --- | --- |
| Homebrew tap | `v0.7.9` | Independently published formula, not an automatic result of the GitHub release |
| npm `phantom-secrets` `latest` | `0.7.9` | A default tag does not prove six-target npm-channel acceptance |
| npm `phantom-secrets-mcp` `latest` | `0.7.9` | A default tag does not prove six-target npm-channel acceptance |

The September 29 snapshot recorded npm `latest` at `0.6.0`, failed `0.7.4`
wrappers under `release-candidate`, crates.io at `0.5.1`, and no MCP Registry
`0.7.9` record. Those are historical observations, not current registry claims.
Historical audit entries and publication runbook examples retain their dates
and version-specific preconditions; do not replay them as current instructions.

On October 26, 2026, the exact public dist-tag endpoints below returned
`latest: 0.7.9` and `release-candidate: 0.7.4` for both npm packages.
This recheck confirms the npm tags, not native npm-channel acceptance.
Homebrew remains the dated October 12 repository observation above; crates.io
and MCP Registry were not requeried by this docs change.

- [CLI dist-tags](https://registry.npmjs.org/-/package/phantom-secrets/dist-tags)
- [MCP dist-tags](https://registry.npmjs.org/-/package/phantom-secrets-mcp/dist-tags)
- [Homebrew formula](https://github.com/ashlrai/homebrew-phantom/blob/main/Formula/phantom.rb)

On November 5, 2026, GitHub still listed `v0.7.9` as the newest published
immutable release, with 19 assets. Both public npm registries still returned
`latest: 0.7.9` and `release-candidate: 0.7.4`; neither public version list
contained `0.8.1` or `0.8.2`, and both exact `0.8.2` endpoints returned HTTP 404.
This does not inspect private npm stage reservations. The `v0.8.0` and `v0.8.1`
tags remain reserved; their existence is not publication evidence. The `v0.8.2`, `v0.8.3`, `v0.8.4`, and `v0.8.5` tags are also reserved and unqualified.

The `v0.8.6` is also reserved and unqualified: its full-CI success did not establish successful supplemental release-source acceptance or publication.

Neither package metadata nor the GitHub release proves hosted-service
commissioning, live provider activation, certification, or customer acceptance.
See [platform support](platform-support.md) for native acceptance boundaries.

Run the offline docs regression and local-link check with:

```sh
node --test scripts/docs-distribution.test.mjs
node scripts/check-docs-distribution.mjs
```
