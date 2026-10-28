# Distribution status

Package publication and native acceptance are separate evidence. Use the
checksum-verified [GitHub v0.7.9 assets](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.9)
for an exact install; an unpinned command can change independently.

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

Neither package metadata nor the GitHub release proves hosted-service
commissioning, live provider activation, certification, or customer acceptance.
See [platform support](platform-support.md) for native acceptance boundaries.

Run the offline docs regression and local-link check with:

```sh
node --test scripts/docs-distribution.test.mjs
node scripts/check-docs-distribution.mjs
```
