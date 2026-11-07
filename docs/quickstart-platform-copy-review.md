# Landing-page quickstart: platform copy review

Use this checklist to review the copy in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). It is a
review aid, not an installation receipt. The selected card is the source of
the current command; release tag, source commit, and script digests come from
[`public-release.ts`](../apps/web/src/lib/public-release.ts). Do not include
local secret values, managed mappings, or command output in review notes.

## Displayed command variants

The selector starts on macOS and shows one platform card at a time. Each card
has one multiline install command, a source link, and two architecture archives
with SHA-256 sidecars. The commands download a pinned script, check its digest,
run it, and check both installed binaries' versions.

| Card | Command and targets | Copy-review checks |
|---|---|---|
| macOS | Bash `install.sh`; Apple Silicon and Intel; `shasum -a 256 -c -`. | Does the copy explain Keychain availability and that the release is not notarized? Is inspection and checksum verification required before any policy-dependent unblock? |
| Windows | PowerShell `install.ps1`; ARM64 and x64; `Get-FileHash -Algorithm SHA256`. | Is current-user Credential Manager availability clear? Does the unsigned-archive caveat limit unblocking to after verification and when local policy permits? |
| Linux | Bash `install.sh`; ARM64 and x64 GNU; `sha256sum -c -`. | Are the glibc 2.35 symbol ceiling and absence of musl and Alpine builds clear? Does the copy distinguish session-persistent keyutils from reboot persistence and point to Secret Service or a managed passphrase when appropriate? |

Two numbered commands follow every card: `phantom --version` and
`phantom-mcp --version` together check the binaries on PATH, then
`phantom init` protects one project. Review whether the page makes clear that
these PATH checks are separate from the installed-path checks in the platform
command, and whether the first project should be an owned Git repository with
an independent provider recovery copy and a supported HTTP API key.

## Cross-platform review checks

- **Selection and copying:** Is it obvious which OS is selected and that the
  visible `$` or `PS>` prompt is not part of the copied command? Can a reader
  select the command manually if clipboard access fails?
- **Trust and order:** Can readers distinguish the pinned script digest from
  the archive's adjacent checksum and understand that the script is verified
  before execution? Can they find the exact source and manual archive guidance?
- **Temporary files:** Do the Unix commands explain `TMPDIR` or `/tmp` staging
  and the exit trap, while Windows uses a temporary file under `$env:TEMP` and
  `finally`? Is cleanup described as attempted, not guaranteed, and distinct
  from the install directory?
- **Evidence and results:** Are the receipts clearly illustrative, and is the
  release evidence kept distinct from local shell, policy, and vault state?
  Can readers recognize a failed verification or version mismatch without
  treating the example output as their own result?
- **Vault and recovery:** Is Linux's encrypted-file passphrase requirement
  visible before init, with the passphrase kept out of agent process
  inheritance? Are users directed to preserve an independent recovery copy
  without putting credential values into review notes?

See the [copy checklist](quickstart-copy-checklist.md),
[platform step map](quickstart-platform-step-map.md), and
[installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows)
for the operational details and manual archive path.
