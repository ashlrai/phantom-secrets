# Landing-page install copy checklist

Use this checklist with the [install panel](https://phm.dev/#install), whose
source is [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx).
Copy the current command from the selected card, not from a saved snippet: the
release tag, source commit, and installer digests are pinned in
[`public-release.ts`](../apps/web/src/lib/public-release.ts).

## Before copying

- [ ] Select your operating system: **macOS** is selected initially; choose
      **Windows** or **Linux** when appropriate. The installer selects the
      architecture: Apple Silicon or Intel, Windows ARM64 or x64, or Linux
      ARM64 or x64. The card also links each archive and SHA-256 sidecar.
- [ ] Use Bash on macOS or Linux and PowerShell on Windows. The Linux releases
      are GNU targets with a glibc 2.35 symbol ceiling; musl and Alpine builds
      are not published.
- [ ] Review the card's exact installer source and the
      [installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows).
      macOS releases are not notarized and Windows archives are not
      Authenticode-signed; follow local policy before any unblock.

## Copy and check the command

- [ ] Copy the entire multiline command using the card's copy control. If copy
      fails, select the command text manually. Do not include the displayed
      `$` or `PS>` prompt when selecting manually; it is not command text.
      Preserve newlines, straight quotes, dollar signs, and parentheses; do not
      retype them as typographic quotes or paste the block into another shell.
- [ ] On macOS and Linux, retain the quotes around
      `"${TMPDIR:-/tmp}/phantom-install.XXXXXX"`, `"$phantom_installer"`,
      `"$phantom_stage"`, and the installed paths. They keep paths containing
      spaces together. The single-quoted `trap` defers expansion until exit;
      keep the surrounding subshell, `set -euo pipefail`, and `umask 077`.
- [ ] On Windows, retain the PowerShell single-quoted literals, the `&` call
      operators, and the double-quoted installed paths. The block uses a
      unique file under `$env:TEMP`, and `-LiteralPath` for its hash and cleanup.
- [ ] Confirm the command downloads the pinned script over HTTPS, verifies its
      fixed SHA-256 digest before executing it, and checks both installed
      binaries. macOS uses `shasum -a 256 -c -`, Linux uses `sha256sum -c -`,
      and Windows uses `Get-FileHash -Algorithm SHA256`. Stop on a failure;
      do not bypass the check. The installer separately verifies the selected
      archive, its two-binary shape, and versions before promotion.

## After running

- [ ] On macOS and Linux, the exit trap attempts to remove the installer and
      then its empty staging directory, including after failures once the trap
      is installed. `TMPDIR` falls back to `/tmp` when unset or empty. On
      Windows, `finally` attempts to remove the temporary installer file.
      Cleanup is best effort, not guaranteed; inspect and remove leftovers if
      needed. These temporary locations are not the install directory.
- [ ] Check both versions against the pinned release. The subsequent panel's
      `phantom --version` and `phantom-mcp --version` use PATH, while the
      platform command checks explicit installed paths. The displayed receipts
      are illustrative.
- [ ] Before `phantom init`, work in an owned Git repository, keep an independent
      provider recovery copy, and start with a supported HTTP API key. Linux's
      initial keyutils vault is session-persistent, not reboot-persistent; the
      encrypted-file backend needs a managed passphrase configured before init,
      kept out of agent process inheritance. Do not expose values or managed
      mappings in chat or logs.

For a step-by-step explanation, see the [reading guide](quickstart-reading-guide.md)
and [platform comparison](quickstart-platform-comparison.md).
