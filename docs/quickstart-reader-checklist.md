# Landing-page quickstart reader checklist

Use this checklist to review the [install panel](https://phm.dev/#install)
against [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
after a copy, layout, or installer change. Check all three cards at desktop and
narrow widths; record the platform, viewport, and any unclear or mismatched
text when reporting an issue. The page's copy controls are the source for the
current commands; release values come from [`public-release.ts`](../apps/web/src/lib/public-release.ts).
Review the exact installer source and the [installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows)
before running anything. Selecting and copying a command does not run it.

## Platform labels

- [ ] The selector offers macOS, Windows, and Linux, with macOS selected
      initially. Selecting each option shows one card with the matching heading
      and selected state; keyboard users can reach and operate the selector.
- [ ] Architecture labels match the card: macOS has Apple Silicon and Intel;
      Windows and Linux each have ARM64 and x64. Each architecture has an
      archive link and a SHA-256 sidecar link for the pinned release.
- [ ] The card identifies its vault and caveat clearly: Keychain when available
      and lack of notarization on macOS; current-user Credential Manager when
      available and unsigned archives on Windows; initially session-persistent
      keyutils and GNU/glibc support limits on Linux. Linux musl and Alpine
      builds are not published.

## Command readability

- [ ] The command label and exact installer source link are visible for each
      card. The whole multiline command remains readable at narrow widths,
      including wrapped lines, quotes, and punctuation; the copy control is
      reachable by keyboard and gives feedback on success or failure.
- [ ] The decorative `$` prompt on macOS/Linux and `PS>` on Windows are not
      part of the copied command. If copying fails, a reader can select the
      command manually without including the prompt and preserve its newlines.
      Use Bash for the Unix cards and PowerShell for Windows.
- [ ] A reader can follow the order: download the pinned script, verify its
      SHA-256 digest, run it only after verification, then check both installed
      binaries. macOS uses `shasum -a 256 -c -`, Linux uses `sha256sum -c -`,
      and Windows uses `Get-FileHash -Algorithm SHA256`.
- [ ] The later PATH-based `phantom --version` and `phantom-mcp --version`
      checks and `phantom init` are distinguishable from the platform command.
      Receipts are illustrative, and init calls for an owned Git repository, an
      independent provider recovery copy, and a supported HTTP API key.

## Staging and cleanup

- [ ] On macOS and Linux, the command creates a unique staging directory under
      `TMPDIR`, or `/tmp` when it is unset or empty. Quoted paths accommodate
      spaces. The `EXIT` trap attempts to remove the installer and then the
      empty directory on exit, including failures after the trap is installed.
- [ ] On Windows, a GUID-based installer file is assigned under `$env:TEMP`;
      the command does not create a Unix staging directory or specify a
      fallback. `finally` attempts to remove the file after the `try` block.
- [ ] The copy makes clear that cleanup is best effort, not guaranteed, and
      that staging is separate from the installed binaries. Before removing a
      leftover, confirm it belongs to a finished run, since another install may
      still be using its files. See [staging and cleanup](quickstart-stage-cleanup.md)
      for failure boundaries and the [copy checklist](quickstart-copy-checklist.md)
      for reader-facing instructions.
