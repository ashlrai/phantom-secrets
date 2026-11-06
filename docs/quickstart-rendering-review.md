# Quickstart rendering review

Use this checklist for the [landing-page install section](https://phm.dev/secrets#install),
rendered by [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx).
It describes the displayed UI, not a record of an installation. The release
version, links, and command text are sourced from the component and its release
constants; check the page for their current values.

## Displayed sections

The selector initially shows macOS; selecting Windows or Linux replaces the
card, so only one platform card is visible at a time. Each card displays its
vault label and description, two architecture archive links with SHA-256
sidecars, an installer-source link, a copyable multiline command, and a caveat.

| Platform | Vault label | Archive targets | Installer and prompt | Caveat shown |
|---|---|---|---|---|
| macOS | Keychain when available | Apple Silicon, Intel | `install.sh`, `$`, `shasum -a 256 -c -` | Release is not notarized; inspect and verify before any policy-dependent unblock. |
| Windows | Credential Manager when available | ARM64, x64 | `install.ps1`, `PS>`, `Get-FileHash -Algorithm SHA256` | Archives are not Authenticode-signed; unblock only after verification and if local policy permits. |
| Linux | Keyutils initially | ARM64, x64 | `install.sh`, `$`, `sha256sum -c -` | Keyutils is session-persistent, not reboot-persistent; Secret Service or a managed passphrase is needed for the described alternatives. |

Linux also displays the GNU glibc 2.35 symbol ceiling and the absence of musl
and Alpine builds. Beneath every selected card, the shared installation note
explains verification, staging, cleanup, and the platform guide. Two shared
numbered steps follow: verify both binaries on PATH with `phantom --version`
and `phantom-mcp --version`, then protect one supported project with
`phantom init`. Their receipts are labeled illustrative; both shared command
panels use the `$` prompt, including on Windows.

## Manual rendering check

1. Open `/secrets#install` locally or on the site. At a desktop width and at
   320px and 375px viewport widths, select each platform and confirm its card,
   targets, source link, caveat, and selected state match the table above.
2. Read each installer panel from top to bottom. Confirm original command
   line breaks and indentation remain readable, especially the Windows `try`
   and `finally` blocks. Long lines may wrap visually, but no text should be
   clipped, overlap, or force horizontal page scrolling. Also inspect the two
   lines in the shared version-check panel and the illustrative receipts.
3. Copy each installer command into a plain-text editor without running it.
   Compare the original line breaks and indentation with the panel; visual
   wrapping must not insert extra newlines. Confirm the decorative `$` or
   `PS>` prompt is absent. Check both shared command panels the same way.
4. Use Tab and Enter or Space to select platforms and activate copy. Confirm
   focus and the selected state are visible and that copy success or failure is
   announced. If clipboard access fails, check that command text can be selected
   manually, excluding the prompt.

Do not include local secrets, managed mappings, or command output in review
notes. The existing narrow-screen browser test checks layout and clipboard
behavior; this visual review also checks legibility and interpretation.
