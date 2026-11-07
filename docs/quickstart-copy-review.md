# Landing-page quickstart copy review

This review describes the install panel in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx), not a
record of an installation. Use the selected card for the current command and
its linked installer source. No local values, managed mappings, or output are
needed for this review.

## Displayed sequence

1. Choose macOS (selected initially), Windows, or Linux. Each card offers two
   architecture-specific archives and their SHA-256 sidecars, a link to the
   pinned installer source, and a copyable platform command.
2. The platform command downloads and checks the pinned installer script before
   running it, then checks both installed binaries. macOS and Linux use a
   temporary staging directory; Windows uses a temporary file. Cleanup is
   attempted, not guaranteed. The page also says the installer checks the
   selected archive and binaries before promotion.
3. The first numbered step asks the reader to verify both binaries on PATH
   against the pinned release. This is separate from the installed-path checks
   already in the platform command.
4. The second numbered step asks the reader to work in an owned Git repository,
   keep an independent provider recovery copy, start with a supported HTTP API
   key, and run `phantom init`. The page labels its receipts illustrative;
   actual vault backends and findings vary.

The cards mention Keychain on macOS, current-user Credential Manager on
Windows, and initial keyutils storage on Linux. They also call out the unsigned
or unnotarized releases on Windows and macOS, Linux GNU compatibility, and
Linux vault persistence and passphrase considerations. See the
[platform step map](quickstart-platform-step-map.md) and
[installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows)
for details.

## Questions for copy review

These are questions for the page owner, not claims that a user has encountered
a failure or requests to change the implementation.

- **Starting point:** Is it clear that selecting an OS and running its command
  comes before the numbered steps, even though the platform card is unnumbered?
  Should the shell required for each command be named beside the copy control?
- **Download choice:** Can a reader tell when to use an architecture archive
  and sidecar instead of the copyable installer command, and where to find the
  manual verification instructions?
- **Trust and policy:** Are the source link, script checksum, archive checksum,
  and platform signing caveats understandable as separate checks? Does the
  reader know what to do if verification fails or local policy prohibits use?
- **Version checks:** Does the page explain why versions are checked again on
  PATH, what versions should match, and what to do if a command is unavailable
  or resolves to another installation?
- **First project:** Is “owned Git repository” sufficiently clear, and can a
  reader find what counts as a supported HTTP API key and how to keep an
  independent provider recovery copy without exposing its value?
- **Vault choice:** Can Linux users identify whether their initial keyutils
  vault meets their persistence needs, and find the managed-passphrase setup
  before init while keeping it out of agent process inheritance? Are the
  fallback expectations for unavailable platform credential stores clear?
- **Result and cleanup:** Will readers distinguish illustrative receipts from
  their own results and understand that temporary cleanup is best effort, not
  a confirmation that the installation or project protection succeeded?
