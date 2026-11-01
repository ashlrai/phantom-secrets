# Maintaining landing-page quickstart content

Use this checklist after changing the install panel in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx), its
release data, or related installation copy. Compare the rendered panel for
every platform with the source and the linked installer; this is a copy review,
not an instruction to run an installer or handle real credentials. The panel
is the source of the copyable commands, and
[`public-release.ts`](../apps/web/src/lib/public-release.ts) supplies its
release identifiers and script digests.

## Review checklist

- [ ] **Platform labels:** Select macOS, Windows, and Linux in turn. Check the
  selected label, card heading, architecture labels, download and checksum
  links, command prompt, vault description, and platform caveat against the
  source and current release evidence. Check the initial selection and the
  accessible names as well as visible text; do not infer availability from a
  label alone.
- [ ] **Displayed command order:** For each card, follow the displayed and
  copied command from temporary staging through download, script checksum
  verification, execution, and both installed-path version checks. Confirm
  verification still precedes execution. Then review the shared numbered steps:
  the PATH-based `phantom --version` and `phantom-mcp --version` checks precede
  `phantom init`. Distinguish these checks from the ones inside the platform
  command and keep receipts described as illustrative.
- [ ] **Cleanup wording:** Compare the wording with each command's actual
  control flow. On macOS and Linux, the `EXIT` trap attempts to remove the
  installer and then the empty staging directory after trap installation,
  including on failures. On Windows, `finally` attempts to remove the temporary
  installer file. Cleanup is not guaranteed; neither the temporary staging
  location nor its cleanup is the user-owned install directory or an uninstall.
  Check the separate installer staging behavior before making claims about it.
- [ ] **Related guidance:** Update any affected
  [platform step map](quickstart-platform-step-map.md),
  [command sequence](quickstart-command-sequence.md),
  [cleanup review](quickstart-temp-cleanup-review.md), and
  [installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows).
  Resolve discrepancies using the component, installer source, and release
  evidence; avoid duplicating copyable commands or sensitive mappings in review
  notes.
- [ ] **Verify:** Run the focused maintenance test and affected QuickStart
  tests, plus the web typecheck and lint. Inspect the panel after changes that
  affect rendering or interaction, and record any platform behavior that could
  not be verified rather than claiming a successful installation.

From `apps/web`, the focused test is
`node --test tests/quickstart-content-maintenance.test.cjs`; the existing
`npm test` suite covers the wider web surface. These checks support review but
do not replace reading the rendered content or validating release artifacts.
