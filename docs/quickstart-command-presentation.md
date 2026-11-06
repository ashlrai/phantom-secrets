# Landing-page quickstart command presentation

The [install section](https://phm.dev/#install) is rendered by
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). It shows
one operating-system installer command followed by two shared numbered command
steps. The two kinds of command blocks have different jobs and presentation:

| | Platform installer card | Numbered steps |
|---|---|---|
| Location | Below the operating-system selector and archive links, inside the selected card. macOS is selected initially; Windows and Linux select their own cards. | Below the platform card and installation note. Each of the two numbered rows has its command beneath its heading and description. |
| Contents | A multiline, platform-specific download, verification, installation, and installed-path version-check command. The card also links the exact installer source and shows a platform caveat. | Step 01 checks `phantom --version` and `phantom-mcp --version` on PATH; step 02 runs `phantom init` for one supported project. An adjacent receipt is labeled illustrative, not actual output. |
| Appearance | A taller, dark command panel with smaller text. Windows displays a `PS>` prompt; macOS and Linux display `$`. | Compact, light command controls using the default `$` prompt, including on Windows. On narrow screens the receipt moves below the instruction. |

Both use [`CopyButton`](../apps/web/src/components/landing/CopyButton.tsx): the
command text is selectable, and the copy control writes the command itself to
the clipboard without the decorative prompt. It reports success or failure; on
failure, select the command manually without the prompt. Preserve the command's
line breaks and syntax. The receipt is separate from the command and is not
copied with it.

Use the selected card for the current command and review its linked installer
source and the [installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows)
before running it. The platform command already checks both binaries at their
installed paths; the later checks use PATH. See the
[copy checklist](quickstart-copy-checklist.md) and
[command sequence](quickstart-command-sequence.md) for platform details. This
guide describes the existing presentation; it does not change installation.
