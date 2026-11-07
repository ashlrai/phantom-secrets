# Reading quickstart command panels

The landing page's [install section](https://phm.dev/#install) is built by
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). Choose
**macOS**, **Windows**, or **Linux** in the operating-system selector. macOS
is selected initially; activating another button replaces the visible card
with that platform's instructions. The buttons expose their selected state to
assistive technology and can be reached with Tab and activated with Enter or
Space. Each card includes architecture-specific archive and checksum links,
the exact installer source, the installer command, and a platform caveat.

The installer command is displayed in a dark copyable panel. It is one
multiline command block: its original line breaks and indentation are
preserved, while long lines may wrap visually to fit. A visual wrap does not
add a line break to the command. The `$` prompt on macOS and Linux, or `PS>`
on Windows, is a display cue at the start of the block, not part of the
command. The command text can also be selected manually.

Activate the command panel to copy the entire block, including its original
line breaks, without the prompt. The control reports whether copying succeeded;
if it fails, select and copy the command text manually, excluding the prompt.
Use the page for the current command and review the linked installer source
and [platform installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows)
before running it.

Below the selected card and installation note are two shared numbered steps.
The first panel contains two lines checking `phantom --version` and
`phantom-mcp --version` on PATH; the second contains `phantom init`. These
use the same copy behavior and the default `$` display prompt, including on
Windows. Their adjacent receipts are labeled illustrative and are not copied
with the commands. See the [reading guide](quickstart-reading-guide.md) for
the platform-specific command sequence and setup prerequisites.
