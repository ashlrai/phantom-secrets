# Install and open Phantom

The supported CLI path works on macOS, Linux and Windows. Resident autonomy is macOS-only. The Apple silicon desktop app is a separate installation path.

## Before installation

Use Node.js 22.15 or later and Git. Check the [published workbench release](https://phm.dev) and select the matching package and desktop artifacts. Installation changes your machine; let the user choose the target environment before an agent installs software.

## Install the reviewed package

The guide is pinned to the 3.29.15 source and published release record:

```sh
npm install -g @ashlr/phantom@3.29.15
phm --version
```

Expected: `phm --version` reports the selected package version. If the command is missing, inspect npm's global executable directory and your PATH. A successful npm installation does not prove desktop startup or provider readiness.

## Open the local workbench

From a project the user has authorized Phantom to access:

```sh
phm verse
```

This starts a local server and opens `http://127.0.0.1:7777/verse/`. It binds to loopback. Startup prints a private read token; a separate mutation token is requested before the first chat or other change. Keep both tokens out of documentation, chat transcripts and shared logs.

For a server without browser opening:

```sh
phm verse --no-open
```

Use the URL printed by the selected process. If the default port is occupied, first identify the existing process; choose an unused port with `phm verse --port 7778` instead of terminating an unrelated service. Starting the workbench may refresh configured account readings; it is not a read-only inspection command.

## Connect a usable resource

Open **Resources** and inspect account readiness and freshness. Native Claude Code, Codex and Grok accounts sign in through their own vendor CLIs. Phantom does not need their passwords. A local model must support the tools required by the task and have available serving capacity. API engines may incur separate charges.

Choose **Work with me**, create a chat, select a scratch repository, and request a small, checkable change. Automatic selects an eligible resource. Advanced lets you choose an account or model. Review the diff and checks before accepting it.

## Desktop on Apple silicon Mac

Inspect the installed command before selecting a matching artifact:

```sh
phm desktop --help
phm desktop install
```

`desktop install` inspects the supported consumer installation path and downloads verified artifacts into a fresh private stage; `--apply` performs installation and requires deliberate operator authorization. Follow the [desktop installation guide](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/desktop/README.md#consumer-first-install). The current release uses a signed app archive and matching `latest.json`, rather than treating an old DMG as current. Local signing is distinct from Apple Developer ID notarization. Clean-Mac installation acceptance remains a separate qualification gate.

Linux and Windows use the CLI; this snapshot has no Linux or Windows desktop package. Never bypass a platform verification failure to make installation appear successful.

## Next steps

Read [the workbench overview](workbench.md), [agent setup](workbench-agents.md) and [troubleshooting](workbench-troubleshooting.md). Starting the console does not activate unattended work; [fleet setup](workbench-autonomy.md) covers that path.

[Source quickstart](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/QUICKSTART.md) and [desktop command source](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/src/cli/desktop.ts).
