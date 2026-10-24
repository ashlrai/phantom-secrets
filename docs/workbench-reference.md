# Workbench command reference

The workbench executable is `phm`, with compatible `ashlr` commands. The Secrets executable `phantom` belongs to a separate product. This page lists a small reviewed surface; the installed help and machine-readable catalog are the authoritative discovery path.

## Discover the installed contract

```sh
phm --version
phm docs --agent --json
phm resources --help
phm authority --help
phm verse --help
```

The agent catalog describes selected commands, safety classes and JSON shapes. Its safety labels do not replace command-specific effects or current authorization. An exit code of zero may mean an inspection succeeded while the inspected subsystem remains held.

## Reviewed commands

| Command | Effect and interpretation |
| --- | --- |
| `phm --version` | Read selected CLI version; compare it with the matching public release |
| `phm docs --agent --json` | Read selected agent-facing command descriptions and output contracts |
| `phm verse` | Start the local workbench and open the browser; may refresh accounts |
| `phm verse --no-open` | Start the local workbench without opening a browser |
| `phm verse --port 7778` | Start on an explicitly selected local port |
| `phm authority status --json` | Read grant, switch, Stop, rollout, ledger and custody state |
| `phm authority setup --dry-run --json` | Read the resumable commissioning checklist without applying it |
| `phm authority resident status --json` | Read resident service admission and configuration drift |
| `phm companions --json` | Read companion executable inventory; availability is not activation |
| `phm jev status --json` | Read local typed-decision ledger; no provider readiness proof |
| `phm desktop install` | Inspect and download verified artifacts into a private stage; `--apply` mutates the installation |

Use actual installed help before selecting an integration or changing settings. Do not invent flags from a historical guide. The source commands may differ from an older installed package.

## Browser and tools

The local console defaults to `http://127.0.0.1:7777/verse/`. Read and mutation tokens are private. Do not expose this listener directly to the internet. Phone access is a separate protected gateway described in [Remote phone](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/REMOTE-PHONE.md).

Configured MCP servers and CLIs preserve their account permissions. Tool names, saved profiles and provider badges are not proof of executable server identity, authentication or permission. Use the selected provider's documented setup and inspect the workbench's readiness result.

## Experimental source workflows

The Universe experiment kernel has an explicit-store command surface, distinct from everyday workbench setup. Discover `phm universe help` and consult [the upstream operator guide](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/ASHLR-UNIVERSE.md) before executing an experiment. Starting a trial can invoke models and write private artifacts; it does not enable autonomous publication.

[CLI entry point](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/src/cli/index.ts), [generated discovery catalog](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/src/cli/help.ts), [workbench launcher](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/src/cli/verse.ts), and [authority commands](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/src/cli/authority.ts).
