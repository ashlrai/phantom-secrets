# Agent setup quickstart

This guide is for coding agents helping a user adopt Phantom. First discover the installed release and actual command surface. Then distinguish inspection, installation, interactive execution and operator-only activation.

## Fetch the public contract

- [Documentation manifest](/docs/manifest.json): catalog, canonical URLs, raw Markdown links and published workbench record.
- [Compact workbench context](/workbench/llms.txt).
- [Full workbench context](/workbench/llms-full.txt).
- [Install guide as Markdown](/docs/workbench-setup/markdown).

Public documentation contains no user credentials or local state. Do not infer a user's runtime readiness from this site's publication record.

## Inspect before changing anything

On a machine with the workbench installed:

```sh
phm --version
phm docs --agent --json
phm authority status --json
phm authority setup --dry-run --json
phm authority resident status --json
```

These commands inspect the selected CLI and local authority state. The setup dry run returns a preparation checklist; it does not install or restart the daemon. Use help to discover exact resource and integration commands:

```sh
phm resources --help
phm verse --help
phm desktop --help
```

Keep private paths, account identifiers, grants and tokens out of public reports. The `ashlr` alias is compatible. The unrelated Secrets executable is `phantom`.

## Installation and first turn

If `phm` is missing, present the [version-pinned installation path](workbench-setup.md) and obtain authority for installing software in the user's selected environment. Launching `phm verse` starts a local server and may refresh configured resources. Follow the printed local URL and token handoff; never publish or transcribe those tokens.

Help the user choose a project and inspect Resources. Authenticate native accounts through their vendor's trusted interface. Do not read credential files or request secrets through the conversation. Use Automatic when no explicit account is required; inspect the chosen resource and costs before starting a turn.

For the first task, use a small authorized repository, observable acceptance criteria and existing tests. Report the actual diff and checker results. Do not convert a configured profile or a successful process exit into verified fleet activation.

## Operator-only steps

Agents may explain custody setup, review dry-run blockers and prepare code for review. They must not imitate Touch ID, type a trusted-terminal ceremony through an agent-controlled shell, sign a standing grant or invoke resident start on the user's behalf. The operator completes these steps through [the autonomy setup guide](workbench-autonomy.md).

A grant limits repositories, engines, roles, spend and risk. A user request to be ambitious does not erase existing signed limits. A saved outcome does not enroll a repository or start a service. If readiness is unknown, report the unknown and its next verification step.

## Suggested handoff report

Report installed version; selected project; account readiness and usage freshness; requested action; diff and checks; remaining operator steps. Distinguish package installation, desktop startup, provider authentication, resident service admission, verified merges and production deployment.

[CLI discovery source](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/src/cli/help.ts), [authority command source](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/src/cli/authority.ts), and [upstream documentation index](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/README.md).
