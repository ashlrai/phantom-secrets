# Local onboarding sequencer

Status: unreleased CLI implementation, following the phase-1 design proposal.
This document describes the source branch. It does not establish a published
binary, deployed workbench UI, provider activation or hosted-service readiness.

## Command and phases

`phantom onboard --plan [--json]` detects dotenv/config presence and bounded
regular MCP profile files, without constructing a vault, counting secrets,
creating directories, migrating legacy plaintext or reconciling sidecars.
A config's presence is metadata, not proof of protection or validity. Detection
accepts local bundled `phantom mcp` or standalone `phantom-mcp` profile entries;
it never executes them or bootstraps a registry package.

A live run sequences these existing commands in order:

1. Protect: `phantom init` for the default `.env`, unless configuration is
   already present. Init retains its exact project-bound consent and transaction.
2. Connect: separately confirm each missing Claude, Cursor, Windsurf and Codex
   MCP profile, then `phantom agent setup --apply`. `--skip-connect` skips both.
3. Verify: `phantom doctor`, `phantom check`, and `phantom agent report`.
   All three must succeed for `done: true`.

Protect, Connect and Verify require attached stdin, stdout and stderr outside
agent authority, followed by confirmation. Verify is not a headless observer:
existing diagnostic vault probes may reconcile legacy backend storage. `--yes`
answers wizard prompts only; it cannot waive terminal checks, init's exact
challenge, or any existing authorization boundary.

## Receipt and failures

`--json` emits one version-1 receipt on stdout, including `done`, `outcome`,
`rerun`, and four ordered phases. Outcomes are `planned`, `complete`, `declined`
and `failed`. Phase and connection-step statuses are `ok`, `skipped`, `declined`
and `failed`. Details are bounded at UTF-8 character boundaries.

Live commands run as subprocesses of the current executable with fixed
arguments. Child stdin remains attached; JSON-mode child prose and prompts use
the already attached stderr. No new terminal or PTY is manufactured. This also
isolates an early exit from agent setup, allowing the parent to record failure.
Diagnostic output is captured into the receipt. A failure or decline stops later
phases and preserves the earlier completed steps in the receipt.

There is no transaction across phases or automatic rollback of completed work.
A rerun detects the current state and verifies it again; it does not guarantee
that interrupted setup is complete. The existing workspace plan/apply ceremony
remains separate.

## Boundaries and acceptance

The wizard does not create accounts, issue credentials, enable provider access,
start paid requests, install packages, trust connector authors or start a proxy.
`phantom exec` sessions remain user-owned. A receipt is available for consumers;
no workbench UI implementation is claimed here.

Source tests use synthetic homes, fake phase outcomes and real CLI subprocesses
with redirected streams. Unix legacy fixtures use effective synthetic HOME/XDG
storage roots; Windows OS KnownFolders cannot be redirected by those variables,
so Windows legacy-vault lifecycle acceptance is not claimed. Tests cover
unchanged legacy-vault bytes and metadata
in plan/refusal paths, one JSON receipt, terminal refusal, completed-step failure
receipts, MCP profile parsing and UTF-8 bounds. Synthetic phase tests do not
establish attended-terminal or live-provider acceptance. No real keychain or
provider credentials are used.
