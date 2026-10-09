# DESIGN: Unified onboarding wizard — proposal (not implemented)

Status: proposal for Mason's input. Nothing below is built.

## Problem

First-run setup is split across four entry points with overlapping
responsibilities and different trust assumptions:

- `phantom init` — vault + managed dotenv rewrite (mutates secrets)
- `phantom setup --client <x>` — writes MCP client config
- `phantom agent setup [--dry-run]` — readiness report / doctor / setup workflows
- `phantom workspace plan|apply|status` — trusted-terminal workspace setup transactions

A new user (or a workbench driving setup on their behalf) must discover the
right order, the right trust context for each step, and what "done" looks like.

## Proposal

One guided flow, `phantom onboard` (name TBD), that walks the operator through
phases with explicit gates:

1. **Detect** (read-only): find dotenv files, existing `.phantom.toml`, client
   configs. Pure reads; safe to run anywhere.
2. **Protect** (trusted terminal only): run the `init` transaction — vault
   selection, value intake, dotenv rewrite, `.env.example`, pre-commit hook.
   Refuses to run unless stdin/stdout are an attached terminal.
3. **Connect** (trusted terminal): pick clients, preview then write MCP configs.
4. **Verify** (anywhere): `doctor`, `check`, installed-runtime smoke; prints a
   bounded summary the operator can hand to an agent.

Each phase prints its exact plan before mutating (like `workspace plan`), and
the whole run emits a machine-readable receipt (`--json`) so the Phantom
workbench can render progress without parsing prose.

## Non-goals

- No new trust model: the existing boundaries (values never in agent context,
  approvals outside agent authority) are unchanged; the wizard only sequences
  existing commands.
- No hosted onboarding: no account creation, no telemetry.

## Questions for Mason

- Should this live in the CLI (`phantom onboard`) or in the workbench UI
  driving the CLI's `--json` receipts?
- Should `phantom agent setup` and `phantom workspace` be refactored onto the
  wizard's phase engine, or left as-is with the wizard as a thin sequencer?
- What is the "done" definition — `doctor` clean, or a stricter checklist?
