# First five minutes: a value-free delegation contract

Run a complete local walkthrough before putting any credential or provider in
scope. The example shows the information an agent may receive and verifies that
the task remains closed to secret values, network access, and mutations.

## Run it

Prerequisite: Node.js 22 or newer on macOS, Linux, or Windows.

From the repository root, run:

```text
node examples/first-five-minutes/run.mjs
```

The command is read-only. It reads this directory's checked-in placeholder and
policy, performs no network request, and writes no file. Its output must match
[expected-output.txt](expected-output.txt) exactly.

## What this proves

The walkthrough verifies only the checked-in, value-free delegation contract:

- the agent can see the name `BILLING_API_TOKEN`, but not a value;
- the only secret field contains `<enter-in-trusted-terminal>`;
- network access and mutations are denied; and
- no Phantom token or mapping is generated or persisted.

It does not install Phantom, initialize a vault, test proxy injection, contact a
provider, or establish provider acceptance. For a real project, continue with
the [safe delegation quickstart](../../docs/delegation-quickstart.md), where
secret entry stays in a trusted terminal.

## Verify the contract test

```text
node --test scripts/examples-first-five-minutes.test.mjs
```

That test runs the example from an empty temporary working directory, compares
the exact transcript, rejects duplicate or unreviewed contract fields, and
enforces a narrow source contract: three exact read-only imports plus explicit
denials for dynamic module loading and known network, subprocess, and
filesystem-write escape hatches. The same test is part of the tiered CI and
release-source graphs.
