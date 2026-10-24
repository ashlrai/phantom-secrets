# Workbench troubleshooting

Start with the selected installed release and its reported blocker. Keep private tokens, credentials, repository content and raw account logs out of shared reports.

## `phm` is missing or the version is wrong

Check Node.js 22.15+, Git, npm's global executable directory and PATH. `phm` belongs to `@ashlr/phantom`; the `phantom` command belongs to Phantom Secrets. Compare `phm --version` with the package and desktop version you selected. Review [installation](workbench-setup.md) before reinstalling.

## The local console will not open

Use the address printed by `phm verse`; its default is `http://127.0.0.1:7777/verse/`. Check whether a previous workbench process occupies the port. For an authorized new server, use `phm verse --port 7778 --no-open` and open its printed address. Do not kill an unrelated listener or expose the service on a public address to solve a local problem.

A browser read token does not authorize mutation. Follow the local token handoff when starting a chat or changing state. Never put tokens in a public URL, screenshot or bug report.

## A resource is connected but work waits

Expand Resources and inspect account, provider, model, reported usage, freshness, reset deadline, reserve and actual eligibility. Signed out, unknown usage, exhausted quota, reserved capacity, unavailable local serving slots and missing authority are distinct blockers.

Native account authentication comes from the vendor CLI. API credits, subscription allowances and local hardware capacity are separate readings. A Grok Bot profile does not inherit Grok Build usage. An estimate does not establish a vendor balance. Diagnose the specific account instead of retrying every seat repeatedly.

## Saving an outcome did not start the fleet

Saving an outcome or changing workspace is navigation and configuration. Resident work requires enrolled repositories, eligible resources and admitted standing authority. Inspect:

```sh
phm authority status --json
phm authority setup --dry-run --json
phm authority resident status --json
```

Read the reported grant, switch, Stop, rollout stage, custody and service drift. Dormant, expired, revoked, held and unknown are meaningful states. The operator completes Touch ID and trusted-terminal service steps; an agent must not simulate them.

## Tests pass but delivery is incomplete

Local tests prove only the tested tree and scope. Check the exact PR head, required hosted checks, merge source, release artifact, installed startup and deployment readback as applicable. A release page or registry receipt is not proof that your app started, provider activated or fleet completed the outcome.

## Desktop installation needs attention

Match the app archive and `latest.json` to the CLI release. Follow [consumer desktop installation](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/desktop/README.md#consumer-first-install). macOS local signing and Apple notarization are different; source availability is not clean-Mac acceptance. Use the CLI on Linux and Windows in this snapshot.

## Share a useful report

Include OS and architecture, Node version, `phm --version`, the failed step, a redacted error category, expected behavior and whether the problem affects interactive chat or resident work. Include test names and exact public source or PR identity when relevant. Never attach credential files or unredacted account state.

[Upstream quickstart](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/QUICKSTART.md), [resource pools](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/RESOURCE-POOLS.md), and [autonomy setup](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/AUTONOMY-SETUP.md).
