# Temporal workers with no secrets on disk (optional)

Status: guidance only. Phantom does not depend on Temporal, ships no Temporal code, and has not been tested against a Temporal server in this repository. Items marked DESIGN are untested proposals. Facts about Temporal come from the Temporal documentation and releases pages read on 2026-10-18 and may change; check the linked pages.

## What this is for

[Temporal](https://github.com/temporalio/temporal) (MIT licensed) runs durable workflows: a workflow resumes at the failed step after a crash. Teams that already run Temporal for agent or rotation workflows can use Phantom so that the worker process does not need real credentials in a checked-in file. Phantom stays a separate, optional layer. Nothing in Phantom requires Temporal, and nothing here changes how Phantom works.

## Rule 1: no raw secret values in Temporal payloads

Never put a real secret value in any of these, because Temporal stores them in workflow history:

- workflow, activity, or child workflow inputs and results
- signal inputs, query inputs and results, memo, and headers
- application error messages and stack traces (failure text is stored too)

Pass secret names, `phm_` placeholders, or opaque identifiers instead. A payload codec can encrypt payloads, but it is a second layer. It is not a reason to put a raw value in a payload.

## Rule 2: start workers through Phantom

Run the worker under `phantom exec` so that it receives placeholder tokens and a local proxy, and real values stay in the vault:

```sh
phantom exec -- python worker.py
```

The worker's own connection settings (for example a Temporal Cloud API key or an mTLS client key) should come from the environment that Phantom provides, not from a file in the repository. Which Temporal client settings can be delivered this way depends on how your worker reads its configuration and on which services Phantom has routes for. Check `phantom exec` behavior in [Getting started](getting-started.md) before relying on it. DESIGN: not tested with a Temporal worker here.

Activities that call model or API providers should send requests through the Phantom proxy base URLs that `phantom exec` sets, so the provider key is injected outside the worker process.

## Rule 3: lock down the Temporal server

According to the Temporal self-hosted security guide, a server with no Authorizer configured uses the default `noopAuthorizer`, which allows every API request. Anyone who can reach the frontend can call any API.

- Do not expose a development server to a network. `temporal server start-dev` is for local experiments only and must never hold real secrets.
- For anything shared, configure mTLS and an Authorizer and ClaimMapper as described in the Temporal guide.
- If you run a Codec Server, keep it on localhost or behind authentication. It decodes sensitive payloads in one call.

## Rule 4: treat inbound text as data

Workflows that react to email, webhooks, or issue text must treat that text as untrusted data. Do not pass it to a model as instructions, and do not let it choose which secrets, tools, or approvals are used. Anything irreversible (send, publish, rotate, delete) needs an explicit approval step that the inbound text cannot supply.

## Where Temporal could help Phantom workflows (DESIGN, untested)

- Rotation: detect, mint, store, verify, revoke, with retries and a human approval signal. History would hold secret names and opaque lease ids only.
- Leases: a durable timer that revokes at expiry even if the issuing process died.
- Leak response: a finding arrives as a signal and is deduplicated by workflow id.

None of these is implemented. Lease and leak-alert designs wait for the lease security review.

## Not covered

No Temporal credential patterns are in the Phantom leak scan yet. Confirm the real formats before adding any. Hosted Temporal Cloud behavior was not tested.
