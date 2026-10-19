# Temporal workers with no secrets on disk (optional)

Status: guidance only. Phantom does not depend on Temporal, ships no Temporal code, and has not been tested against a Temporal server in this repository. Items marked DESIGN are untested proposals. Facts about Temporal come from the Temporal documentation and releases pages read on 2026-10-18 and rechecked on 2026-10-19, and may change; check the linked pages. A payload codec sketch lives in [`examples/temporal-codec-python`](../examples/temporal-codec-python/README.md) (unit tested with fake keys only).

## What this is for

[Temporal](https://github.com/temporalio/temporal) (MIT licensed) runs durable workflows: a workflow resumes at the failed step after a crash. Teams that already run Temporal for agent or rotation workflows can use Phantom so that the worker process does not need real credentials in a checked-in file. Phantom stays a separate, optional layer. Nothing in Phantom requires Temporal, and nothing here changes how Phantom works.

## Rule 1: no raw secret values in Temporal payloads

Never put a real secret value in any of these, because Temporal stores them in workflow history:

- workflow, activity, or child workflow inputs and results
- signal inputs, query inputs and results, memo, and headers
- application error messages and stack traces (failure text is stored too)

Pass secret names or opaque identifiers instead, and let the activity use the credential that `phantom exec` gave its own process. A `phm_` placeholder is not a real key, so it is safe in history, but prefer the name: `phantom exec` hands each run fresh session placeholders that stop working when that run ends, so a placeholder recorded in history will not resolve when the workflow is replayed or retried on another worker.

A payload codec can encrypt payloads, but it is a second layer. It is not a reason to put a raw value in a payload.

## Rule 2: start workers through Phantom

Run the worker under `phantom exec` so that it receives placeholder tokens and a local proxy, and real values stay in the vault:

```sh
phantom exec -- python worker.py
```

The worker's own connection settings (for example a Temporal Cloud API key or an mTLS client key) should come from the environment that Phantom provides, not from a file in the repository. Which Temporal client settings can be delivered this way depends on how your worker reads its configuration and on which services Phantom has routes for. Check `phantom exec` behavior in [Getting started](getting-started.md) before relying on it. DESIGN: not tested with a Temporal worker here.

Activities that call model or API providers should send requests through the Phantom proxy base URLs that `phantom exec` sets, so the provider key is injected outside the worker process.

## Rule 3: lock down the Temporal server

**Configure an Authorizer.** The Temporal self-hosted security guide warns that if you do not configure an `Authorizer`, the server uses the default `noopAuthorizer`, which allows every API request with no authentication or access control: anyone who can reach the server can call any API, including administrative ones (https://docs.temporal.io/self-hosted-guide/security). The guide says to configure an `Authorizer` with a matching `ClaimMapper` (server options `temporal.WithAuthorizer` and `temporal.WithClaimMapper`).

- Do not expose a development server to a network. `temporal server start-dev` is for local experiments only and must never hold real secrets.
- For anything shared, configure mTLS (`internode` and `frontend`) plus the Authorizer and ClaimMapper.

**Pin the server version.** Use Temporal Server v1.32.1 or newer. v1.32.1 was published on 2026-10-08 and was the newest release on the v1.32 line when this page was checked (https://github.com/temporalio/temporal/releases/tag/v1.32.1). Its release notes list bug fixes and no security advisories, so the pin is a current baseline, not a fix for a known issue. Check the releases page for newer patches before you upgrade.

## Rule 4: encrypt payloads with a codec, and guard the Codec Server

Per the Temporal data encryption guide (https://docs.temporal.io/production-deployment/data-encryption):

- A Payload Codec encrypts payloads before they reach the Temporal Service, so data is unencrypted only in the client and worker processes. It covers workflow, activity and child workflow inputs and results, signal inputs, memo, headers (check your SDK), query inputs and results, and local activity and side effect results. Failure messages and stack traces are encoded only if you enable that in the Failure Converter.
- A Codec Server is an HTTP server you run (`/encode`, `/decode`, and `/download` for External Storage). It decodes sensitive data in one call, so restrict access. Keeping it on localhost is a pattern the guide accepts. Authorization from the Web UI requires HTTPS, and the Web UI also needs CORS headers.

How this fits with Phantom:

- Running the worker under `phantom exec` keeps provider keys out of it, but it does not deliver a codec key. `phantom exec` exports `phm_` placeholders, and the Phantom proxy injects real credentials only into outbound requests on its routes; it does not hand key material to a process. A codec key stored in Phantom would therefore reach the worker as a placeholder, which cannot encrypt anything. The [codec sketch](../examples/temporal-codec-python/README.md) records the key id in payload metadata for rotation, so key ids land in workflow history and must be plain labels. It prefers to read its keys once from an inherited pipe named by `PHANTOM_TEMPORAL_CODEC_KEYS_FD` (an fd number, not a secret), which keeps them out of argv and the process environment; `PHANTOM_TEMPORAL_CODEC_KEY_<ID>` variables remain as a weaker fallback. Phantom has no command that writes a key to that pipe, so the producer is yours to choose, and it must not take the key on its own command line.
- The sketch's Codec Server binds to `127.0.0.1:8081` and sends no CORS headers by default, which suits the Temporal CLI (`--codec-endpoint`). For the Web UI, list exact origins (scheme, host and port) in `PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS`; `*` and patterns are refused at startup. It then allows only `POST` to `/encode` and `/decode` with `Content-Type` and `X-Namespace`, and refuses a request from any other origin with 403 and no CORS headers. It does not check authorization, so it does not allow the `Authorization` header. It has unit and local HTTP tests but was not run against the Web UI.
- A codec does not make it safe to put a raw secret in a payload (Rule 1).

## Rule 5: treat inbound text as data

Workflows that react to email, webhooks, or issue text must treat that text as untrusted data. Do not pass it to a model as instructions, and do not let it choose which secrets, tools, or approvals are used. Anything irreversible (send, publish, rotate, delete) needs an explicit approval step that the inbound text cannot supply.

## Where Temporal could help Phantom workflows (DESIGN, untested)

- Rotation: detect, mint, store, verify, revoke, with retries and a human approval signal. History would hold secret names and opaque lease ids only.
- Leases: a durable timer that revokes at expiry even if the issuing process died.
- Leak response: a finding arrives as a signal and is deduplicated by workflow id.

None of these is implemented. Lease and leak-alert designs wait for the lease security review.

## Not covered

No Temporal credential patterns are in the Phantom leak scan yet. Confirm the real formats before adding any. Hosted Temporal Cloud behavior was not tested.
