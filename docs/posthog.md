# PostHog fleet capture through Phantom

Fleet, RQ-BUS-5 and RQ-QUEUE emitters can send events without reading a project
key. The `posthog_fleet` built-in route injects the vault's `POSTHOG_API_KEY`
only into `Authorization: Bearer …` on an HTTPS request to
`us.i.posthog.com/i/v1/analytics/events`. It accepts only POST and an optional
trailing slash. Other methods, legacy capture paths and management paths fail
locally before credential lookup. This route supports US Cloud only.
Use the project's capture token, not a personal API key.

## Configure the route

In a trusted terminal, `phantom init` auto-detects the built-in when protecting
an existing `POSTHOG_API_KEY`. For a new empty project, use `phantom init --empty`
then `phantom add POSTHOG_API_KEY` and add the route table below. Never paste a
key into chat or source. For an already protected key, add this value-free definition to `.phantom.toml`
(replace the previous custom `posthog_fleet` table):

```toml
[services.posthog_fleet]
secret_key = "POSTHOG_API_KEY"
pattern = "us.i.posthog.com"
header = "Authorization"
header_format = "Bearer {secret}"
secret_type = "api_key"
```

The complete definition must match. Arbitrary destinations, renamed custom
routes and altered headers remain refused by `phantom exec`.

From the protected project directory, check the value-free diagnosis:

```sh
phantom why POSTHOG_API_KEY --json
```

Expected: `exec.delivery` is `proxied`, with service `posthog_fleet` and
upstream `us.i.posthog.com`. Missing custody, a locked vault or a refused route
must be resolved through Phantom before launching an emitter.

## Run an emitter

The [Python example](../examples/posthog-capture.py) uses only the standard
library. After authorizing an event write to the configured PostHog project,
run it under the newly built Phantom binary:

```sh
phantom exec -- python3 /path/to/phantom-secrets/examples/posthog-capture.py \
  fleet.work test-fleet --properties '{"queue":"RQ-QUEUE"}'
```

Expected output: `PostHog capture: HTTP 200, event accepted`. Each invocation
writes one event; it does not automatically retry. Use the same interface for
RQ-BUS-5 and RQ-QUEUE event names and non-secret properties.

The child receives a fresh placeholder in `POSTHOG_API_KEY`, an authenticated
loopback `POSTHOG_BASE_URL`, and `PHANTOM_PROXY_TOKEN`. The emitter never reads
`POSTHOG_API_KEY`. It sends the proxy bearer in `x-phantom-proxy-token`, including
in header-only auth mode. Keep the local URL and bearer out of logs too.
Phantom replaces client Authorization headers with the route-owned vault value,
never resolves body placeholders, refuses upstream redirects and scrubs
credential echoes from responses. The example disables redirects and ambient
HTTP proxies, bounds responses and prints fixed diagnostics.

Header injection works with PostHog's **v1 analytics** protocol. Legacy
`/capture`, `/batch` and `/i/v0/e` require body credentials; pointing an unchanged
legacy SDK at this route will fail. Adapt emitters to the v1 batch envelope and
required headers as shown in the example. A 200 alone does not prove event
acceptance: the example checks that the submitted UUID has an `ok` or `warning`
result. `drop`, `retry`, unknown or missing results fail without printing the
provider body. A warning indicates acceptance with reduced processing.

The protocol was checked against PostHog source commit
`09dbfe9e960c61d83b58dfd5c2d6c194fcf11001`:
[bearer authentication](https://github.com/PostHog/posthog/blob/09dbfe9e960c61d83b58dfd5c2d6c194fcf11001/rust/capture/src/v1/context.rs),
[required headers](https://github.com/PostHog/posthog/blob/09dbfe9e960c61d83b58dfd5c2d6c194fcf11001/rust/capture/src/v1/constants.rs),
[batch schema](https://github.com/PostHog/posthog/blob/09dbfe9e960c61d83b58dfd5c2d6c194fcf11001/rust/capture/src/v1/analytics/types.rs)
and [results](https://github.com/PostHog/posthog/blob/09dbfe9e960c61d83b58dfd5c2d6c194fcf11001/rust/capture/src/v1/analytics/response.rs).
Provider rollout and live acceptance require separate verification.

## Retire the fleet.env workaround

Change the external fleet, RQ-BUS-5 and RQ-QUEUE launch commands to use
`phantom exec` and the v1 emitter contract above. Remove their `fleet.env`
sourcing after confirming a real event is accepted. This repository contains
neither those external emitters nor their interim environment file, so this
change does not delete or claim to migrate an external file.

Rollback: stop the affected emitter and remove the `posthog_fleet` service
table. Do not restore plaintext-key environment injection. Without a route,
`phantom exec` withholds the inherited `POSTHOG_BASE_URL`; the key's placeholder
cannot authenticate directly to PostHog.
