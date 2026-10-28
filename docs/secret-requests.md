# Request a secret without handling its value

An agent can reserve a secret name in an initialized project:

```sh
phantom request OPENAI_API_KEY --purpose 'Call the model for this application' --route openai
phantom requests --json
```

`request` prints `NAME=phm_…` for immediate reference. The placeholder and purpose
are stored in `.phantom.toml`; keep this metadata private. Supply only a
non-secret purpose. There is no value argument, value prompt, stdin reader,
vault access, provider call, or approval ceremony in either request command.
Run `phantom init --empty` first if the project is not initialized.

The optional route is a hint restricted to the built-in proxy route for that
exact secret name. It does not install a route or authorize credential use.
Requests without a supported route can still be fulfilled; use `phantom why
NAME` to check delivery before running a client. Client headers and bodies
never resolve placeholders.

A human in a terminal outside agent authority fulfills the request with:

```sh
phantom add OPENAI_API_KEY
```

The existing hidden prompt accepts the value outside the model. An existing
sanctioned producer may instead use `phantom add OPENAI_API_KEY --stdin` under
its own authorization. For application-owned random secrets,
`phantom add OPENAI_API_KEY --generate` fulfills the request the same way:
it installs the reserved placeholder and records `fulfilled` in the same
transaction. Agents must not solicit values in chat or execute a
producer to obtain them. No new value-bearing API is introduced.

Successful `add` stores the value, installs the reserved placeholder in the
managed dotenv, and records `fulfilled` in one exact-before transaction.
Failures leave the request pending. Existing vault names retain the existing
create-only refusal. A pending request does not place a dummy credential in
the vault or dotenv and cannot authenticate a client before fulfillment.
Repeating an identical request returns the same placeholder; conflicting
purpose or route metadata is refused.

`phantom requests --json` (also `phantom --json requests`) returns an object
with `schema: "phantom.requests.v1"` and `requests`, a name-keyed object. Each
request has `purpose`, nullable `route`, `placeholder`, and `status` (`pending`
or `fulfilled`). An empty project returns an empty object. Text output lists
names and statuses. Status is a persisted fulfillment receipt, not a live
credential validation or inventory check: later removal, expiry, or rotation
uses its existing workflow and does not erase request history. Other import
and copy workflows do not fulfill requests; use `add` for this workflow.
