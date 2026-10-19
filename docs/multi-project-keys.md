# Separating personal, company, and client keys

Engineers who work across personal projects, an employer, and several clients
usually hold many API keys that must never cross between those contexts. This
guide shows how to keep them separate with the commands that ship in `v0.7.9`.

## The isolation unit is the project directory

Each `phantom init` creates a vault namespace keyed to the **canonical path** of
that checkout (`PhantomConfig::project_id_from_path`). Two repositories never
share a namespace, even when they use the same variable name such as
`OPENAI_API_KEY`. The committed `.phantom.toml` holds only a portable
`project_id` and `phm_` placeholders; it never contains values.

Practical consequence: lay your checkouts out by owner and protect each one.

```text
~/code/personal/...      # your own projects
~/code/company/...       # your company
~/code/clients/<client>/ # one directory tree per client
```

```bash
# Preview, then protect every repo with a .env under one owner's tree
phantom init --all ~/code/clients/example-client --dry-run
phantom init --all ~/code/clients/example-client
```

Run `--all` per owner tree rather than once over `~/code`, so a review of the
dry-run output covers exactly one client at a time.

## Sharing a key deliberately

Reuse across projects is explicit and one-directional:

```bash
cd ~/code/company/api
phantom copy STRIPE_SECRET_KEY --to ../billing-worker
phantom copy OPENAI_API_KEY --to ../evals --rename OPENAI_API_KEY_EVALS
```

`copy` never overwrites a name the target already owns. There is no implicit
"global" key: never copy a client's key into a personal or company project.

## Checking what a project can reach

```bash
phantom list            # names only, never values
phantom status --json   # value-free metadata, safe for agents and CI logs
phantom why OPENAI_API_KEY
```

Agents connected through `phantom setup --client <client>` see the same
value-blind inventory for the project they are opened in, and nothing else.

## Moving a client off your machine

When an engagement ends, remove that client's secrets project by project from a
trusted terminal (`phantom remove NAME` asks for an exact challenge), then
rotate the credentials at the vendor. Phantom `v0.7.9` does not call provider
rotation APIs; see [Rotating real provider credentials](../README.md#rotating-real-provider-credentials).

## Not yet available

- Named environment scopes (`dev`/`staging`/`prod`) inside one project exist in
  `phantom-core` but are not exposed as CLI commands in `v0.7.9`.
- There is no owner/tenant label on a project; separation relies on directory
  layout. See [ROADMAP.md](../ROADMAP.md) for planned work.
