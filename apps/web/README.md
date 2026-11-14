# Phantom web

## Local SEO observation

From the repository root, run the credential-free observer with Node.js 22 and
network access to `https://phm.dev` and the public GitHub API:

```sh
node scripts/seo/observe.mjs --experiments seo/experiments.json --out seo/reports/observation.json
```

The checked-in experiment ledger is the input; `--experiments` defaults to
that path relative to the working directory. No provider credentials or
analytics files are required. This command observes the deployed public site,
not a local web server, and does not publish or change the experiment ledger.

The sanitized JSON report appears at `seo/reports/observation.json` and a
Markdown summary is printed to the terminal. The report directory is ignored
by Git. The observer creates the report with mode `0600` and refuses to
overwrite an existing file, so choose a new `--out` path for each run. A
`FAIL` verdict exits with status 1.

Optional `--gsc-file`, `--ga4-file`, and `--ahrefs-file` arguments accept local
aggregate JSON inputs; `--summary <path>` appends the Markdown summary to a
file. See [the observation loop](../../docs/seo-observation-loop.md) for input
schemas, privacy constraints, and interpretation.
