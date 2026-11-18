# Phantom web

This directory is the Next.js source for [phm.dev](https://phm.dev), the public
website for Phantom and Phantom Secrets. It serves the landing pages, the
rendered docs, the `llms.txt` files and install scripts, and the hosted
dashboard, device-login, and API routes used by Phantom Cloud features.

## Where it fits

Phantom Secrets is one of the open-source tools from [Ashlr](https://ashlr.ai).
Together they aim to be an autonomous, code-first, agent-native software
factory: agents write, test, review, and ship the code, and the human acts as a
passive board member. The long-term goal is open-source recursive
self-improvement (RSI). The full tool list (Phantom, Phantom Secrets, Locus,
Lexicon, Ashlr MD, Ashlr Stack, and ashlr-plugin) is in the root README's
[ecosystem section](../../README.md#part-of-the-ashlr-ecosystem). The site shows
the same list in `src/components/landing/AshlrEcosystem.tsx`, and
`tests/ashlr-ecosystem.test.cjs` fails if the two drift apart.

## Layout

| Path | What it holds |
| --- | --- |
| `src/app/page.tsx` | Home page for the Phantom workbench and ecosystem |
| `src/app/secrets/` | Phantom Secrets landing page and use-case pages |
| `src/app/docs/` | Docs index and `/docs/<slug>` pages, rendered from `../../docs/*.md` |
| `docs-catalog.json` | Which repo docs are published under `/docs/<slug>` |
| `docs-routes.json` | Older `/docs` paths that redirect to the Markdown on GitHub |
| `ecosystem-repos.json` | Public `ashlrai` repos counted in the site's star total |
| `src/app/dashboard/`, `src/app/device/`, `src/app/api/` | Hosted account, device-code login, and `/api/v1` routes |
| `public/` | `llms.txt`, `llms-full.txt`, `install.sh`, `install.ps1`, and static assets |
| `supabase/` | Database config and migrations for the hosted routes |

To publish another doc, add the Markdown file under the repo's `docs/`, then add
it to `docs-catalog.json` and the imports in `src/lib/public-docs.ts`.

## Run it

Use Node.js 22, which is the version CI uses.

```sh
cd apps/web
npm ci
npm run dev
```

The dev server listens on `http://localhost:3000` by default. The hosted
dashboard, login, billing, and analytics code reads the variables named in
`.env.local.example`; copy it to `.env.local` and fill in only what you need.

## How agents work on it

Coding agents make most changes here through pull requests, like any
contributor. Follow the root [AGENTS.md](../../AGENTS.md) and
[CONTRIBUTING.md](../../CONTRIBUTING.md). CI runs these steps from this
directory, so run them before you open a pull request:

```sh
npm run lint
npm test
npm run build
```

Keep page copy in line with the CLI. From the repo root,
`cargo test --locked -p phantom-secrets --test docs_command_flags_test` checks
documented `phantom` commands in the web sources and `llms*.txt` against the
CLI help. `npm run test:claims` checks public claims on the site.

## Tests

Run `npm ci` and `npm test` from this directory. The install-command syntax
tests require Bash and PowerShell (`pwsh`) on PATH; they parse commands without
running them.

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
