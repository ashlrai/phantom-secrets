# phm.dev: editing the public site as an agent

This directory is the Next.js source of `https://phm.dev`. Phantom (the
engineering workbench) is at `/`; Phantom Secrets is at `/secrets`. Both routes
must keep working, and the host website publisher refuses a build where either
fails its route contract.

## The path from a change to production

1. **Branch.** Work on your own branch. Never push to `main` or to another
   agent's branch.
2. **Edit.** Keep each change to one purpose. Public copy must match shipped
   behavior: cite the source file or command that backs any claim about a
   command, flag, tool count, version, platform or provider capability.
3. **Preview check.** From `apps/web`, after `npm ci`:

   ```sh
   npm run preview:check
   ```

   This runs lint, typecheck and the tests, builds with a credential-free
   environment, serves the build on `127.0.0.1`, and checks:
   - `/` and `/secrets` against the publisher's route contract (200, HTML,
     canonical URL, required marker text) and the security headers;
   - `/install.sh` and `/install.ps1` still answer 410;
   - every sitemap page returns 200;
   - every internal link and `#anchor` on those pages resolves;
   - the shipped output (`.next/static`, prerendered pages, `public/`) holds no
     credential-shaped strings and no value of a credential-named environment
     variable.

   It writes `.next/phm-site-preview-receipt.json` with the exact commit, the
   step results and an output digest. Commit first: a dirty tree is recorded
   and cannot describe a commit. Preview a running page with `npm run build &&
   npm run start` (it binds to localhost).
4. **Draft PR.** Open a draft PR with the receipt's commit and results. CI runs
   the same verification after its production build (`npm run preview:verify`).
5. **Review and merge.** A human reviews and merges through the protected
   `main` branch with required checks.
6. **Promotion.** Only the host-owned website publisher in `ashlrai/phantom`
   deploys. It publishes an exact, normally merged `main` revision, and only when
   the operator has commissioned it and set it to Auto. An agent may request it
   with the `ashlr_website_publish` MCP tool, which carries the revision and
   nothing else. See `docs/RESIDENT-RUNTIME.md` ("Automatic public website
   publication") in that repository.

A passing preview receipt is local evidence. It is not CI admission, a merge, a
deployment or a promotion, and must not be described as one.

## Never

- Deploy from a workstation, call the Vercel CLI or API, or change domains,
  project settings or environment variables.
- Add credentials, account identifiers, private customer context or private
  hostnames to source, docs or `public/`.
- Change `src/lib/workbench-release.json` by hand. Refresh it only from the
  output of `phm release-articles metadata --json` on the host.
- Change installer pins in `src/lib/public-release.ts` or `public/install.*`
  outside a Secrets release.
- Remove the `/` or `/secrets` routes or the marker text the route contract
  checks (`scripts/site-preview-contract.mjs`). Changing the contract needs
  the matching change to `WEBSITE_PROFILE` in `ashlrai/phantom`.
- Document a native Codex, Claude or Grok capability unless its interface and
  account binding are verified in shipped source.

## Where things are

| Path | What |
|---|---|
| `src/app/page.tsx`, `src/components/landing/Workbench*.tsx` | Phantom workbench home (`/`) |
| `src/app/secrets/page.tsx` | Phantom Secrets (`/secrets`) |
| `docs-catalog.json`, `src/lib/public-docs.ts`, `../../docs/*.md` | Public docs at `/docs/<slug>` |
| `public/llms.txt`, `public/llms-full.txt` | Agent-readable summaries |
| `src/app/sitemap.ts` | Sitemap; update `modified` only when content changes |
| `tests/*.test.cjs` | Public claim, SEO, security and preview-contract tests |
| `scripts/site-preview*.mjs` | Preview check and its pure contract |
