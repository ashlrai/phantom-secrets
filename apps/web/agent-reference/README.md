# Agent reference generation

Run `npm run generate:agents` from `apps/web`, then `npm run check:agents`.
The generator is credential-free and runs without network access.

- `README.md` at the repository root supplies the product explanation and section index.
- `docs-catalog.json` selects first-party documents. Their Markdown headings generate the canonical guide index and section anchors.
- `Cargo.toml` supplies the source version, license, and workspace crate count.
- `compact.md` and `full.md` preserve the reviewed public site's bounded command, release, and authority guidance. Edit these source narratives when behavior changes.
- `src/app/sitemap.ts` and `docs-catalog.json` supply the repository sitemap mirror.

Both main `llms` files in `public/` are mirrored byte-for-byte into `docs/`.
Generation normalizes em dash punctuation and maps published guide links to their canonical `phm.dev/docs` routes. It does not refresh publication evidence or inspect credentials.

The source narratives record the older September 29 Homebrew snapshot and the site's October 6 snapshot explicitly. Neither date is advanced by regeneration. Workbench-specific references remain owned by the separate workbench documentation contract.

## Verify a change

From `apps/web`, run the existing build and the rendered contract explicitly:

```sh
HOME=$(mktemp -d) npm run check:agents
HOME=$(mktemp -d) npm test
HOME=$(mktemp -d) npm run typecheck
HOME=$(mktemp -d) npm run lint
HOME=$(mktemp -d) npm run build
HOME=$(mktemp -d) npm run test:discoverability
```

The regular test command checks generation and the Markdown renderer without
requiring a prior build. The discoverability command requires `.next` output
and parses the production HTML, JSON-LD, and sitemap XML. It covers every
public indexable source page and every catalog guide, including heading
anchors. Account and authorization pages deliberately remain outside public
discovery. No server, credentials, or external listings are needed for these
checks.
