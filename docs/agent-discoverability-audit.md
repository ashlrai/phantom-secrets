# Agent discoverability audit

This audit covers the public Phantom Secrets site in `apps/web` for
`RQ-DISC-SITE-PS`, starting at commit
`3d062e9e386b4dfb9ed39d3fa464e0213b890c59` on 2026-10-26.
It measures source and local verification, not a production deployment.

## Rubric availability

The requested `RQ-DISC-READINESS-SCORER` rubric at
`phantom/docs/AGENT-READINESS.md` was unavailable locally. A bounded recursive
search for the exact job identifier and filename across the local Ashlr
workspace, excluding Git internals, dependencies,
build outputs, and lockfiles, returned no matches. The sibling `phantom`
checkout also had no local Git history for that path.

The following is a **provisional, acceptance-derived rubric**, not the missing
queue rubric. Each criterion receives one point only when supported by the
stated evidence. A zero marked unverified means no qualifying evidence was
collected, not that the behavior is necessarily broken. Before and after must
use the same criteria. An official readiness score remains unavailable until
the requested rubric can be supplied.

## Before and after

| Criterion | Before | After | Before evidence |
| --- | ---: | ---: | --- |
| SoftwareApplication includes source-consistent name, version, license, repository, OS, and a truthful free-core offer | 1 | 1 | `LandingStructuredData.tsx` already supplies these fields; version agrees with `Cargo.toml`. |
| Public pages provide descriptions and OpenGraph metadata | 1 | 1 | Public route metadata and `docs/[slug]/page.tsx` define descriptions and social fields. |
| Public docs have a single designated canonical URL per page | 1 | 1 | `docs/[slug]/page.tsx` uses `/docs/${doc.slug}`; markdown responses refer to the same canonical. Rendered uniqueness is covered separately below. |
| Rendered public pages have exactly one canonical, one h1, and ordered semantic headings | 0 | 1 | Unverified: existing tests inspect source patterns rather than every rendered public page. |
| Compact LLM index is reproducibly generated from README and published docs headings | 0 | 1 | Four independently maintained root LLM references contain prose; no source-heading generator exists. |
| Site and docs LLM references stay identical through a drift check | 0 | 1 | `apps/web/public/llms*.txt` and `docs/llms*.txt` differ, including installation and MCP setup statements. |
| A dedicated capabilities and installation page links supported setup and explicit limits | 0 | 1 | Installation sections exist on the landing page, but no dedicated combined page exists. |
| Acceptance tests parse JSON-LD and LLM references and validate sitemap XML | 0 | 1 | Existing SEO tests use source assertions; no combined parsed output contract exists. |
| Existing site build, typecheck, lint, and applicable tests pass with temporary HOME | 0 | 0 (unverified) | Unverified at the initial source audit; these commands must run for the final change. |
| Agent guidance distinguishes local capabilities from hosted services and authority | 1 | 1 | README project status and trust boundary, public pricing, and the existing LLM references describe local scope and separate hosted commissioning. |
| **Total** | **4/10** | **9/10** | Provisional source and verification score only. |

No score in this document establishes live service commissioning, registry
publication, or customer acceptance. The official queue rubric remains
unavailable regardless of the provisional result.

## After evidence

The implementation was reviewed independently for source facts, authority
boundaries, semantic structure, and acceptance-test coverage. The execution
owner reported the following local results with temporary HOME directories;
`BRIDGE_NOTES.md` records the final commands and outcomes.

- `npm run build`: passed, producing 68 routes with the existing `next build`
  command. `npm run typecheck` and `npm run lint` passed.
- `npm run test:discoverability`: 33 passed, zero failed. This parses built
  HTML for all 27 public indexable pages, including all 19 catalog guides,
  and checks one canonical, one h1, heading order, description, and
  OpenGraph metadata. It parses the actual JSON-LD and compares Secrets
  identity to `Cargo.toml` and `LICENSE`, validates sitemap XML and mirror
  equality, and verifies LLM document links against rendered heading IDs.
- `node --test tests/llms-generation.test.cjs`: five passed, zero failed.
  Generation is deterministic, ignores fenced code when extracting headings,
  includes README prose and canonical docs headings, and rejects stale
  mirrored files. The earlier combined focused suite passed 68 of 68 tests.
- `/secrets/capabilities` passed desktop checks at 1512 pixels and mobile
  checks at 390 pixels: no horizontal overflow, zero console errors,
  working section anchors, and working mobile menu and Escape dismissal.
  The docs light-theme text contrast issue found during review was corrected.
- Source guidance now separates the free local CLI from hosted services and
  provider authority, and qualifies pinned release behavior separately from
  newer source capabilities.

The public-page scope excludes `/dashboard`, `/device`, and `/integrations`
account or authorization flows. Those routes are intentionally noindex and
are not public discovery targets.

The first full `npm test` run reported 253 passed, zero failed, and one
cancelled test: the existing two-build fixture reached its unchanged
600-second timeout while other builds ran concurrently. No assertions or
timeouts were weakened. The full-suite retry without a competing build
reported 254 passed, zero failed, one cancelled, and zero skipped, again
exceeding that fixture timeout under heavy host load. The combined
build/typecheck/lint/test criterion therefore has not received its point;
see commands and logs in `BRIDGE_NOTES.md`.

## Source facts and existing drift

- `Cargo.toml` workspace package declares version `0.7.9`, license `MIT`, and
  repository `https://github.com/ashlrai/phantom-secrets`.
- `LICENSE`, README's local-first MIT description, and `apps/web/src/app/pricing/page.tsx`
  support a free local CLI offer. This does not make enterprise services or
  separately commissioned hosted plans free or available.
- The immutable GitHub installation identity comes from
  `apps/web/src/lib/public-release.ts`. Source version and published release
  identity are separate concepts and should not be silently conflated.
- The site root describes the Phantom workbench. Phantom Secrets lives at
  `/secrets`; its executable is `phantom`, while the workbench uses `phm`.
- Before regeneration, `docs/llms.txt` says Claude setup writes
  `.claude/settings.local.json`; current site guidance describes MCP
  registration in `.mcp.json` with separate permission hardening.
- Before regeneration, `docs/llms.txt` advertises a Gemini setup writer
  without separating source from the pinned release. The immutable
  `v0.7.9` source at `7a51ce512ec4aee12cc29ff859036af63fbe93db` has no
  Gemini writer in `crates/phantom-cli/src/commands/setup.rs`. The current
  checkout implements `Client::Gemini`, `setup_gemini`, and its setup plan.
  The release guide must distinguish that newer source capability from the
  pinned release's status-only Gemini support.
- `docs/getting-started.md` retains a dated 2026-09-29 registry snapshot,
  while README and site references carry later publication statements.
  Prefer exact immutable GitHub installation guidance; generation alone
  does not turn dated upstream prose into current registry evidence.

## Delivery boundary

The explicit job rules prohibit committing, pushing, publishing, new public
listings, and changes to `.github`, CODEOWNERS, or release/publish configuration.
The implementation and verification therefore remain uncommitted in this
worktree. The future PR body should carry both the provisional before/after
scores and the missing-official-rubric caveat. Deployment remains the existing
merge-to-main path.
