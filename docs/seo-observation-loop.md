# SEO and agent-discovery observation loop

Phantom treats search work as a monitored product experiment, not a content
autopilot. The repository can inspect public evidence, enforce a waiting
window, and prepare a review. It cannot publish content, change production,
contact anyone, open issues or pull requests, or decide that an experiment won.

## The loop

1. **Test.** Define one falsifiable hypothesis, one primary metric, the public
   routes in scope, an unchanged control cohort, and a baseline window. Avoid
   simultaneous changes that make attribution impossible.
2. **Implement.** Use the normal reviewed pull-request and deployment process.
   Record the exact merge commit and immutable deployment identifier in
   `seo/experiments.json`; a deployment claim is not inferred from source.
3. **Wait.** The default observation window is 28 days. Search effects can take
   weeks, so the observer reports `observing` until the experiment's explicit
   `not_before` time. Low-volume pages may need a longer window.
4. **Review.** Compare finalized post-period evidence with the baseline and
   control cohort. Record `accepted`, `reverted`, or `inconclusive` and a short
   bounded lesson only through a human-reviewed change.

The checked-in experiment ledger is the durable learning record. The observer
does not rewrite that ledger or train itself from noisy measurements.

Every experiment entry uses this closed field set: `id`, `hypothesis`,
`primary_metric`, `target_routes`, `control_routes`, `status`,
`baseline_start`, `baseline_end`, `implementation_sha`, `deployment_id`,
`implemented_at`, `not_before`, `decision_rule`, and `lesson`. Planned entries
use `null` for the four implementation fields and for `lesson`. Implemented
entries bind a lowercase 40-character commit, an immutable `dpl_` deployment
identifier, and UTC implementation/review instants. Only completed human
decisions may contain a lesson. Calendar dates and instants are round-trip
validated; an implemented experiment's complete baseline must end before its
implementation instant.

## What the credential-free observer measures

`node scripts/seo/observe.mjs --experiments seo/experiments.json --out <path>`
uses only Node.js built-ins. Its default network boundary is `https://phm.dev`
and the public GitHub API records for `ashlrai/phantom-secrets`.

Every logical request has one monotonic deadline shared by all of its retries
and redirects. The complete observation has a seven-minute monotonic budget,
leaving three minutes beneath the workflow timeout for runner and artifact
cleanup.

It checks:

- sitemap closure, public-route status, same-host self-canonicals, titles,
  descriptions, one primary heading, and parseable structured data;
- required homepage software, source-code, organization, installation, and FAQ
  schema plus article and breadcrumb schema on rendered guides;
- crawler policy, response security headers, machine-readable `llms` files,
  and provider-free health/readiness status;
- agreement between live public release metadata and GitHub's latest immutable
  release; and
- coarse public GitHub star and fork totals as adoption context, never proof of
  SEO causality.

The weekly/manual workflow has exact `contents: read` permission at both the
workflow and job levels. It creates one sanitized report with mode `0600` in
runner-temporary storage and uploads it as an artifact. The rendered job
summary is deterministically capped below GitHub's limit; if needed, it names
the number of omitted findings while the artifact retains the complete report.
The workflow has no credential input and no mutation or communication
permission.

## Optional aggregate inputs

An operator may supply local JSON files with `--gsc-file`, `--ga4-file`, or
`--ahrefs-file`. These adapters are validators, not provider connectors. Files
under `seo/private/` and reports under `seo/reports/` are ignored by Git.

The contracts are deliberately narrow:

- Search Console: finalized date/page aggregates containing clicks,
  impressions, CTR, and position. A final period contains only complete
  calendar days before the observation capture time. Raw search queries are
  rejected.
- GA4: public page paths with sessions, engaged sessions, engagement rate, key
  events, and an allowlisted coarse referral class. Rows below ten sessions are
  suppressed. Query-bearing URLs, full referrers, campaigns, and user or
  session identifiers are rejected.
- Ahrefs: public page paths with estimated organic traffic and referring-domain
  counts. Keyword lists and raw queries are rejected.

Each input has a closed top-level shape:

```json
{
  "schema_version": "phantom-seo-gsc-v1",
  "period": { "start": "YYYY-MM-DD", "end": "YYYY-MM-DD", "data_state": "final" },
  "rows": [
    {
      "page_path": "/docs",
      "brand_class": "nonbrand",
      "clicks": 0,
      "impressions": 0,
      "ctr": 0,
      "position": 0
    }
  ]
}
```

GA4 uses `phantom-seo-ga4-v1`; each row contains `page_path`, one of the
documented coarse `referral_class` values, `sessions`, `engaged_sessions`,
`engagement_rate`, and `key_events`. Ahrefs uses `phantom-seo-ahrefs-v1`; each
row contains `page_path`, `estimated_organic_traffic`, and
`referring_domains`. Unknown fields fail closed.

Only public paths present in the observed sitemap are accepted. Reports never
include input filenames or provider credentials.

## Metric interpretation

The preferred SEO primary metric is finalized, page-level non-brand
impressions or clicks. CTR and average position are secondary diagnostics.
GitHub star change and command-copy events are adoption signals but cannot, by
themselves, establish search attribution. Availability and freshness of
`llms.txt`, `llms-full.txt`, structured data, and rendered documentation are
agent-discovery prerequisites, not evidence that a model cited Phantom.

Search Console clicks and analytics sessions use different systems and should
not be expected to match exactly. A review should preserve negative findings,
consider sitewide or algorithmic changes, and return `inconclusive` when volume
or controls are inadequate.

## External commissioning remains separate

Search Console property verification, GA4 collection and consent, Ahrefs
access, paid tooling, analytics privacy notices, provider credentials, and
direct API connectors are not commissioned by this workflow. Any future
connector should use read-only access from a trusted terminal, aggregate before
writing, preserve the same closed schemas, and receive its own security and
privacy review.

External publishing, directory corrections, outreach, testimonials, paid
reviews, and customer-identifying case studies remain explicit founder gates.
