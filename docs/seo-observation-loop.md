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

## The sanitized JSON report

`--out` writes one JSON document (`schema_version`
`phantom-seo-observation-v1`) containing `captured_at` (UTC), `scope`
(`site_origin`, `repository`, and `network_policy`), `verdict`, `counts`,
`technical`, `github`, `experiments`, `aggregate_inputs`, and `findings`.
`verdict` is `FAIL` when `counts.fail` is nonzero, `WARN` when only
`counts.warn` is nonzero, and `PASS` otherwise. `findings` is deterministically
sorted by severity, code, route, and message; each entry carries `severity`
(`fail` or `warn`), `code`, `message`, and `route` when it applies to one.
The Markdown summary shows the verdict, route count, capture time, finding
counts, external-data states, and per-experiment `observed_status`; it may
truncate findings under its byte budget and reports the omitted count, while
the JSON report always retains the complete findings. The report file is
created exclusively with mode `0600` and an existing path is never
overwritten; the command exits with status 1 for a `FAIL` verdict or when it
cannot write the report.

`technical.sitemap` records the sitemap HTTP `status` and `route_count`;
`technical.robots` records its HTTP `status`. `technical.public_routes` holds
one record per sitemap path:

| Record | Fields |
| --- | --- |
| HTML page | `route`, `status`, `content_type`, `title`, `description`, `canonical`, `h1_count`, `structured_data_types` |
| `.txt` route | `route`, `status`, `content_type`, `text_length`; the body is omitted |
| Other non-HTML | `route`, `status`, `content_type`, `skipped: "non_html"`; only the status check applies |
| Request failure | `route`, `status: null`, `error: "request_failed"` plus a `public_route_unreachable` finding; metadata fields are absent rather than reported missing |

`content_type` is the response header, or `""` when absent. For HTML,
`title` is the cleaned `<title>` text: `null` when the tag is absent and `""`
when it cleans to empty; both produce `title_missing`. `description` is the
cleaned content of the first `meta name="description"`: `null` when the tag
or its content is absent or empty, and `""` when whitespace-only content
cleans to empty; both produce `description_missing`. `canonical` is the
normalized absolute URL of the route only when exactly one nonempty canonical
href is present and it matches the same origin and path without query or
hash; otherwise `null`. `canonical_count` reports zero or multiple hrefs and
`canonical_mismatch` a single nonmatching href. `h1_count` counts opening H1
tags; any value other than one produces the `h1_count` finding.
`structured_data_types` lists the sorted unique `@type` values collected from
parseable JSON-LD (`[]` when none); invalid JSON-LD produces
`structured_data_invalid`, and raw JSON-LD never appears in the route record.

`technical.operational` records `health` and `ready` HTTP statuses, or
`status: null` with `error: "request_failed"` when a fetch fails.

`github` is `state: "observed"` with `stargazers`, `forks`,
`latest_release`, `latest_release_immutable`, and `release_published_at`
(`null` when GitHub omits it) when both public API responses are usable;
otherwise it is `state: "unavailable"` with a `github_public_api_unavailable`
warning rather than zero counts.

`experiments` echoes the validated ledger and adds `observed_status` to each
entry: `implemented` and `observing` entries report `observing` until their
`not_before` instant and `ready_for_review` after it; every other status is
reported unchanged. The derived status never rewrites the ledger.
`aggregate_inputs` reports each of `gsc`, `ga4`, and `ahrefs` as
`{ "state": "not_supplied" }` or as `supplied` with the validated
`schema_version`, `period`, and sorted `rows`; supplied GA4 input also reports
`suppressed_rows`, the count of cohorts under ten sessions that were dropped.

If the observer fails before completing the public-surface report, it still
writes a fail-closed report: `verdict` `FAIL` with a single
`observer_execution_failed` finding, null sitemap and robots statuses, zero
routes, empty operational data, `github` `state: "unavailable"`, an empty
experiment ledger, and not-supplied aggregates. Those defaults are not
evidence that the site has no routes or analytics.

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
