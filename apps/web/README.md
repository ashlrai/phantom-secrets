# Phantom web

## SEO observation

From the repository root, run the read-only public observer with a new output
path (the report is created exclusively with mode `0600`):

```sh
node scripts/seo/observe.mjs --out seo/reports/observation.json
```

The observer checks the public site and public GitHub repository and release
API; it does not publish or change the site. It prints a Markdown summary and
writes a JSON report. Use `--summary <path>` to append the summary to a file.
An existing report path is never overwritten. The command exits with status 1
for a `FAIL` verdict or if it cannot write the report. Use a fresh output name
for each run.

The JSON report uses `schema_version` (`phantom-seo-observation-v1`),
`captured_at` (UTC), and `scope` to identify the observation. `verdict` is
`FAIL` if there are failures, `WARN` if there are warnings but no failures,
and `PASS` otherwise; `counts` contains the number of each. Each entry in
`findings` has a `severity`, `code`, and `message`, plus `route` when the
finding applies to a route. The Markdown summary shows these counts and
findings, external-data states, and experiment statuses; it may truncate findings
and reports the omitted count. The JSON report retains the complete findings.

`technical.sitemap` contains its HTTP `status` and `route_count`;
`technical.robots` contains its HTTP `status`. `technical.public_routes`
contains one record per sitemap path. For HTML responses the record includes:

| Field | Meaning and missing values |
| --- | --- |
| `route`, `status`, `content_type` | Sitemap path, HTTP status, and response content type; a missing content-type header appears as `""`. |
| `title` | Cleaned page title; `null` if the tag is absent and `""` if it cleans to empty. Either produces `title_missing`. |
| `description` | Cleaned meta description; `null` if absent or its content is empty, and `""` if whitespace-only content cleans to empty. Either produces `description_missing`. |
| `canonical` | Normalized same-origin URL for the route, only when exactly one nonempty canonical href matches it; otherwise `null`. `canonical_count` reports zero or multiple hrefs; `canonical_mismatch` reports a single nonmatching href. |
| `h1_count` | Number of opening H1 tags; a value other than one produces `h1_count`. |
| `structured_data_types` | Sorted JSON-LD types found in valid parsed data; `[]` means no types were found. Invalid JSON-LD also produces `structured_data_invalid`. Raw JSON-LD is not included in route records. |

A `.txt` route instead has `route`, `status`, `content_type`, and `text_length`;
its body is omitted. Other non-HTML responses have `skipped: "non_html"` and
receive a status check, not HTML metadata checks. A request failure has
`status: null` and `error: "request_failed"`; metadata fields are absent, not
reported as missing. `technical.operational` records health and readiness HTTP
statuses, or the same null status and error on request failure.

`github` is `state: "observed"` with star and fork counts, latest release tag,
immutability, and publication time when both public API responses are usable;
a missing publication time is `null`. Otherwise it is `state: "unavailable"`
with a warning, not zero counts. `experiments` includes the validated ledger and
an `observed_status` for each experiment; this derived status does not change the
ledger. `aggregate_inputs` reports `gsc`, `ga4`, and `ahrefs` as `not_supplied`
or `supplied` with their validated period and rows. GA4 also reports
`suppressed_rows` for cohorts under 10 sessions. Optional input files can be
passed with `--gsc-file`, `--ga4-file`, and `--ahrefs-file`; `--experiments`
overrides the default `seo/experiments.json` ledger.

If the observer fails before completing the public-surface report, it writes a
fail-closed report with `observer_execution_failed`, null sitemap and robots
statuses, zero routes, and unavailable or not-supplied states. Those defaults
are not evidence that the site has no routes or analytics.

See the [SEO observation loop](../../docs/seo-observation-loop.md) for the
input schemas, privacy boundaries, and operational workflow.
