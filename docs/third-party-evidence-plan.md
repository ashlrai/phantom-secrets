# Third-party evidence plan

## Goal

Make Phantom discoverable for the problem it actually solves by producing
credible, reproducible evidence outside Ashlr-owned pages. This is an adoption
plan, not permission to post, contact reviewers, publish packages, or make
claims on someone else's behalf.

## Principle

Search and AI retrieval systems can inspect first-party documentation, but
buyers also look for independent corroboration. Phantom should earn that
corroboration with reproducible tests and real user outcomes. It must not
manufacture Reddit consensus, testimonials, reviews, citations, directory
ratings, or comparison results.

## Phase 1: correct the entity footprint

1. Keep [the public fact sheet](./public-fact-sheet.md) aligned with the exact
   public release, install channels, and hard denials.
2. After a release is independently accepted, update official GitHub, Homebrew,
   npm, crates.io, and MCP Registry records as separate publication steps.
3. Prepare factual correction requests for directory pages that show stale
   versions, unsupported installation commands, obsolete pricing, or absolute
   security claims. Ask only for accuracy and link to primary evidence.
4. Record the page URL, observed claim, source used for correction, outreach
   owner, send approval, response, and verified final state.

## Phase 2: publish a reproducible benchmark

Create a public, deterministic test corpus for one narrow workflow:

- one exact Phantom release and source digest;
- one OS and client per result row;
- synthetic credentials with canary markers;
- agent-visible prompt, tools, environment, files, logs, and outputs captured
  without publishing real credentials;
- expected exact-route successes and unsupported-route denials;
- same-user, stolen-bearer, provider-response, and unmanaged-file limitations;
  and
- a value-free machine-readable receipt for every run.

Invite an independent security engineer to choose additional adversarial cases,
run the harness, preserve negative findings, and publish on a domain or
repository they control. Disclose payment and do not condition it on outcome.

## Phase 3: three real pilot case studies

Recruit three teams using owned, non-production repositories. Each case study
should record:

- exact OS, coding client, Phantom release, vault backend, and provider route;
- time from install to one successful bounded API request;
- whether the managed credential appeared in agent-visible artifacts;
- setup failures, unsupported workflows, and recovery steps;
- repeat use after seven days; and
- whether the participant was compensated.

Prefer a participant-authored post, public repository, or jointly published
report on a participant-controlled domain. A quote on phm.dev is first-party
marketing unless the underlying evidence is independently inspectable.

## Phase 4: category education

Publish a small number of durable, query-specific resources:

- protecting API keys from AI coding agents;
- value-blind MCP secret management;
- exact-route credential injection versus plaintext dotenv access; and
- a versioned, primary-source comparison only after a reproducible methodology
  exists.

Every resource must answer the query directly, include one executable workflow,
identify its release, link proof, state limits, and end with one next action.
Do not generate thin client, city, industry, or competitor pages.

## Measurement

Measure outcomes rather than content volume:

- installation to `phantom agent doctor` success;
- installation to one bounded real API request;
- seven-day repeat use;
- indexed canonical pages and non-brand query impressions;
- independent domains with current, accurate Phantom evidence;
- factual directory corrections completed; and
- coarse allowlisted referral class: ChatGPT, GitHub, Google, Bing, other, or
  direct.

Do not retain prompts, search queries, secret names, commands, full referrers,
or user-identifying paths for acquisition analytics.

## Human gates

The founder must approve external sends, package publication, registry updates,
paid reviews, named case studies, testimonials, and any customer-identifying
material. A prepared plan or draft is not evidence that outreach occurred.
