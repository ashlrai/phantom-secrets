# Phantom North Star: Agent-Safe Secrets Control Plane

## Primary Promise
Delegate everything to AI without exposing real credentials.

## Core Product Object
Every project should progress through an Agent Readiness state:

- `unsafe`
- `protected`
- `verified`
- `team-ready`
- `compliance-ready`

## Hero Workflow
`phantom agent setup` detects repo shape, env files, AI tools, package scripts, service providers, cloud/team state, CI config, and platform targets, then applies safe defaults and ends with a signed readiness report.

## Strategic Wedge
Phantom should own context-safe secrets for AI agents. Traditional secret managers protect storage and transport; Phantom protects LLM context and agent runtime.

## Implementation Order
1. Security foundation and known claim cleanup.
2. Agent autopilot and unified policy.
3. Cloud, teams, and dashboard credibility.
4. Distribution, docs, and release trust.
5. Quality system for long-running agent swarms.

## Current Execution Slice
Start with proxy authentication hardening:

- Header-only auth by default.
- Redact printed proxy URLs.
- Keep query-token auth only behind an explicit compatibility switch and warnings.
