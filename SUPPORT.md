# Support

Phantom is an open-source project with community support. This repository does
not promise paid support, priority response, uptime, or a contractual service
level. Hosted pilots and enterprise work require a separate written agreement.

## Choose the right channel

| Need | Channel |
|---|---|
| Setup, usage, or design question | [GitHub Discussions](https://github.com/ashlrai/phantom-secrets/discussions) |
| Reproducible defect | [Bug report](https://github.com/ashlrai/phantom-secrets/issues/new?template=bug_report.yml) |
| Feature or design proposal | [Feature request](https://github.com/ashlrai/phantom-secrets/issues/new?template=feature_request.yml) |
| Documentation problem | [Documentation report](https://github.com/ashlrai/phantom-secrets/issues/new?template=documentation.yml) |
| Suspected vulnerability | [Private vulnerability report](https://github.com/ashlrai/phantom-secrets/security/advisories/new) or [security@ashlr.ai](mailto:security@ashlr.ai) |
| Commissioned pilot or enterprise evaluation | [mason@ashlr.ai](mailto:mason@ashlr.ai) |

Do not put a vulnerability in a public issue or discussion. Follow the
[security policy](SECURITY.md) instead.

## Before asking for help

1. Check the [documentation map](docs/README.md) and
   [troubleshooting guide](docs/troubleshooting.md).
2. Record `phantom --version`, the installation method, operating system and
   architecture, shell, and the exact command that failed.
3. For a source build, include the full commit SHA and dirty state.
4. Include the smallest reproducible example and the result you expected.
5. Redact real credentials, cookies, device codes, vault contents, cloud
   tokens, and `phm_` mappings. Persistent mappings are sensitive metadata.

Release-state snapshot, verified 2026-09-02 before any `v0.7.5` publication:
the reviewed immutable GitHub/Homebrew distribution is `v0.7.4`. Both npm
`0.7.4` wrappers remain public only under the failed `release-candidate` track,
and npm `latest` remains `0.6.0`. Repository source is versioned for the
then-unpublished `0.7.5` fix-forward; source, CI configuration, or a changelog section
is not proof that a `0.7.5` artifact, package, deployment, provider integration,
or hosted entitlement has been released or commissioned.

## Response expectations

Community questions and public issues are handled as maintainer availability
allows. Security reports use the non-contractual response targets in
[SECURITY.md](SECURITY.md). A written commercial agreement, if any, is the only
source for customer-specific support scope and service terms.
