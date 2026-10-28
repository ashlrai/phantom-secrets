### Added (value-free secret requests)

- `phantom request <NAME> --purpose <text> [--route <route>]` reserves a
  pending secret and a stable `phm_` placeholder without opening the vault,
  prompting for a value, or calling a provider. A human or sanctioned
  producer fulfills it outside the agent with `phantom add`, which installs
  the reserved mapping and records the fulfillment receipt in one
  exact-before transaction. Repeating an identical request is idempotent;
  conflicting metadata is refused without mutating config.
- `phantom requests --json` lists request receipts (`phantom.requests.v1`)
  without vault access. Request metadata is validated on config load and
  invalid placeholders or routes are rejected without echoing their
  contents. See docs/secret-requests.md.
