### Fixed (versioned JSON keeps the durability warning)

- `phantom env --json` and `phantom add NAME --generate --json` now include
  `durability_verified` and `warnings` on `env.v1` and `add.v1`. A verified
  write whose directory crash durability is not provable sets
  `durability_verified` to false and puts the warning text in `warnings`,
  instead of dropping it. Stderr stays empty for those two commands.
- `phantom audit path --json` is unchanged and still prints a durability
  warning on stderr, because `audit.path.v1` has no durability field.
