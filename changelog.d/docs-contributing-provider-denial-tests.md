### Changed (docs)

- The provider hard-denial checks in CONTRIBUTING.md now also list
  `grant_add_denial_test`, which proves `phantom grant add` refuses before it
  reads the client-secret environment variable or touches project state, and
  `rotate_provider_test`, which covers `phantom rotate --provider` failing
  closed. A contributor who changes a grant or rotation path now sees every
  test that guards it.
