### Changed (docs: what the Secret-shape scan blocks)

- CONTRIBUTING.md now says what the required `Secret-shape scan` blocks, as
  `scrub.pl` implements it: provider token shapes, PEM private-key blocks, and
  a password inside a URL. It states the scanner's real output
  (`<blocked> allowed=<n>`), that it also reads unchanged context lines, that
  the fixture allowance never covers docs or PEM blocks, and how to find a
  match locally without printing it.
