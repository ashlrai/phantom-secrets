### Removed (stray agent write-probe at the repository root)

- Removed `.test_write.tmp`, an empty file an agent created to test write
  access, which a bridge commit added at the repository root. `.gitignore`
  already excludes it, so it was the only tracked file the ignore rules
  exclude (`git ls-files -ci --exclude-standard` now prints nothing).
  Nothing referenced it.
