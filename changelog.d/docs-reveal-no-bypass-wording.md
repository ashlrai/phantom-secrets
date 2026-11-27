### Fixed (docs: reveal has no non-interactive default)

- `docs/getting-started.md` and the site `llms-full.txt` said `phantom reveal`
  is "blocked in non-interactive contexts by default", which implies a way to
  turn the block off. There is none: reveal needs an attached terminal and the
  exact typed confirmation, as the README and `docs/llms-full.txt` already say.
