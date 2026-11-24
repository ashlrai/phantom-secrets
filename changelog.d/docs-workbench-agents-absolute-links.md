### Fixed (workbench agent quickstart links work on GitHub)

- `docs/workbench-agents.md` linked the documentation manifest, the two
  workbench `llms` files, and the Markdown install guide with site-root paths
  such as `/docs/manifest.json`, which resolve against the repository on
  GitHub and 404. They now use the absolute `https://phm.dev` URLs, which work
  on GitHub and on the phm.dev docs page.
