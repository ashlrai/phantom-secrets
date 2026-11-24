### Fixed (docs: provider hard-denial is current, not a 0.7.9 claim)

- The grants specification, architecture, platform support, audit index,
  delegation FAQ, multi-project keys guide, and `docs/llms-full.txt` no longer
  say provider issuance, enrollment, rotation, and remote revocation are
  hard-denied "in 0.7.9". The source still hard-denies them before credential
  access and network I/O, so these docs now describe current releases.
