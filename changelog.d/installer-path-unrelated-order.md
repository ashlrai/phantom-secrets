### Added (Unix installer PATH-update tests)

- `installer-path-unrelated-order` now covers two more order shapes: the same
  unrelated lines written reversed, so "original relative order" is proven to
  be the file's own rather than the fixture's, and a repeat update over a
  startup file whose managed block already has unrelated lines below it.
- New `installer-path-unrelated-order-integration` drives the complete
  offline installer — download, checksum verification, archive validation,
  promotion, and the PATH update — over order-sensitive bash, zsh, and fish
  startup files for both installer copies and asserts every unrelated line
  keeps its original relative order. It is wired into the direct-installer
  CI step, and its release fixture packs a compiled shim binary (matching
  real Mach-O/ELF release members) so it can also run on hosts where script
  fixtures cannot exec.
