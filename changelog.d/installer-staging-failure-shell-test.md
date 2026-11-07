### Added (Unix installer staging tests)

- A node-free `installer-staging-failure.test.sh` leg runs the shipped
  `scripts/install.sh` end-to-end under `env -i` while PATH shims make each
  staging-creation step fail in turn — `mktemp -d` refusing the private
  template, `chmod 700` failing on the created stage, the staging
  subdirectories failing halfway, and `mktemp` reporting success for a
  directory that does not exist. Every run must exit nonzero before any
  download, leave a preexisting destination byte-for-byte intact, and
  release the install lock with no stage, backup, or lock sibling left
  beside the destination.
