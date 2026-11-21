### Fixed (docs)

- The `Source secret scan` note in CONTRIBUTING.md's "Reproduce the pull
  request jobs locally" section again says what to do when the history scan
  finds a token you committed and then deleted: remove it from your branch
  history and force-push the branch, never `main`. An earlier edit had split
  that instruction from the sentence it referred to. The note now also says to
  rotate a real credential that reached a pushed commit, and it is split into
  separate paragraphs for the CI behavior and the local fork and shallow-clone
  caveats.
