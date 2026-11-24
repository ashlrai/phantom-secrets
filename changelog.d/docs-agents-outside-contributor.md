### Changed (agent instructions cover agents working from a fork)

- `AGENTS.md` has a new "Agents working for an outside contributor" section.
  Article 1 grants merge rights and names a `publish.sh` push wrapper that
  only the Ashlr fleet's own agents have; the new section tells an agent
  working from a fork to push with plain `git push`, open a pull request, and
  rely on `CI Gate` and the merge queue, with the security floor unchanged.
- "Contribute with an agent" in `CONTRIBUTING.md` now shows the push command
  and says that `publish.sh` is not part of this repository.
