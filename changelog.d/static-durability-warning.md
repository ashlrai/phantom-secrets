### Security (env.v1 durability warning stays path-free)

- `phantom env --json` puts a fixed sentence in `warnings` when directory
  crash durability is not provable. The example filename stays in `output`
  and is not copied into that sentence.
