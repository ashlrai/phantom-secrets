# LiteLLM behind Phantom (experimental)

Value-free example. See [docs/litellm.md](../../docs/litellm.md) for pinning, rules and exactly what was tested.

- `config.yaml`: LiteLLM config that reads the Phantom base URL and `phm_` placeholder from the environment.
- `mock_upstream.py`: OpenAI-compatible mock that records requests (127.0.0.1 only).
- `verify.py`: local smoke test (LiteLLM, Phantom proxy, mock). Needs `LITELLM_BIN` and cargo. Not run in CI. Exit 0 passed, 1 failed, 2 prerequisites missing.
