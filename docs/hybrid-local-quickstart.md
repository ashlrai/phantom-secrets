# Quickstart: local Qwen on Ollama behind LiteLLM, plus a frontier model

A tested path for hybrid use: a local model for high-volume loops, and a frontier model for planning and merges. Everything listens on `127.0.0.1` only.

What was actually run (Oct 25 2026, Linux x86_64, no GPU): Ollama 0.40.11, LiteLLM 1.103.5 in a fresh virtualenv, and the small model `Qwen/Qwen3-0.6B-GGUF` (Q8_0, 639 MB) as a stand-in. That model only proves the wiring. For real work use the larger tags in phantom's [LOCAL-INFERENCE.md](https://github.com/ashlrai/phantom/blob/master/docs/LOCAL-INFERENCE.md) (for example `qwen3.8:27b`). The frontier step at the end was not exercised.

## 1. Ollama on loopback

```bash
OLLAMA_HOST=127.0.0.1:11434 ollama serve
ollama pull qwen3.8:27b        # recommended; on the test box we used the small model below instead
```

On the test box `ollama pull` could not reach Ollama's download host, so the small model was loaded from Hugging Face instead:

```bash
curl -L -o qwen3-0.6b-q8_0.gguf \
  https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q8_0.gguf
printf 'FROM ./qwen3-0.6b-q8_0.gguf\n' > Modelfile
ollama create qwen3-0.6b-local -f Modelfile
```

Check it answers on Ollama's OpenAI-compatible API (no key):

```bash
curl -s http://127.0.0.1:11434/v1/models
curl -s http://127.0.0.1:11434/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"qwen3-0.6b-local","messages":[{"role":"user","content":"Reply with the single word: pong /no_think"}],"max_tokens":30}'
```

Observed: the model listed as `qwen3-0.6b-local:latest`, and the reply content was `pong`.

## 2. LiteLLM in front, on loopback

Install a pinned LiteLLM (see "Pin and verify LiteLLM first" in [litellm.md](litellm.md)):

```bash
python3 -m venv llvenv && llvenv/bin/pip install 'litellm[proxy]==1.103.5'
```

`local.yaml`:

```yaml
model_list:
  - model_name: local-coder
    litellm_params:
      model: ollama_chat/qwen3-0.6b-local   # use ollama_chat/qwen3.8:27b for real work
      api_base: http://127.0.0.1:11434

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  allow_client_side_credentials: false
```

Start it with a minimal environment, so it sees no provider keys:

```bash
env -i PATH=/usr/bin:/bin HOME="$PWD/llhome" LITELLM_MASTER_KEY=sk-<your own random value> \
  llvenv/bin/litellm --config local.yaml --host 127.0.0.1 --port 4000
```

Call it with the master key:

```bash
curl -s http://127.0.0.1:4000/v1/models -H "Authorization: Bearer $LITELLM_MASTER_KEY"
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"local-coder","messages":[{"role":"user","content":"Reply with the single word: pong /no_think"}],"max_tokens":30}'
```

Observed: `/v1/models` listed `local-coder`, and the reply content was `pong`. Requests with no key or a wrong key were refused (in this setup without a database, LiteLLM answered 500 and 400 rather than 401).

## 3. Frontier model (not exercised)

To add a hosted model to the same LiteLLM, follow the Quickstart in [litellm.md](litellm.md): add a `gpt-gateway` entry that reads `OPENAI_BASE_URL` and `OPENAI_API_KEY` from the environment, and start LiteLLM under `phantom exec` so it only ever sees a `phm_` placeholder and Phantom's local proxy injects the real key. This step was not run here; no provider key was used.

## Security notes

- Keep Ollama and LiteLLM on `127.0.0.1`. Local servers can log prompts, so keep `phm_` placeholders in prompts.
- Never give the local route a real provider key; it needs none.
- Phantom's own `localInference` config is not covered here yet. It is in review (phantom #917) and will be documented once it merges.
