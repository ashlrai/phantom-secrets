#!/usr/bin/env python3
"""Local smoke test: LiteLLM -> Phantom proxy -> mock upstream.

Needs: a built litellm (LITELLM_BIN, installed from a pinned, safe version, see
docs/litellm.md) and cargo. No provider, no network, no real key. Everything
binds 127.0.0.1 on ephemeral ports. Not run in CI by default.

Asserts:
  1. the mock upstream received the stand-in real credential in Authorization
     (Phantom injected it),
  2. the mock never saw the phm_ placeholder or the LiteLLM master key,
  3. the request path reached the mock as /v1/chat/completions,
  4. neither the real stand-in nor the Phantom session token appears in the
     LiteLLM process environment passed on the command line, and the LiteLLM
     log never contains the stand-in real value.
Exit 0 all passed, 1 a check failed, 2 prerequisites missing.
"""
import json, os, shutil, socket, subprocess, sys, tempfile, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
LITELLM = os.environ.get("LITELLM_BIN") or shutil.which("litellm")
if not LITELLM or not shutil.which("cargo"):
    print("INCOMPLETE: need LITELLM_BIN and cargo")
    sys.exit(2)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def wait_port(port, secs=60):
    end = time.time() + secs
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close(); return True
        except OSError:
            time.sleep(0.3)
    return False


fails = []
def check(ok, msg):
    print(("PASS " if ok else "FAIL ") + msg)
    if not ok: fails.append(msg)


tmp = tempfile.mkdtemp(prefix="phm-litellm-")
procs = []
try:
    real = "stand-in-real-" + os.urandom(6).hex()
    placeholder = "phm_" + os.urandom(16).hex()
    master = "sk-master-" + os.urandom(6).hex()
    record = os.path.join(tmp, "upstream.jsonl")
    open(record, "w").close()

    mock_port = free_port()
    procs.append(subprocess.Popen([sys.executable, os.path.join(HERE, "mock_upstream.py"), str(mock_port), record]))
    if not wait_port(mock_port): check(False, "mock upstream started"); sys.exit(1)

    harness = subprocess.Popen(
        ["cargo", "run", "-q", "-p", "phantom-secrets-proxy", "--example", "litellm_loopback_harness"],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env={**os.environ, "HARNESS_MOCK_PORT": str(mock_port), "HARNESS_REAL_VALUE": real})
    procs.append(harness)
    port = token = None
    for line in harness.stdout:
        if line.startswith("PORT="): port = int(line.strip()[5:])
        if line.startswith("TOKEN="): token = line.strip()[6:]
        if port and token: break
    check(bool(port and token), "Phantom proxy harness started")
    if not (port and token): sys.exit(1)

    # What `phantom exec` would hand the child: a base URL carrying the session
    # token, and a phm_ placeholder as the provider key.
    base = f"http://127.0.0.1:{port}/openai/_phantom/{token}/"
    env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "OPENAI_BASE_URL": base,
           "OPENAI_API_KEY": placeholder, "LITELLM_MASTER_KEY": master,
           "LITELLM_LOCAL_MODEL_COST_MAP": "True", "LITELLM_TELEMETRY": "False",
           "NO_DOCS": "True", "NO_REDOC": "True"}
    llm_port = free_port()
    log = open(os.path.join(tmp, "litellm.log"), "w")
    procs.append(subprocess.Popen(
        [LITELLM, "--config", os.path.join(HERE, "config.yaml"), "--host", "127.0.0.1", "--port", str(llm_port)],
        env=env, stdout=log, stderr=subprocess.STDOUT))
    if not wait_port(llm_port, 120): check(False, "litellm started"); sys.exit(1)
    time.sleep(2)

    req = urllib.request.Request(
        f"http://127.0.0.1:{llm_port}/v1/chat/completions",
        data=json.dumps({"model": "gpt-gateway", "messages": [{"role": "user", "content": "hi"}]}).encode(),
        headers={"content-type": "application/json", "authorization": f"Bearer {master}"})
    try:
        resp = json.load(urllib.request.urlopen(req, timeout=60))
        check(resp["choices"][0]["message"]["content"] == "mock reply", "LiteLLM returned the mock completion")
    except Exception as e:
        check(False, f"LiteLLM request failed: {e}")

    time.sleep(1)
    recs = [json.loads(l) for l in open(record) if l.strip()]
    check(len(recs) == 1, f"mock upstream saw exactly 1 request (saw {len(recs)})")
    if recs:
        r = recs[0]
        hdrs = {k.lower(): v for k, v in r["headers"].items()}
        check(hdrs.get("authorization") == f"Bearer {real}", "upstream Authorization carried the injected stand-in real value")
        blob = json.dumps(r)
        check(placeholder not in blob, "upstream never saw the phm_ placeholder")
        check(master not in blob, "upstream never saw the LiteLLM master key")
        check(token not in blob, "upstream never saw the Phantom session token")
        check(r["path"] == "/v1/chat/completions", f"upstream path was {r['path']}")
    log.flush()
    text = open(os.path.join(tmp, "litellm.log")).read()
    check(real not in text, "LiteLLM log never contained the stand-in real value")
    check(real not in json.dumps(env), "LiteLLM environment never contained the stand-in real value")
finally:
    for p in procs:
        try:
            if p.stdin: p.stdin.close()
            p.terminate()
        except Exception: pass
    if os.environ.get("KEEP_TMP"): print("tmp:", tmp)
    else: shutil.rmtree(tmp, ignore_errors=True)
print("RESULT:", "FAIL" if fails else "PASS")
sys.exit(1 if fails else 0)
