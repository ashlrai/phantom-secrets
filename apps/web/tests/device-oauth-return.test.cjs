const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const filename = path.resolve(__dirname, "../src/app/device/device-authorization-client.tsx");
const source = fs.readFileSync(filename, "utf8");
const testCode = "ABCD-2345";
const testToken = "synthetic-callback-bearer";

function harness(options = {}) {
  const states = [];
  const refs = [];
  const effects = [];
  const events = [];
  const requests = [];
  let cursor = 0;
  let refCursor = 0;
  let url = new URL(options.url ?? `https://phm.dev/device?oauth=1#access_token=${testToken}`);
  const storage = new Map(options.storedCode === null ? [] : [["phantom_device_code", options.storedCode ?? testCode]]);
  let resume;
  const initializationBarrier = options.deferInitialization
    ? new Promise((resolve) => { resume = resolve; }) : Promise.resolve();
  let session = options.previousSession ?? null;
  const location = {};
  for (const field of ["search", "hash", "origin", "href"]) {
    Object.defineProperty(location, field, { get: () => url[field] });
  }
  const window = {
    location,
    history: { replaceState(_state, _title, next) { events.push("cleanup"); url = new URL(next, url); } },
  };
  const sessionStorage = {
    getItem: (key) => { if (options.storageReadThrows) throw new Error("storage denied"); return storage.get(key) ?? null; },
    setItem: (key, value) => { if (options.storageWriteThrows) throw new Error("storage denied"); storage.set(key, value); },
    removeItem: (key) => { if (options.storageRemoveThrows) throw new Error("storage denied"); events.push("remove-code"); storage.delete(key); },
  };
  const jsx = (type, props) => ({ type, props });
  const dependencies = {
    "react/jsx-runtime": { jsx, jsxs: jsx },
    "next/image": { default: "img" },
    "next/link": { default: "a" },
    react: {
      useState(initial) {
        const slot = cursor++;
        if (!(slot in states)) states[slot] = initial;
        return [states[slot], (value) => { states[slot] = value; }];
      },
      useRef(initial) { return refs[refCursor++] ??= { current: initial }; },
      useEffect(callback) { if (effects.length === 0) effects.push(callback); },
    },
    "@/lib/device-code": {
      normalizeDeviceUserCode: (value) => value.replace(/-/g, "").toUpperCase(),
      formatDeviceUserCode: (value) => value,
      isValidDeviceUserCode: (value) => /^[A-Z2-9]{4}-?[A-Z2-9]{4}$/.test(value),
    },
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": {
      createClient() {
        events.push("create-client");
        // Match auth-js: constructor starts async initialization; getSession
        // awaits it but discards its error and can return an older session.
        const initialization = (async () => {
          await initializationBarrier;
          events.push("sdk-url-read");
          if (options.initializationThrows) throw new Error("private callback detail");
          if (options.initializationError) return { error: { message: "private callback detail" } };
          if (url.hash.includes(`access_token=${testToken}`)) {
            session = options.nullSession ? null : { access_token: testToken };
            events.push("sdk-session-restored");
          }
          return { error: null };
        })();
        return { auth: {
          initialize: () => initialization,
          async getSession() {
            await initialization;
            events.push("get-session");
            return { data: { session }, error: options.sessionError ? { message: "private session detail" } : null };
          },
          async signInWithOAuth() {
            events.push("start-oauth");
            if (options.startThrows) throw new Error("private provider detail");
            return { error: options.startError ? { message: "private provider detail" } : null };
          },
        } };
      },
    },
  };
  const module = { exports: {} };
  const output = ts.transpileModule(options.source ?? source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
    fileName: filename,
  }).outputText;
  new Function("require", "module", "exports", "window", "sessionStorage", "fetch", output)(
    (name) => { if (!(name in dependencies)) throw new Error(`Unexpected dependency ${name}`); return dependencies[name]; },
    module, module.exports, window, sessionStorage,
    async (endpoint, request) => {
      assert.equal(endpoint, "/api/v1/auth/device/approve");
      events.push("approve");
      requests.push(request);
      if (options.approvalThrows) throw new Error("private network detail");
      return options.approvalError
        ? Response.json({ error: "Invalid or expired code. Please try again." }, { status: 400 })
        : Response.json({ status: "approved" });
    },
  );
  function render() { cursor = 0; refCursor = 0; return module.exports.default(); }
  const initialTree = render();
  return {
    initialTree, render, states, events, requests, storage,
    runEffect: () => effects[0](),
    resumeInitialization: () => resume(),
    url: () => url,
    settle: async () => { for (let i = 0; i < 5; i++) await new Promise(setImmediate); },
  };
}

function find(tree, type) {
  if (!tree || typeof tree !== "object") return null;
  if (tree.type === type) return tree;
  for (const child of [tree.props?.children].flat(Infinity)) {
    const match = find(child, type);
    if (match) return match;
  }
  return null;
}

async function assertSuccessfulCallback(h) {
  h.runEffect();
  await h.settle();
  assert.equal(h.states[1], "done");
  assert.equal(h.requests.length, 1);
  assert.deepEqual(JSON.parse(h.requests[0].body), { user_code: "ABCD2345" });
  assert.equal(h.requests[0].headers.Authorization, `Bearer ${testToken}`);
  assert.ok(h.events.indexOf("sdk-session-restored") < h.events.indexOf("cleanup"));
  assert.ok(h.events.indexOf("cleanup") < h.events.indexOf("approve"));
  assert.equal(h.storage.has("phantom_device_code"), false);
  assert.equal(h.url().href, "https://phm.dev/device");
}

test("callback waits for asynchronous SDK fragment ingestion, then approves once under StrictMode replay", async () => {
  const h = harness({ deferInitialization: true });
  h.runEffect();
  h.runEffect();
  assert.ok(h.url().hash.includes(testToken));
  assert.equal(h.storage.get("phantom_device_code"), testCode);
  assert.equal(h.requests.length, 0);
  h.resumeInitialization();
  await h.settle();
  assert.equal(h.states[1], "done");
  assert.equal(h.requests.length, 1);
  assert.deepEqual(h.events, ["create-client", "sdk-url-read", "sdk-session-restored", "get-session", "cleanup", "remove-code", "approve"]);
});

test("causal negative control loses callback session when URL cleanup is moved before SDK initialization", async () => {
  await assertSuccessfulCallback(harness());
  const earlyCleanup = source.replace("void completeOAuthReturn();", 'window.history.replaceState(null, "", "/device");\n    void completeOAuthReturn();');
  assert.notEqual(earlyCleanup, source);
  const control = harness({ source: earlyCleanup });
  await assert.rejects(() => assertSuccessfulCallback(control), { code: "ERR_ASSERTION" });
  assert.equal(control.requests.length, 0);
  assert.equal(control.storage.get("phantom_device_code"), testCode);
});

test("failed initialization never approves an older session and safely preserves retry code", async () => {
  for (const failure of [{ initializationError: true }, { initializationThrows: true }, { sessionError: true }, { nullSession: true }]) {
    const h = harness({ ...failure, ...(failure.initializationError ? { previousSession: { access_token: "synthetic-prior-account" } } : {}) });
    h.runEffect(); await h.settle();
    assert.equal(h.requests.length, 0);
    assert.equal(h.states[1], "input");
    assert.match(h.states[2], /Please try again/);
    assert.doesNotMatch(h.states[2], /private|synthetic-/);
    assert.equal(h.storage.get("phantom_device_code"), testCode);
    assert.equal(h.url().href, "https://phm.dev/device");
    assert.equal(find(h.render(), "input").props.disabled, false);
    assert.equal(find(h.render(), "button").props.disabled, false);
  }
});

test("callback error presence rejects even a restored session without reflecting descriptions", async () => {
  for (const suffix of ["#error=access_denied&error_description=private-detail", "&error_code=private-detail#access_token=" + testToken]) {
    const h = harness({ url: "https://phm.dev/device?oauth=1" + suffix, previousSession: { access_token: "synthetic-prior-account" } });
    h.runEffect(); await h.settle();
    assert.equal(h.requests.length, 0);
    assert.equal(h.states[1], "input");
    assert.doesNotMatch(h.states[2], /private-detail|synthetic-/);
    assert.equal(h.url().href, "https://phm.dev/device");
    assert.equal(h.storage.get("phantom_device_code"), testCode);
  }
});

test("missing or invalid pending code still consumes callback and enables manual code entry", async () => {
  for (const storedCode of [null, "invalid"]) {
    const h = harness({ storedCode }); h.runEffect(); await h.settle();
    assert.equal(h.requests.length, 0);
    assert.ok(h.events.includes("sdk-session-restored"));
    assert.equal(h.url().href, "https://phm.dev/device");
    assert.equal(h.states[1], "input");
    assert.match(h.states[2], /current code from your terminal/);
    assert.equal(find(h.render(), "input").props.disabled, false);
  }
});

test("ordinary noncallback visit leaves URL and pending code untouched", async () => {
  const h = harness({ url: "https://phm.dev/device#ordinary-anchor" });
  h.runEffect(); await h.settle();
  assert.deepEqual(h.events, []);
  assert.equal(h.storage.get("phantom_device_code"), testCode);
  assert.equal(h.url().hash, "#ordinary-anchor");
});

test("failed approval leaves the restored code editable for an explicit owner retry", async () => {
  for (const failure of [{ approvalError: true }, { approvalThrows: true }]) {
    const h = harness(failure); h.runEffect(); await h.settle();
    assert.equal(h.requests.length, 1);
    assert.equal(h.states[0], testCode);
    assert.equal(h.states[1], "input");
    assert.equal(find(h.render(), "input").props.disabled, false);
    assert.equal(find(h.render(), "button").props.disabled, false);
    assert.doesNotMatch(h.states[2], /private network detail/);
  }
});


test("restricted tab storage still allows SDK ingestion and safe manual code or approval", async () => {
  const deniedRead = harness({ storageReadThrows: true });
  deniedRead.runEffect(); await deniedRead.settle();
  assert.ok(deniedRead.events.includes("sdk-session-restored"));
  assert.equal(deniedRead.url().href, "https://phm.dev/device");
  assert.equal(deniedRead.requests.length, 0);
  assert.equal(deniedRead.states[1], "input");
  assert.match(deniedRead.states[2], /current code from your terminal/);
  const deniedRemove = harness({ storageRemoveThrows: true });
  deniedRemove.runEffect(); await deniedRemove.settle();
  assert.equal(deniedRemove.requests.length, 1);
  assert.equal(deniedRemove.states[1], "done");
});

test("submit errors enable retry without reflecting private SDK details", async () => {
  for (const failure of [{ sessionError: true }, { startError: true }, { startThrows: true }, { storageWriteThrows: true }]) {
    const h = harness({ url: "https://phm.dev/device", storedCode: null, ...failure });
    find(h.render(), "input").props.onChange({ target: { value: testCode } });
    await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
    assert.equal(h.states[1], "input");
    assert.doesNotMatch(h.states[2], /private|storage denied/);
    assert.match(h.states[2], /Please try again/);
    assert.equal(h.requests.length, 0);
    assert.equal(find(h.render(), "button").props.disabled, false);
    if (failure.startError || failure.startThrows) assert.equal(h.storage.get("phantom_device_code"), testCode);
  }
});

test("branded form associates instructions and errors and announces busy and success states", async () => {
  const h = harness({ deferInitialization: true });
  const tree = h.render();
  assert.equal(find(tree, "label").props.htmlFor, "device-code");
  assert.equal(find(tree, "input").props.id, "device-code");
  assert.equal(find(tree, "input").props["aria-describedby"], "device-help");
  assert.equal(find(tree, "button").props.type, "submit");
  assert.match(find(tree, "input").props.className, /text-2xl.*tracking-\[0\.12em\]/);
  assert.equal(find(tree, "a").props.href, "/secrets");
  h.runEffect();
  assert.equal(find(h.render(), "section").props["aria-busy"], true);
  h.resumeInitialization(); await h.settle();
  assert.equal(h.states[1], "done");
  assert.equal(find(h.render(), "section").props["aria-busy"], false);
  assert.equal(find(h.render(), "section").props.children.props.role, "status");
});
