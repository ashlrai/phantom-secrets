const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const filename = path.resolve(__dirname, "../src/app/device/device-authorization-client.tsx");
const source = fs.readFileSync(filename, "utf8");
const deviceCodeSource = fs.readFileSync(path.resolve(__dirname, "../src/lib/device-code.ts"), "utf8");
const deviceCodeModule = { exports: {} };
new Function("module", "exports", ts.transpileModule(deviceCodeSource, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText)(deviceCodeModule, deviceCodeModule.exports);
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
  const storage = options.storage ?? new Map(options.storedCode === null ? [] : [["phantom_device_code", options.storedCode ?? testCode]]);
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
    removeItem: (key) => { if (options.storageRemoveThrows) throw new Error("storage denied"); if (key === "phantom_device_code") events.push("remove-code"); storage.delete(key); },
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
    "@/lib/device-code": deviceCodeModule.exports,
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
          if (url.hash.includes(`access_token=${testToken}`) && !options.ignoreCallback) {
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

function findById(tree, id) {
  if (!tree || typeof tree !== "object") return null;
  if (tree.props?.id === id) return tree;
  for (const child of [tree.props?.children].flat(Infinity)) {
    const match = findById(child, id);
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

test("explicit retry after a failed new callback restarts OAuth instead of approving an older account", async () => {
  for (const failure of [
    { initializationError: true },
    { initializationThrows: true },
    { url: "https://phm.dev/device?oauth=1#error=access_denied" },
    { sessionError: true },
  ]) {
    const h = harness({ ...failure, previousSession: { access_token: "synthetic-prior-account" } });
    h.runEffect(); await h.settle();
    assert.equal(h.requests.length, 0);
    const readsBeforeRetry = h.events.filter((event) => event === "get-session").length;
    await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
    assert.equal(h.requests.length, 0);
    assert.ok(h.events.includes("start-oauth"));
    assert.equal(h.events.filter((event) => event === "get-session").length, readsBeforeRetry);
    assert.equal(h.storage.get("phantom_device_code"), testCode);
  }
});

test("repeated failed OAuth starts never fall back to a previous account session", async () => {
  for (const failure of [{ startError: true }, { startThrows: true }, { storageWriteThrows: true }]) {
    const h = harness({ initializationError: true, previousSession: { access_token: "synthetic-prior-account" }, ...failure });
    h.runEffect(); await h.settle();
    for (let attempt = 0; attempt < 2; attempt++) {
      await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
      assert.equal(h.requests.length, 0);
      assert.equal(h.states[1], "input");
      assert.doesNotMatch(h.states[2], /private|synthetic-|storage denied/);
    }
  }
});

test("ordinary existing-session submission still approves without starting OAuth", async () => {
  const h = harness({ url: "https://phm.dev/device", previousSession: { access_token: "synthetic-existing-account" } });
  find(h.render(), "input").props.onChange({ target: { value: testCode } });
  await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].headers.Authorization, "Bearer synthetic-existing-account");
  assert.equal(h.events.includes("start-oauth"), false);
  assert.equal(h.states[1], "done");
});

test("empty device code submission shows validation without authorizing", async () => {
  const h = harness({ url: "https://phm.dev/device", storedCode: null, previousSession: { access_token: "synthetic-existing-account" } });
  let tree = h.render();
  assert.equal(find(tree, "input").props.value, "");
  assert.equal(find(tree, "button").props.disabled, false);

  let prevented = false;
  await find(tree, "form").props.onSubmit({ preventDefault() { prevented = true; } });
  tree = h.render();
  assert.equal(prevented, true);
  assert.equal(h.states[1], "input");
  assert.equal(find(tree, "input").props.value, "");
  assert.equal(find(tree, "input").props["aria-invalid"], true);
  assert.equal(findById(tree, "device-error").props.role, "alert");
  assert.equal(findById(tree, "device-error").props.children, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
  assert.ok(find(tree, "form"));
  assert.equal(find(tree, "button").props.disabled, false);
  assert.deepEqual(h.events, []);
  assert.equal(h.requests.length, 0);
});

test("clicking authorize with an empty code displays accessible validation", async () => {
  const { JSDOM } = require("jsdom");
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
  const previousGlobals = new Map(["window", "document", "navigator", "HTMLElement"].map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  for (const name of previousGlobals.keys()) Object.defineProperty(globalThis, name, { value: dom.window[name], configurable: true, writable: true });

  const React = require("react");
  const { render, cleanup } = require("@testing-library/react");
  const userEvent = require("@testing-library/user-event").default;
  let clientsCreated = 0;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": deviceCodeModule.exports,
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => { clientsCreated++; throw new Error("Unexpected client creation"); } },
  };
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  try {
    new Function("require", "module", "exports", compiled)(
      (name) => dependencies[name] ?? require(name), module, module.exports,
    );
    const page = render(React.createElement(module.exports.default));
    const input = page.getByRole("textbox", { name: "Device code" });
    const button = page.getByRole("button", { name: "Authorize Device" });
    assert.equal(input.value, "");
    assert.equal(button.disabled, false);
    await userEvent.setup({ document: dom.window.document }).click(button);
    const alert = page.getByRole("alert");
    assert.equal(alert.textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id));
    assert.equal(clientsCreated, 0);
  } finally {
    cleanup();
    dom.window.close();
    for (const [name, descriptor] of previousGlobals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
});

test("invalid device code explains the accepted characters and displayed format", async () => {
  const h = harness({ url: "https://phm.dev/device", storedCode: null });
  find(h.render(), "input").props.onChange({ target: { value: "ab12c" } });
  await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
  const tree = h.render();
  assert.equal(find(tree, "input").props.value, "AB12-C");
  assert.equal(find(tree, "input").props["aria-invalid"], true);
  assert.equal(find(tree, "input").props["aria-describedby"], "device-code-hint device-error device-help");
  const error = find(tree, "form").props.children.find((child) => child?.props?.id === "device-error");
  assert.equal(error.props.role, "alert");
  assert.equal(error.props.children, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
  assert.deepEqual(h.events, []);
  assert.equal(h.requests.length, 0);
});

test("seven-character device code shows the length error and can be corrected", async () => {
  const h = harness({ url: "https://phm.dev/device", storedCode: null, previousSession: { access_token: "synthetic-existing-account" } });
  find(h.render(), "input").props.onChange({ target: { value: "abcd234" } });
  let tree = h.render();
  assert.equal(find(tree, "input").props.value, "ABCD-234");
  assert.equal(find(tree, "button").props.disabled, false);

  await find(tree, "form").props.onSubmit({ preventDefault() {} });
  tree = h.render();
  assert.equal(findById(tree, "device-error").props.children, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
  assert.equal(find(tree, "input").props["aria-invalid"], true);
  assert.deepEqual(h.events, []);
  assert.equal(h.requests.length, 0);

  find(tree, "input").props.onChange({ target: { value: "abcd2345" } });
  tree = h.render();
  assert.equal(find(tree, "button").props.disabled, false);
  await find(tree, "form").props.onSubmit({ preventDefault() {} });
  assert.equal(h.states[2], "");
  assert.equal(h.states[1], "done");
  assert.equal(h.requests.length, 1);
  assert.deepEqual(JSON.parse(h.requests[0].body), { user_code: "ABCD2345" });
});

test("eight letters and numbers are formatted and submitted without the display hyphen", async () => {
  const h = harness({ url: "https://phm.dev/device", previousSession: { access_token: "synthetic-existing-account" } });
  let input = find(h.render(), "input");
  assert.equal(input.props.placeholder, "XXXX-XXXX");
  assert.equal(input.props.maxLength, 9);
  input.props.onChange({ target: { value: "ab01" } });
  assert.equal(find(h.render(), "input").props.value, "AB01");
  find(h.render(), "input").props.onChange({ target: { value: "ab01-cd23!45" } });
  input = find(h.render(), "input");
  assert.equal(input.props.value, "AB01-CD23");
  assert.equal(find(h.render(), "button").props.disabled, false);
  await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
  assert.equal(h.states[1], "done");
  assert.deepEqual(JSON.parse(h.requests[0].body), { user_code: "AB01CD23" });
});

test("causal control reproduces prior-account approval when the failed-callback retry guard is removed", async () => {
  const unguardedSource = source.replace("= needsFreshOAuth\n        ?", "= false\n        ?");
  assert.notEqual(unguardedSource, source);
  const h = harness({ source: unguardedSource, initializationError: true, previousSession: { access_token: "synthetic-prior-account" } });
  h.runEffect(); await h.settle();
  assert.equal(h.requests.length, 0);
  await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].headers.Authorization, "Bearer synthetic-prior-account");
  assert.equal(h.events.includes("start-oauth"), false);
});

test("failed callback intent survives URL cleanup and a full page reload", async () => {
  for (const failure of [
    { initializationError: true },
    { url: "https://phm.dev/device?oauth=1#error=access_denied", storedCode: null },
  ]) {
    const previousSession = { access_token: "synthetic-prior-account" };
    const failed = harness({ ...failure, previousSession });
    failed.runEffect(); await failed.settle();
    assert.equal(failed.requests.length, 0);
    assert.equal(failed.storage.get("phantom_device_oauth_pending"), "1");
    const reloaded = harness({ url: failed.url().href, storage: failed.storage, previousSession });
    find(reloaded.render(), "input").props.onChange({ target: { value: testCode } });
    await find(reloaded.render(), "form").props.onSubmit({ preventDefault() {} });
    assert.equal(reloaded.requests.length, 0);
    assert.ok(reloaded.events.includes("start-oauth"));
    assert.equal(reloaded.events.includes("get-session"), false);
  }
});

test("tokenless or unconsumed callback cannot clear retry intent or approve an older session", async () => {
  for (const failure of [
    { url: "https://phm.dev/device?oauth=1" },
    { ignoreCallback: true },
  ]) {
    const h = harness({ ...failure, previousSession: { access_token: "synthetic-prior-account" } });
    h.runEffect(); await h.settle();
    assert.equal(h.requests.length, 0);
    assert.equal(h.storage.get("phantom_device_oauth_pending"), "1");
    assert.equal(h.states[1], "input");
    assert.match(h.states[2], /GitHub sign-in did not complete/);
    await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
    assert.equal(h.requests.length, 0);
    assert.ok(h.events.includes("start-oauth"));
  }
});

test("unreadable retry intent cannot approve a stored older session", async () => {
  const h = harness({ url: "https://phm.dev/device", storedCode: null, storageReadThrows: true, previousSession: { access_token: "synthetic-prior-account" } });
  find(h.render(), "input").props.onChange({ target: { value: testCode } });
  await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
  assert.equal(h.requests.length, 0);
  assert.ok(h.events.includes("start-oauth"));
});

test("unwritable callback storage retains only a safe retry flag across reload", async () => {
  const previousSession = { access_token: "synthetic-prior-account" };
  const failed = harness({ initializationError: true, storageWriteThrows: true, previousSession });
  failed.runEffect(); await failed.settle();
  assert.equal(failed.requests.length, 0);
  assert.equal(failed.url().href, "https://phm.dev/device?oauth_retry=1");
  assert.equal(failed.url().hash, "");
  const reloaded = harness({ url: failed.url().href, storage: failed.storage, previousSession, storageWriteThrows: true });
  find(reloaded.render(), "input").props.onChange({ target: { value: testCode } });
  await find(reloaded.render(), "form").props.onSubmit({ preventDefault() {} });
  assert.equal(reloaded.requests.length, 0);
  assert.equal(reloaded.events.includes("get-session"), false);
  assert.equal(reloaded.states[1], "input");
  assert.doesNotMatch(reloaded.states[2], /private|synthetic-|storage denied/);
});

test("only successful callback verification clears persisted retry intent", async () => {
  const h = harness();
  h.runEffect(); await h.settle();
  assert.equal(h.states[1], "done");
  assert.equal(h.storage.has("phantom_device_oauth_pending"), false);
  const retained = harness({ storedCode: null, storageRemoveThrows: true, storageReadThrows: true });
  retained.runEffect(); await retained.settle();
  assert.equal(retained.storage.get("phantom_device_oauth_pending"), "1");
  find(retained.render(), "input").props.onChange({ target: { value: testCode } });
  await find(retained.render(), "form").props.onSubmit({ preventDefault() {} });
  assert.equal(retained.requests.length, 1);
  assert.equal(retained.requests[0].headers.Authorization, `Bearer ${testToken}`);
  assert.equal(retained.events.includes("start-oauth"), false);
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

test("rendered device code input exposes the visible format hint", () => {
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const { getByRole, getByText } = require("@testing-library/dom");
  const { isInaccessible } = require("dom-accessibility-api");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": deviceCodeModule.exports,
    "@/lib/posthog": { capturePostHog: async () => {} },
  };
  const module = { exports: {} };
  new Function("require", "module", "exports", compiled)(
    (name) => dependencies[name] ?? require(name), module, module.exports,
  );
  const dom = new JSDOM(renderToStaticMarkup(React.createElement(module.exports.default)));
  try {
    const body = dom.window.document.body;
    const hint = getByText(body, "Enter 8 letters or numbers in the format XXXX-XXXX.");
    assert.equal(isInaccessible(hint), false);
    const input = getByRole(body, "textbox", {
      name: "Device code",
      description: /Enter 8 letters or numbers in the format XXXX-XXXX\./,
    });
    assert.equal(input.getAttribute("placeholder"), "XXXX-XXXX");
    assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(hint.id));
  } finally {
    dom.window.close();
  }
});

test("device code format hint remains associated with the input when validation fails", async () => {
  const h = harness();
  let tree = h.render();
  const hint = findById(tree, "device-code-hint");
  assert.match(hint.props.children, /8 letters or numbers.*XXXX-XXXX/);
  assert.deepEqual(find(tree, "input").props["aria-describedby"].split(" "), ["device-code-hint", "device-help"]);

  await find(tree, "form").props.onSubmit({ preventDefault() {} });
  tree = h.render();
  const input = find(tree, "input");
  assert.equal(input.props["aria-invalid"], true);
  assert.deepEqual(input.props["aria-describedby"].split(" "), ["device-code-hint", "device-error", "device-help"]);
  assert.equal(findById(tree, "device-error").props.role, "alert");
  for (const id of input.props["aria-describedby"].split(" ")) assert.ok(findById(tree, id));
});

test("device code input has an accessible name before and after validation", async () => {
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const { getByRole } = require("@testing-library/dom");
  const h = harness({ url: "https://phm.dev/device", storedCode: null });

  function toElement(node) {
    if (Array.isArray(node)) return node.map(toElement);
    if (!node || typeof node !== "object") return node;
    const { children, ...props } = node.props;
    return React.createElement(node.type, props, ...[children].flat().map(toElement));
  }

  function assertNamedInput() {
    const document = new JSDOM(renderToStaticMarkup(toElement(h.render()))).window.document;
    const input = getByRole(document.body, "textbox", { name: "Device code" });
    assert.equal(input.id, "device-code");
    assert.equal(input.labels.length, 1);
    assert.equal(input.labels[0].textContent.trim(), "Device code");
  }

  assertNamedInput();
  await find(h.render(), "form").props.onSubmit({ preventDefault() {} });
  assert.equal(find(h.render(), "input").props["aria-invalid"], true);
  assertNamedInput();
});

test("branded form associates instructions and errors and announces busy and success states", async () => {
  const h = harness({ deferInitialization: true });
  const tree = h.render();
  assert.equal(find(tree, "label").props.htmlFor, "device-code");
  assert.equal(find(tree, "input").props.id, "device-code");
  assert.equal(find(tree, "input").props["aria-describedby"], "device-code-hint device-help");
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
