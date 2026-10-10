const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const filename = path.resolve(__dirname, "../src/app/dashboard/layout.tsx");
const source = fs.readFileSync(filename, "utf8");
const testToken = "synthetic-dashboard-callback";
const previousSession = { access_token: "synthetic-old-session", user: { email: "old@example.invalid" } };
const pendingKey = "phantom_dashboard_oauth_pending";

function harness(options = {}) {
  const states = [];
  const effects = [];
  const events = [];
  const redirects = [];
  const storage = options.storage ?? new Map();
  let cursor = 0;
  let url = new URL(options.url ?? `https://phm.dev/dashboard?oauth=1#access_token=${testToken}`);
  let session = options.previousSession ?? null;
  let client;
  let resume;
  const barrier = options.deferInitialization ? new Promise((resolve) => { resume = resolve; }) : Promise.resolve();
  const location = {};
  for (const field of ["search", "hash", "pathname", "origin", "href"]) {
    Object.defineProperty(location, field, { get: () => url[field] });
  }
  const window = {
    location,
    history: { replaceState(_state, _title, next) { events.push("cleanup"); url = new URL(next, url); } },
  };
  const sessionStorage = {
    getItem(key) { if (options.storageReadThrows) throw new Error("private storage detail"); return storage.get(key) ?? null; },
    setItem(key, value) { if (options.storageWriteThrows) throw new Error("private storage detail"); events.push("pending-intent"); storage.set(key, value); },
    removeItem(key) { if (options.storageRemoveThrows) throw new Error("private storage detail"); events.push("clear-intent"); storage.delete(key); },
  };
  const jsx = (type, props) => ({ type, props });
  const dependencies = {
    "react/jsx-runtime": { jsx, jsxs: jsx },
    react: {
      useState(initial) {
        const slot = cursor++;
        if (!(slot in states)) states[slot] = initial;
        return [states[slot], (value) => { states[slot] = value; }];
      },
      useEffect(callback) { if (effects.length === 0) effects.push(callback); },
    },
    "next/link": { __esModule: true, default: "a" },
    "next/navigation": { usePathname: () => url.pathname },
    "@/components/landing/Nav": { Nav: "nav" },
    "@/components/landing/Icons": { Github: "svg" },
    "@/lib/supabase-browser": {
      getBrowserClient() {
        if (options.clientThrows) throw new Error("private configuration detail");
        if (client) return client;
        events.push("create-client");
        // Match auth-js: initialization preserves an older stored session on
        // callback failure, and getSession does not propagate that error.
        const initialization = (async () => {
          await barrier;
          events.push("sdk-url-read");
          if (options.initializationThrows) throw new Error("private callback detail");
          if (options.initializationError) return { error: { message: "private callback detail" } };
          if (url.hash.includes(testToken)) {
            session = options.nullSession ? null : options.restoredSession ?? { access_token: testToken, user: { email: "current@example.invalid" } };
            events.push("sdk-session-restored");
          }
          return { error: null };
        })();
        client = { auth: {
          initialize: () => initialization,
          async getSession() {
            await initialization;
            events.push("get-session");
            if (options.sessionThrows) throw new Error("private session detail");
            return { data: { session }, error: options.sessionError ? { message: "private session detail" } : null };
          },
          async signInWithOAuth(request) {
            events.push("start-oauth");
            redirects.push(request);
            const outcome = options.startOutcomes?.[redirects.length - 1];
            if (outcome === "throw") throw new Error("private provider detail");
            return { error: outcome === "error" ? { message: "private provider detail" } : null };
          },
        } };
        return client;
      },
    },
  };
  const module = { exports: {} };
  const output = ts.transpileModule(options.source ?? source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
    fileName: filename,
  }).outputText;
  new Function("require", "module", "exports", "window", "sessionStorage", output)(
    (name) => { assert.ok(name in dependencies, name); return dependencies[name]; },
    module, module.exports, window, sessionStorage,
  );
  function render() {
    cursor = 0;
    return module.exports.default({ children: jsx("section", { id: "private-dashboard-child" }) });
  }
  render();
  return {
    states, events, redirects, render, storage,
    runEffect: () => effects[0](),
    resume: () => resume(),
    url: () => url,
    settle: async () => { for (let i = 0; i < 5; i++) await new Promise(setImmediate); },
  };
}

function find(tree, predicate) {
  if (!tree || typeof tree !== "object") return null;
  if (predicate(tree)) return tree;
  for (const child of [tree.props?.children].flat(Infinity)) {
    const match = find(child, predicate);
    if (match) return match;
  }
  return null;
}
const button = (h) => find(h.render(), (node) => node.type === "button");
const privateChild = (h) => find(h.render(), (node) => node.props?.id === "private-dashboard-child");

async function assertFailedCallback(h) {
  h.runEffect(); await h.settle();
  assert.equal(h.states[0], "unavailable");
  assert.equal(privateChild(h), null);
  assert.equal(button(h).props.disabled, false);
  assert.ok(find(h.render(), (node) => node.props?.role === "alert"));
  assert.doesNotMatch(JSON.stringify(h.render()), /private callback detail|old@example|private provider detail/);
  assert.equal(h.url().href, "https://phm.dev/dashboard?oauth_retry=1");
}

test("failed callback cannot present an older stored session as a successful dashboard sign-in", async () => {
  const h = harness({ initializationError: true, previousSession });
  await assertFailedCallback(h);
  assert.equal(h.events.includes("get-session"), false);

  const ignoresInitializationError = source.replace("initializationError || callbackError", "callbackError");
  assert.notEqual(ignoresInitializationError, source);
  const control = harness({ source: ignoresInitializationError, initializationError: true, previousSession: { ...previousSession, access_token: testToken } });
  await assert.rejects(() => assertFailedCallback(control), { code: "ERR_ASSERTION" });
  assert.equal(control.states[0], "signed_in");
  assert.ok(privateChild(control));
});

test("callback consumes the fragment before cleanup and keeps a nested dashboard destination", async () => {
  const h = harness({ url: `https://phm.dev/dashboard/team?oauth=1#access_token=${testToken}`, deferInitialization: true });
  h.runEffect();
  assert.ok(h.url().hash.includes(testToken));
  assert.equal(h.events.includes("cleanup"), false);
  h.resume(); await h.settle();
  assert.equal(h.states[0], "signed_in");
  assert.equal(h.states[1], "current@example.invalid");
  assert.ok(privateChild(h));
  assert.ok(h.events.indexOf("sdk-session-restored") < h.events.indexOf("cleanup"));
  assert.equal(h.url().href, "https://phm.dev/dashboard/team");
});

test("explicit provider errors reject old sessions even if initialization reports success", async () => {
  for (const url of [
    "https://phm.dev/dashboard?oauth=1#error=access_denied&error_description=private-provider-detail",
    "https://phm.dev/dashboard?error_code=private-provider-detail",
  ]) {
    const h = harness({ url, previousSession });
    await assertFailedCallback(h);
    assert.doesNotMatch(JSON.stringify(h.render()), /private-provider-detail/);
  }
});

test("failed callback without a stored session enables an explicit GitHub retry and repeated start recovery", async () => {
  for (const failure of ["error", "throw"]) {
    const h = harness({ initializationError: true, startOutcomes: [failure, "success"] });
    await assertFailedCallback(h);
    await button(h).props.onClick();
    assert.equal(h.states[0], "unavailable");
    assert.equal(button(h).props.disabled, false);
    assert.doesNotMatch(JSON.stringify(h.render()), /private provider detail/);
    await button(h).props.onClick();
    assert.equal(button(h).props.disabled, true);
    assert.equal(h.redirects.length, 2);
    assert.deepEqual(h.redirects[1], { provider: "github", options: { redirectTo: "https://phm.dev/dashboard?oauth=1" } });
    assert.equal(privateChild(h), null);
  }
});

test("SDK failures leave safe retry UI instead of claiming browser configuration is absent", async () => {
  for (const failure of ["initializationThrows", "sessionError", "sessionThrows", "clientThrows"]) {
    const h = harness({ [failure]: true });
    await assertFailedCallback(h);
    const tree = JSON.stringify(h.render());
    assert.doesNotMatch(tree, /private configuration detail|private session detail|no usable browser-auth configuration/);
  }
});

test("ordinary visits preserve their URL and still restore an existing session or offer sign-in", async () => {
  for (const session of [null, previousSession]) {
    const h = harness({ url: "https://phm.dev/dashboard?tab=overview#backups", previousSession: session });
    h.runEffect(); await h.settle();
    assert.equal(h.states[0], session ? "signed_in" : "signed_out");
    assert.equal(h.url().href, "https://phm.dev/dashboard?tab=overview#backups");
    assert.equal(h.events.includes("cleanup"), false);
    if (!session) {
      await button(h).props.onClick();
      assert.equal(h.redirects[0].options.redirectTo, "https://phm.dev/dashboard?oauth=1");
    }
  }
});

test("unmounted async callbacks cannot change state or clean up a newer navigation", async () => {
  const h = harness({ deferInitialization: true });
  const cleanup = h.runEffect(); cleanup();
  h.resume(); await h.settle();
  assert.equal(h.states[0], "loading");
  assert.equal(h.events.includes("cleanup"), false);
});

test("StrictMode effect replay accepts one initialized session and cleans callback once", async () => {
  const h = harness({ deferInitialization: true });
  h.runEffect()(); h.runEffect();
  h.resume(); await h.settle();
  assert.equal(h.states[0], "signed_in");
  assert.equal(h.events.filter((event) => event === "create-client").length, 1);
  assert.equal(h.events.filter((event) => event === "cleanup").length, 1);
  assert.ok(privateChild(h));
});

test("tokenless OAuth returns and mismatched restored sessions cannot reuse a previous login", async () => {
  for (const options of [
    { url: "https://phm.dev/dashboard?oauth=1", previousSession },
    { restoredSession: previousSession },
    { nullSession: true },
  ]) {
    const h = harness(options);
    await assertFailedCallback(h);
    assert.equal(h.storage.get(pendingKey), "1");
  }
  const ignoresCallbackBinding = source.replace(
    'error || (needsFreshOAuth && (!callbackBearer || session?.access_token !== callbackBearer))',
    'error',
  );
  assert.notEqual(ignoresCallbackBinding, source);
  const control = harness({ source: ignoresCallbackBinding, url: "https://phm.dev/dashboard?oauth=1", previousSession });
  await assert.rejects(() => assertFailedCallback(control), { code: "ERR_ASSERTION" });
  assert.equal(control.states[0], "signed_in");
});

test("failed callback intent survives fresh-module reload even when the retry query is removed", async () => {
  const storage = new Map();
  const failed = harness({ initializationError: true, previousSession, storage });
  await assertFailedCallback(failed);
  for (const url of [failed.url().href, "https://phm.dev/dashboard"]) {
    const reload = harness({ url, previousSession, storage });
    reload.runEffect(); await reload.settle();
    assert.equal(reload.states[0], "unavailable");
    assert.equal(privateChild(reload), null);
    assert.equal(button(reload).props.disabled, false);
    assert.equal(storage.get(pendingKey), "1");
  }
});

test("only a matching verified callback clears intent, then ordinary reload can restore the session", async () => {
  const storage = new Map([[pendingKey, "1"]]);
  const successful = harness({ storage });
  successful.runEffect(); await successful.settle();
  assert.equal(successful.states[0], "signed_in");
  assert.equal(storage.has(pendingKey), false);
  assert.equal(successful.url().href, "https://phm.dev/dashboard");
  const reload = harness({ storage, url: successful.url().href, previousSession });
  reload.runEffect(); await reload.settle();
  assert.equal(reload.states[0], "signed_in");
  assert.ok(privateChild(reload));
  assert.equal(reload.events.includes("cleanup"), false);
});

test("unwritable callback storage leaves only safe retry intent in the URL and blocks stale-session reload", async () => {
  const storage = new Map();
  const failed = harness({ url: "https://phm.dev/dashboard?oauth=1&error_description=private-detail#refresh_token=synthetic-private", storage, storageWriteThrows: true, previousSession });
  await assertFailedCallback(failed);
  assert.equal(storage.size, 0);
  assert.equal(failed.url().search, "?oauth_retry=1");
  assert.equal(failed.url().hash, "");
  const reload = harness({ url: failed.url().href, storage, previousSession });
  await assertFailedCallback(reload);
});

test("unreadable pending storage on an ordinary visit requires an explicit fresh sign-in", async () => {
  const h = harness({ url: "https://phm.dev/dashboard", storageReadThrows: true, previousSession });
  h.runEffect(); await h.settle();
  assert.equal(h.states[0], "unavailable");
  assert.equal(privateChild(h), null);
  assert.doesNotMatch(JSON.stringify(h.render()), /private storage detail|old@example/);
  await button(h).props.onClick();
  assert.equal(h.redirects.length, 1);
  assert.equal(h.storage.get(pendingKey), "1");
});

test("failed intent removal allows this verified callback but blocks a fresh-module reload", async () => {
  const storage = new Map();
  const successful = harness({ storage, storageRemoveThrows: true });
  successful.runEffect(); await successful.settle();
  assert.equal(successful.states[0], "signed_in");
  assert.ok(privateChild(successful));
  assert.equal(storage.get(pendingKey), "1");
  assert.equal(successful.url().href, "https://phm.dev/dashboard?oauth_retry=1");
  assert.deepEqual([...storage.values()], ["1"]);
  const reload = harness({ storage, url: successful.url().href, previousSession });
  await assertFailedCallback(reload);
});

test("sign-in start records intent before SDK contact and failed starts cannot restore an old session on reload", async () => {
  for (const storageWriteThrows of [false, true]) {
    const storage = new Map();
    const start = harness({ url: "https://phm.dev/dashboard", storage, storageWriteThrows, startOutcomes: ["error"] });
    start.runEffect(); await start.settle();
    assert.equal(start.states[0], "signed_out");
    await button(start).props.onClick();
    assert.equal(start.states[0], "unavailable");
    assert.equal(button(start).props.disabled, false);
    if (storageWriteThrows) {
      assert.equal(start.url().search, "?oauth_retry=1");
      assert.ok(start.events.indexOf("cleanup") < start.events.indexOf("start-oauth"));
    } else {
      assert.equal(storage.get(pendingKey), "1");
      assert.ok(start.events.indexOf("pending-intent") < start.events.indexOf("start-oauth"));
    }
    const reload = harness({ url: start.url().href, storage, previousSession });
    reload.runEffect(); await reload.settle();
    assert.equal(reload.states[0], "unavailable");
    assert.equal(privateChild(reload), null);
  }
});
