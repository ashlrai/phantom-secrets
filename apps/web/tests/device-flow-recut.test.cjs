const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const { JSDOM } = require("jsdom");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
const previousGlobals = new Map(
  ["window", "document", "navigator", "HTMLElement"].map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]),
);
for (const name of previousGlobals.keys()) {
  Object.defineProperty(globalThis, name, { value: dom.window[name], configurable: true, writable: true });
}
const React = require("react");
const { cleanup, render } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;
const { computeAccessibleDescription } = require("dom-accessibility-api");

test.afterEach(() => {
  cleanup();
  dom.window.sessionStorage.clear();
});
test.after(() => {
  dom.window.close();
  for (const [name, descriptor] of previousGlobals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
});

function compile(file, dependencies = {}, fetch = () => { throw new Error("Unexpected fetch"); }) {
  const filename = path.join(__dirname, "../src", file);
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  // Inject tab storage and fetch so this suite cannot use ambient credentials or network.
  new Function("require", "module", "exports", "sessionStorage", "fetch", output)(
    (name) => dependencies[name] ?? require(name), module, module.exports, dom.window.sessionStorage, fetch,
  );
  return module.exports;
}

function renderDevice({ approvalError } = {}) {
  let sessionReads = 0;
  const requests = [];
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts"),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => ({ auth: {
      getSession: async () => {
        sessionReads++;
        return { data: { session: { access_token: "synthetic-recut-session" } }, error: null };
      },
    } }) },
  };
  const Component = compile("app/device/device-authorization-client.tsx", dependencies, async (endpoint, request) => {
    requests.push({ endpoint, request });
    return approvalError
      ? Response.json({ error: approvalError }, { status: 400 })
      : Response.json({ status: "approved" });
  }).default;
  return {
    page: render(React.createElement(Component)),
    user: userEvent.setup({ document: dom.window.document }),
    requests,
    sessionReads: () => sessionReads,
  };
}

test("Enter from the code input rejects short codes and authorizes the corrected code", async () => {
  const h = renderDevice();
  const input = h.page.getByRole("textbox", { name: "Device code" });
  // Main already covers empty input Enter and every short length submitted by click.
  const displayed = ["A", "AB", "ABC", "ABCD", "ABCD-2", "ABCD-23", "ABCD-234"];
  for (let length = 1; length < 8; length++) {
    await h.user.clear(input);
    await h.user.type(input, "abcd2345".slice(0, length));
    assert.equal(dom.window.document.activeElement, input);
    await h.user.keyboard("{Enter}");
    const alert = h.page.getByRole("alert");
    assert.equal(alert.textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
    assert.equal(input.value, displayed[length - 1]);
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.ok(computeAccessibleDescription(input).includes(alert.textContent));
    assert.equal(h.sessionReads(), 0);
    assert.equal(h.requests.length, 0);
  }

  await h.user.type(input, "5");
  assert.equal(input.value, "ABCD-2345");
  await h.user.keyboard("{Enter}");
  assert.ok(await h.page.findByRole("heading", { name: "Device Authorized" }));
  assert.equal(h.sessionReads(), 1);
  assert.equal(h.requests.length, 1);
  const { endpoint, request } = h.requests[0];
  assert.equal(endpoint, "/api/v1/auth/device/approve");
  assert.equal(request.method, "POST");
  assert.equal(request.headers.Authorization, "Bearer synthetic-recut-session");
  assert.deepEqual(JSON.parse(request.body), { user_code: "ABCD2345" });
});

test("a server rejection replaces validation feedback in the editable field's description", async () => {
  const message = "Invalid or expired code. Please try again.";
  const h = renderDevice({ approvalError: message });
  const input = h.page.getByRole("textbox", { name: "Device code" });
  await h.user.type(input, "abcd234");
  await h.user.click(h.page.getByRole("button", { name: "Authorize Device" }));
  assert.match(h.page.getByRole("alert").textContent, /Enter 8 letters or numbers/);
  assert.equal(h.sessionReads(), 0);
  assert.equal(h.requests.length, 0);

  await h.user.type(input, "5");
  await h.user.click(h.page.getByRole("button", { name: "Authorize Device" }));
  const alert = await h.page.findByRole("alert");
  assert.equal(alert.textContent, message);
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id));
  const description = computeAccessibleDescription(input);
  assert.ok(description.includes(message));
  assert.ok(description.includes("Enter 8 letters or numbers in the format XXXX-XXXX."));
  assert.doesNotMatch(description, /Enter 8 letters or numbers\. The code is displayed/);
  assert.equal(input.value, "ABCD-2345");
  assert.equal(input.disabled, false);
  assert.equal(h.page.getByRole("button", { name: "Authorize Device" }).disabled, false);
  assert.equal(h.page.queryByRole("heading", { name: "Device Authorized" }), null);
  assert.equal(h.requests.length, 1);
});
