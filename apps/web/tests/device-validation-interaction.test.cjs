const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { JSDOM } = require("jsdom");
const ts = require("typescript");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
global.window = dom.window;
global.document = dom.window.document;
global.sessionStorage = dom.window.sessionStorage;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
global.HTMLElement = dom.window.HTMLElement;

const React = require("react");
const { cleanup, render, screen } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

function compile(file, localRequire) {
  const filename = path.resolve(__dirname, "../src", file);
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", output)(localRequire, module, module.exports);
  return module.exports;
}

test("submitting an empty device code shows validation without starting authorization", async () => {
  let clientCalls = 0;
  let fetchCalls = 0;
  const originalFetch = global.fetch;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts", require),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient() { clientCalls++; throw new Error("Unexpected authentication"); } },
  };
  global.fetch = async () => { fetchCalls++; throw new Error("Unexpected network request"); };
  try {
    const Component = compile("app/device/device-authorization-client.tsx", (name) => dependencies[name] ?? require(name)).default;
    const user = userEvent.setup();
    for (const method of ["click", "enter"]) {
      render(React.createElement(Component));
      const input = screen.getByRole("textbox", { name: "Device code" });
      const button = screen.getByRole("button", { name: "Authorize Device" });
      assert.equal(input.value, "");
      assert.equal(screen.queryByRole("alert"), null);
      if (method === "click") await user.click(button);
      else { await user.click(input); await user.keyboard("{Enter}"); }
      const alert = screen.getByRole("alert");
      assert.equal(alert.textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
      assert.equal(input.getAttribute("aria-invalid"), "true");
      assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id));
      assert.equal(input.value, "");
      assert.equal(input.disabled, false);
      assert.equal(button.disabled, false);
      assert.equal(clientCalls, 0);
      assert.equal(fetchCalls, 0);
      cleanup();
    }
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});

test("each short code submitted with Enter independently shows the format error", async () => {
  let clientCalls = 0;
  let fetchCalls = 0;
  const originalFetch = global.fetch;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts", require),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient() { clientCalls++; throw new Error("Unexpected authentication"); } },
  };
  global.fetch = async () => { fetchCalls++; throw new Error("Unexpected network request"); };
  try {
    const Component = compile("app/device/device-authorization-client.tsx", (name) => dependencies[name] ?? require(name)).default;
    const user = userEvent.setup();
    for (let length = 1; length < 8; length++) {
      render(React.createElement(Component));
      const input = screen.getByRole("textbox", { name: "Device code" });
      await user.type(input, "abcd2345".slice(0, length));
      assert.equal(screen.queryByRole("alert"), null);
      await user.keyboard("{Enter}");
      const alert = screen.getByRole("alert");
      assert.equal(alert.textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
      assert.equal(input.getAttribute("aria-invalid"), "true");
      assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id));
      assert.equal(input.disabled, false);
      assert.equal(clientCalls, 0);
      assert.equal(fetchCalls, 0);
      cleanup();
    }
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});

test("short codes show the format error through the form and a corrected code can be authorized", async () => {
  let clientCalls = 0;
  const requests = [];
  const originalFetch = global.fetch;
  const deviceCode = compile("lib/device-code.ts", require);
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": deviceCode,
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient() {
      clientCalls++;
      return { auth: { getSession: async () => ({ data: { session: { access_token: "synthetic-session" } }, error: null }) } };
    } },
  };
  global.fetch = async (endpoint, request) => {
    requests.push({ endpoint, request });
    return { ok: true };
  };
  try {
    const Component = compile("app/device/device-authorization-client.tsx", (name) => dependencies[name] ?? require(name)).default;
    const user = userEvent.setup();
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    const button = screen.getByRole("button", { name: "Authorize Device" });
    const displayedCodes = ["", "A", "AB", "ABC", "ABCD", "ABCD-2", "ABCD-23", "ABCD-234"];
    for (let length = 0; length < 8; length++) {
      await user.clear(input);
      if (length) await user.type(input, "abcd2345".slice(0, length));
      await user.click(button);
      assert.equal(screen.getByRole("alert").textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
      assert.equal(input.getAttribute("aria-invalid"), "true");
      const retainedInput = screen.getByRole("textbox", { name: "Device code" });
      assert.equal(retainedInput.value, displayedCodes[length]);
      assert.equal(retainedInput.disabled, false);
      assert.equal(clientCalls, 0);
      assert.equal(requests.length, 0);
    }
    await user.type(input, "5");
    assert.equal(input.value, "ABCD-2345");
    await user.click(button);
    assert.ok(await screen.findByRole("heading", { name: "Device Authorized" }));
    assert.equal(clientCalls, 1);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].endpoint, "/api/v1/auth/device/approve");
    assert.deepEqual(JSON.parse(requests[0].request.body), { user_code: "ABCD2345" });
  } finally {
    cleanup();
    global.fetch = originalFetch;
    dom.window.close();
  }
});
