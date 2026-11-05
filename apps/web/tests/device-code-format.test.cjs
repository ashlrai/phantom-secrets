const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { after, test } = require("node:test");
const ts = require("typescript");
const { JSDOM } = require("jsdom");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
for (const name of ["window", "document", "navigator", "HTMLElement"]) {
  Object.defineProperty(globalThis, name, { value: dom.window[name], configurable: true, writable: true });
}
global.sessionStorage = dom.window.sessionStorage;

const React = require("react");
const { render, cleanup, screen } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

after(() => dom.window.close());

function compile(filename, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "../src", filename), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", output)(
    (name) => dependencies[name] ?? require(name), module, module.exports,
  );
  return module.exports;
}

function componentDeps(supabaseBehavior, fetchHandler) {
  return {
    dependencies: {
      "next/image": { __esModule: true, default: () => null },
      "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
      "@/lib/device-code": compile("lib/device-code.ts"),
      "@/lib/posthog": { capturePostHog: async () => {} },
      "@supabase/supabase-js": { createClient() {
        return supabaseBehavior?.() ?? {
          auth: { getSession: async () => ({ data: { session: null }, error: null }) }
        };
      } },
    },
    fetchHandler: fetchHandler ?? (async () => { throw new Error("Unexpected network request"); }),
  };
}

const validationError = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";

test("empty device code produces a validation error without submitting the form", async () => {
  const originalFetch = global.fetch;
  let supabaseCalls = 0;
  let fetchCalls = 0;
  const requests = [];

  const deps = componentDeps(
    () => { supabaseCalls++; throw new Error("Unexpected Supabase call"); },
    async (url, opts) => { fetchCalls++; requests.push({ url, opts }); throw new Error("Unexpected fetch"); },
  );

  global.fetch = deps.fetchHandler;

  try {
    const Component = compile("app/device/device-authorization-client.tsx", deps.dependencies).default;
    const user = userEvent.setup();

    render(React.createElement(Component));

    const input = screen.getByRole("textbox", { name: "Device code" });
    const button = screen.getByRole("button", { name: "Authorize Device" });

    // The form starts with an empty input
    assert.equal(input.value, "");

    // Click submit with empty code
    await user.click(button);

    // A validation error alert should appear
    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, validationError);
    assert.equal(alert.id, "device-error");

    // The error is linked to the input for accessibility
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.ok(
      input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id),
      "aria-describedby should reference the error element"
    );

    // No submission occurred: no auth calls, no network requests, no Supabase
    assert.equal(supabaseCalls, 0, "Supabase was not called");
    assert.equal(fetchCalls, 0, "fetch was not called");
    assert.equal(requests.length, 0, "no form submission requests");

    // The input remains editable so the user can enter a valid code
    assert.equal(input.disabled, false, "input is still editable");
    assert.equal(button.disabled, false, "submit button is still enabled");
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});

test("empty device code validation is also triggered by pressing Enter", async () => {
  const originalFetch = global.fetch;
  let supabaseCalls = 0;
  let fetchCalls = 0;

  const deps = componentDeps(
    () => { supabaseCalls++; throw new Error("Unexpected Supabase call"); },
    async () => { fetchCalls++; throw new Error("Unexpected fetch"); },
  );

  global.fetch = deps.fetchHandler;

  try {
    const Component = compile("app/device/device-authorization-client.tsx", deps.dependencies).default;
    const user = userEvent.setup();

    render(React.createElement(Component));

    const input = screen.getByRole("textbox", { name: "Device code" });

    // Submit via keyboard: focus input and press Enter
    await user.click(input);
    await user.keyboard("{Enter}");

    // Validation error appears even for keyboard submission
    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, validationError);

    // No network or auth activity
    assert.equal(supabaseCalls, 0, "Supabase was not called");
    assert.equal(fetchCalls, 0, "fetch was not called");
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});

test("typing then clearing the device code retains empty validation behavior", async () => {
  const originalFetch = global.fetch;
  let supabaseCalls = 0;
  let fetchCalls = 0;

  const deps = componentDeps(
    () => { supabaseCalls++; throw new Error("Unexpected Supabase call"); },
    async () => { fetchCalls++; throw new Error("Unexpected fetch"); },
  );

  global.fetch = deps.fetchHandler;

  try {
    const Component = compile("app/device/device-authorization-client.tsx", deps.dependencies).default;
    const user = userEvent.setup();

    render(React.createElement(Component));

    const input = screen.getByRole("textbox", { name: "Device code" });
    const button = screen.getByRole("button", { name: "Authorize Device" });

    // Type a valid code, then clear it
    await user.type(input, "abcd2345");
    assert.equal(input.value, "ABCD-2345");
    await user.clear(input);
    assert.equal(input.value, "");

    // Submit the now-empty form
    await user.click(button);

    // Same validation error as an empty form
    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, validationError);
    assert.equal(supabaseCalls, 0, "Supabase was not called");
    assert.equal(fetchCalls, 0, "fetch was not called");
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});
