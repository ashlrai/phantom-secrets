const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const { JSDOM } = require("jsdom");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
global.window = dom.window;
global.document = dom.window.document;
global.sessionStorage = dom.window.sessionStorage;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
global.HTMLElement = dom.window.HTMLElement;

const React = require("react");
const { cleanup, fireEvent, render, screen, waitFor } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;
const { computeAccessibleDescription } = require("dom-accessibility-api");

function compile(file, localRequire) {
  const filename = path.join(__dirname, "../src", file);
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", output)(localRequire, module, module.exports);
  return module.exports;
}

test("device code validation is named, announced, described, and cleared on retry", async () => {
  let resolveSession;
  const session = new Promise((resolve) => { resolveSession = resolve; });
  const deviceCode = compile("lib/device-code.ts", require);
  const { default: DeviceAuthorizationClient } = compile("app/device/device-authorization-client.tsx", (name) => {
    if (name === "next/image") return { __esModule: true, default: () => null };
    if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
    if (name === "@/lib/device-code") return deviceCode;
    if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
    if (name === "@supabase/supabase-js") return { createClient: () => ({ auth: { getSession: () => session } }) };
    return require(name);
  });
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: true });

  try {
    render(React.createElement(DeviceAuthorizationClient));
    const input = screen.getByRole("textbox", { name: "Device code" });
    const hint = "Enter 8 letters or numbers in the format XXXX-XXXX.";
    const message = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";
    assert.equal(input.getAttribute("aria-invalid"), "false");
    assert.match(computeAccessibleDescription(input), /Enter 8 letters or numbers in the format XXXX-XXXX\./);
    assert.equal(screen.queryByRole("alert"), null);

    // Submit directly with a short code to exercise form validation.
    fireEvent.change(input, { target: { value: "ab12c" } });
    fireEvent.submit(input.closest("form"));
    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, message);
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.equal(screen.getByRole("textbox", { name: "Device code" }), input);
    const description = computeAccessibleDescription(input);
    assert.ok(description.includes(hint));
    assert.ok(description.includes(message));

    fireEvent.change(input, { target: { value: "abcd2345" } });
    fireEvent.click(screen.getByRole("button", { name: "Authorize Device" }));
    assert.equal(input.getAttribute("aria-invalid"), "false");
    assert.equal(screen.queryByRole("alert"), null);
    assert.ok(computeAccessibleDescription(input).includes(hint));
    assert.ok(!computeAccessibleDescription(input).includes(message));

    resolveSession({ data: { session: { access_token: "synthetic-session" } }, error: null });
    await waitFor(() => assert.ok(screen.getByRole("heading", { name: "Device Authorized" })));
  } finally {
    global.fetch = originalFetch;
    cleanup();
  }
});

for (const key of ["{Enter}", " "]) {
  test(`device authorization is reachable and submittable by keyboard (${key === " " ? "Space" : "Enter"})`, async () => {
    const requests = [];
    const deviceCode = compile("lib/device-code.ts", require);
    const { default: DeviceAuthorizationClient } = compile("app/device/device-authorization-client.tsx", (name) => {
      if (name === "next/image") return { __esModule: true, default: () => null };
      if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
      if (name === "@/lib/device-code") return deviceCode;
      if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
      if (name === "@supabase/supabase-js") return { createClient: () => ({ auth: { getSession: async () => ({ data: { session: { access_token: "synthetic-session" } }, error: null }) } }) };
      return require(name);
    });
    const originalFetch = global.fetch;
    global.fetch = async (endpoint, request) => {
      requests.push({ endpoint, request });
      return { ok: true };
    };

    try {
      const user = userEvent.setup();
      render(React.createElement(DeviceAuthorizationClient));
      const input = screen.getByRole("textbox", { name: "Device code" });
      const button = screen.getByRole("button", { name: "Authorize Device" });
      assert.equal(document.activeElement, input);
      await user.tab({ shift: true });
      assert.equal(document.activeElement, screen.getByRole("link", { name: "Phantom Secrets" }));
      await user.tab();
      assert.equal(document.activeElement, input);
      await user.keyboard("abcd2345");
      assert.equal(input.value, "ABCD-2345");
      await user.tab();
      assert.equal(document.activeElement, button);
      await user.tab({ shift: true });
      assert.equal(document.activeElement, input);
      await user.tab();
      assert.equal(document.activeElement, button);
      await user.keyboard(key);
      assert.ok(await screen.findByRole("heading", { name: "Device Authorized" }));
      assert.equal(requests.length, 1);
      assert.equal(requests[0].endpoint, "/api/v1/auth/device/approve");
      assert.deepEqual(JSON.parse(requests[0].request.body), { user_code: "ABCD2345" });
    } finally {
      global.fetch = originalFetch;
      cleanup();
    }
  });
}
