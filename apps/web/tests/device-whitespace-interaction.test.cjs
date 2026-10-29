const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { JSDOM } = require("jsdom");
const ts = require("typescript");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
for (const name of ["window", "document", "navigator", "HTMLElement", "sessionStorage"]) {
  Object.defineProperty(globalThis, name, { value: dom.window[name], configurable: true, writable: true });
}
const React = require("react");
const { cleanup, render, screen } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

function compile(file, dependencies = {}) {
  const filename = path.join(__dirname, "../src", file);
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", output)(
    (name) => dependencies[name] ?? require(name), module, module.exports,
  );
  return module.exports;
}

test("pasted leading and trailing whitespace is removed before device code validation", async () => {
  let sessionCalls = 0;
  let fetchCalls = 0;
  const originalFetch = global.fetch;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts"),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => ({ auth: { getSession: async () => {
      sessionCalls++;
      return { data: { session: null }, error: new Error("synthetic session error") };
    } } }) },
  };
  global.fetch = async () => { fetchCalls++; throw new Error("Unexpected network request"); };
  try {
    const Component = compile("app/device/device-authorization-client.tsx", dependencies).default;
    const user = userEvent.setup();
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    const button = screen.getByRole("button", { name: "Authorize Device" });

    for (const [pasted, displayed] of [["  abcd234 ", "ABCD-234"], [" abcd23456  ", "ABCD-23456"]]) {
      await user.clear(input);
      await user.click(input);
      await user.paste(pasted);
      assert.equal(input.value, displayed);
      await user.click(button);
      assert.equal(screen.getByRole("alert").textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
      assert.equal(input.getAttribute("aria-invalid"), "true");
      assert.equal(sessionCalls, 0);
    }

    for (const pasted of ["  abcd2345", "abcd2345  ", " \tabcd-2345\n "]) {
      await user.clear(input);
      await user.click(input);
      await user.paste(pasted);
      assert.equal(input.value, "ABCD-2345");
      await user.click(button);
      assert.equal((await screen.findByRole("alert")).textContent, "Unable to read your sign-in session. Please try again.");
    }
    assert.equal(sessionCalls, 3);
    assert.equal(fetchCalls, 0);
  } finally {
    cleanup();
    global.fetch = originalFetch;
    dom.window.close();
  }
});
