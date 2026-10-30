import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { compileFunction } from "node:vm";
import { JSDOM } from "jsdom";
import ts from "typescript";

const runtimeRequire = createRequire(import.meta.url);
const dirname = path.dirname(fileURLToPath(import.meta.url));

function compile(filename, localRequire) {
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const compiledModule = { exports: {} };
  compileFunction(output, ["require", "module", "exports"], { filename })(localRequire, compiledModule, compiledModule.exports);
  return compiledModule.exports;
}

function installDomGlobals(dom) {
  const previousGlobals = new Map();
  for (const [name, value] of Object.entries({
    window: dom.window, document: dom.window.document, navigator: dom.window.navigator,
    sessionStorage: dom.window.sessionStorage, HTMLElement: dom.window.HTMLElement,
  })) {
    previousGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
  return previousGlobals;
}

function restoreGlobals(previousGlobals) {
  for (const [name, descriptor] of previousGlobals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
}

const FORMAT_ERROR = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";

test("blank device code shows validation without starting authorization", async () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
  const previousGlobals = installDomGlobals(dom);
  const originalFetch = globalThis.fetch;
  let clientCalls = 0;
  let requests = 0;
  globalThis.fetch = async () => { requests++; throw new Error("Unexpected request"); };

  const React = await import("react");
  const { cleanup, render, screen } = await import("@testing-library/react");
  const { default: userEvent } = await import("@testing-library/user-event");
  try {
    const dependencies = {
      "next/image": { __esModule: true, default: () => null },
      "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
      "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
      "@/lib/posthog": { capturePostHog: async () => { /* Analytics is intentionally inert in this test. */ } },
      "@supabase/supabase-js": { createClient() { clientCalls++; throw new Error("Unexpected client"); } },
    };
    const Component = compile(path.join(dirname, "device-authorization-client.tsx"),
      (name) => dependencies[name] ?? runtimeRequire(name)).default;
    const user = userEvent.setup({ document: dom.window.document });
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    assert.equal(input.value, "");
    await user.click(screen.getByRole("button", { name: "Authorize Device" }));

    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, FORMAT_ERROR);
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id));
    assert.equal(input.value, "");
    assert.equal(clientCalls, 0);
    assert.equal(requests, 0);
    assert.equal(dom.window.sessionStorage.length, 0);
  } finally {
    cleanup();
    globalThis.fetch = originalFetch;
    dom.window.close();
    restoreGlobals(previousGlobals);
  }
});

test("punctuation outside the displayed format shows validation and prevents submission", async () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
  const previousGlobals = installDomGlobals(dom);
  const originalFetch = globalThis.fetch;
  let clientCalls = 0;
  let sessionCalls = 0;
  let requests = 0;
  globalThis.fetch = async () => { requests++; throw new Error("Unexpected request"); };

  const React = await import("react");
  const { cleanup, render } = await import("@testing-library/react");
  const { default: userEvent } = await import("@testing-library/user-event");
  try {
    const dependencies = {
      "next/image": { __esModule: true, default: () => null },
      "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
      "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
      "@/lib/posthog": { capturePostHog: async () => { /* Analytics is intentionally inert in this test. */ } },
      "@supabase/supabase-js": { createClient() {
        clientCalls++;
        return { auth: { getSession: async () => {
          sessionCalls++;
          return { data: { session: null }, error: new Error("synthetic session error") };
        } } };
      } },
    };
    const Component = compile(path.join(dirname, "device-authorization-client.tsx"),
      (name) => dependencies[name] ?? runtimeRequire(name)).default;
    // user-event and `screen` bind the module-load document; pass this test's
    // document to setup and query the render result so both target this JSDOM.
    const user = userEvent.setup({ document: dom.window.document });
    const view = render(React.createElement(Component));
    const input = view.getByRole("textbox", { name: "Device code" });
    const button = view.getByRole("button", { name: "Authorize Device" });

    // Separators the XXXX-XXXX display never shows must not count toward the
    // eight characters or leave stray punctuation behind in the field.
    for (const [pasted, displayed] of [
      ["ABCD-2345-6", "ABCD-23456"],
      ["AB.CD-EF.G", "ABCD-EFG"],
      ["ab cd_ef", "ABCD-EF"],
      ["ABCD–EFGHI", "ABCD-EFGHI"],
      ["-.-.-.-", ""],
    ]) {
      await user.clear(input);
      await user.click(input);
      await user.paste(pasted);
      assert.equal(input.value, displayed);
      await user.click(button);
      const alert = view.getByRole("alert");
      assert.equal(alert.textContent, FORMAT_ERROR);
      assert.equal(input.getAttribute("aria-invalid"), "true");
      assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id));
      assert.equal(input.value, displayed);
      assert.equal(input.disabled, false);
      assert.equal(button.disabled, false);
      assert.equal(clientCalls, 0);
      assert.equal(sessionCalls, 0);
      assert.equal(requests, 0);
      assert.equal(dom.window.sessionStorage.length, 0);
    }

    await user.clear(input);
    await user.type(input, "ab.cd.ef");
    assert.equal(input.value, "ABCD-EF");
    await user.click(button);
    assert.equal(view.getByRole("alert").textContent, FORMAT_ERROR);
    assert.equal(clientCalls, 0);
    assert.equal(sessionCalls, 0);
    assert.equal(requests, 0);

    // A corrected code reaches sign-in, so validation alone blocked submission.
    await user.clear(input);
    await user.type(input, "wxyz6789");
    assert.equal(input.value, "WXYZ-6789");
    await user.click(button);
    assert.equal((await view.findByRole("alert")).textContent,
      "Unable to read your sign-in session. Please try again.");
    assert.equal(clientCalls, 1);
    assert.equal(sessionCalls, 1);
    assert.equal(requests, 0);
  } finally {
    cleanup();
    globalThis.fetch = originalFetch;
    dom.window.close();
    restoreGlobals(previousGlobals);
  }
});
