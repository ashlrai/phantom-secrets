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

test("blank device code shows validation without starting authorization", async () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
  const previousGlobals = new Map();
  for (const [name, value] of Object.entries({
    window: dom.window, document: dom.window.document, navigator: dom.window.navigator,
    sessionStorage: dom.window.sessionStorage, HTMLElement: dom.window.HTMLElement,
  })) {
    previousGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
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
    const user = userEvent.setup();
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    assert.equal(input.value, "");
    await user.click(screen.getByRole("button", { name: "Authorize Device" }));

    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
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
    for (const [name, descriptor] of previousGlobals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
});
