/* eslint-disable @typescript-eslint/no-require-imports -- This Node test compiles the TSX component as CommonJS. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const { JSDOM } = require("jsdom");

function compile(filename, dependencies = {}) {
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const compiledModule = { exports: {} };
  new Function("require", "module", "exports", output)(
    (name) => dependencies[name] ?? require(name), compiledModule, compiledModule.exports,
  );
  return compiledModule.exports;
}

test("lowercase device codes are normalized and displayed as they are entered", async () => {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
  for (const name of ["window", "document", "navigator", "HTMLElement"]) {
    Object.defineProperty(globalThis, name, { value: dom.window[name], configurable: true, writable: true });
  }
  const React = require("react");
  const { render, cleanup } = require("@testing-library/react");
  const userEvent = require("@testing-library/user-event").default;
  const deviceCode = compile(path.resolve(__dirname, "../../lib/device-code.ts"));
  let clientCalls = 0;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": deviceCode,
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient() { clientCalls++; throw new Error("Unexpected API client"); } },
  };
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = () => { fetchCalls++; throw new Error("Unexpected API request"); };
  try {
    const Component = compile(path.join(__dirname, "device-authorization-client.tsx"), dependencies).default;
    const page = render(React.createElement(Component));
    const input = page.getByRole("textbox", { name: "Device code" });
    const user = userEvent.setup();

    await user.type(input, "ab12");
    assert.equal(input.value, "AB12");
    await user.type(input, "cd34");
    assert.equal(input.value, "AB12-CD34");
    assert.equal(deviceCode.normalizeDeviceUserCode(input.value), "AB12CD34");

    await user.clear(input);
    await user.click(input);
    await user.paste("wxyz-67 89!");
    assert.equal(input.value, "WXYZ-6789");
    assert.equal(deviceCode.normalizeDeviceUserCode(input.value), "WXYZ6789");
    assert.equal(input.getAttribute("aria-invalid"), "false");
    assert.equal(clientCalls, 0);
    assert.equal(fetchCalls, 0);
  } finally {
    cleanup();
    globalThis.fetch = originalFetch;
    dom.window.close();
  }
});
