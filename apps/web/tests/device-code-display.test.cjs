const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const { JSDOM } = require("jsdom");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
for (const name of ["window", "document", "navigator", "HTMLElement"]) {
  Object.defineProperty(globalThis, name, { value: dom.window[name], configurable: true, writable: true });
}
const React = require("react");
const { render, cleanup } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

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

test("public device form displays eight characters with a separator when typed or pasted", async () => {
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts"),
    "@/lib/posthog": { capturePostHog: async () => {} },
  };
  const DeviceAuthorizationClient = compile("app/device/device-authorization-client.tsx", dependencies).default;
  const user = userEvent.setup();
  try {
    const screen = render(React.createElement(DeviceAuthorizationClient));
    const input = screen.getByRole("textbox", { name: "Device code", description: /8 letters or numbers.*XXXX-XXXX/ });
    const button = screen.getByRole("button", { name: "Authorize Device" });
    assert.equal(input.placeholder, "XXXX-XXXX");
    assert.equal(button.disabled, false);

    await user.type(input, "abcd");
    assert.equal(input.value, "ABCD");
    await user.type(input, "234");
    assert.equal(input.value, "ABCD-234");
    await user.click(button);
    assert.match(screen.getByRole("alert").textContent, /Enter 8 letters or numbers/);
    await user.type(input, "5");
    assert.equal(input.value, "ABCD-2345");
    assert.equal(button.disabled, false);

    await user.type(input, "6");
    assert.equal(input.value, "ABCD-23456");
    await user.click(button);
    assert.match(screen.getByRole("alert").textContent, /Enter 8 letters or numbers/);

    await user.clear(input);
    await user.click(input);
    await user.paste("wxyz6789");
    assert.equal(input.value, "WXYZ-6789");
    assert.equal(button.disabled, false);
  } finally {
    cleanup();
    dom.window.close();
  }
});
