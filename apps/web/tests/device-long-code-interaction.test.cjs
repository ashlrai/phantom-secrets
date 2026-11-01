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

test("overlong device codes cannot start authorization, but can be corrected", async () => {
  let sessionCalls = 0;
  let oauthCalls = 0;
  const requests = [];
  const originalFetch = global.fetch;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts"),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => ({ auth: {
      getSession: async () => {
        sessionCalls++;
        return { data: { session: { access_token: "synthetic-session" } }, error: null };
      },
      signInWithOAuth: async () => { oauthCalls++; throw new Error("Unexpected OAuth"); },
    } }) },
  };
  global.fetch = async (endpoint, request) => {
    requests.push({ endpoint, request });
    return { ok: true };
  };
  try {
    const Component = compile("app/device/device-authorization-client.tsx", dependencies).default;
    const user = userEvent.setup();
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    const button = screen.getByRole("button", { name: "Authorize Device" });

    for (const method of ["type", "paste"]) {
      await user.clear(input);
      await user.click(input);
      if (method === "type") await user.type(input, "abcd23456");
      else await user.paste("  abcd-23456  ");
      assert.equal(input.value, "ABCD-23456", "extra code characters must not be silently truncated");
      if (method === "type") await user.keyboard("{Enter}");
      else await user.click(button);
      const alert = screen.getByRole("alert");
      assert.equal(alert.textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
      assert.equal(input.getAttribute("aria-invalid"), "true");
      assert.ok(input.getAttribute("aria-describedby").split(/\s+/).includes(alert.id));
      assert.equal(input.value, "ABCD-23456");
      assert.equal(input.disabled, false);
      assert.equal(button.disabled, false);
      assert.equal(sessionCalls, 0);
      assert.equal(oauthCalls, 0);
      assert.equal(requests.length, 0);
      assert.equal(sessionStorage.getItem("phantom_device_code"), null);
    }

    await user.clear(input);
    await user.type(input, "abcd2345");
    await user.click(button);
    assert.ok(await screen.findByRole("heading", { name: "Device Authorized" }));
    assert.equal(sessionCalls, 1);
    assert.equal(oauthCalls, 0);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].endpoint, "/api/v1/auth/device/approve");
    assert.deepEqual(JSON.parse(requests[0].request.body), { user_code: "ABCD2345" });
  } finally {
    cleanup();
    global.fetch = originalFetch;
    dom.window.close();
  }
});
