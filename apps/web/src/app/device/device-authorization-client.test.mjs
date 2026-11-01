import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import test, { after } from "node:test";
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

// One JSDOM is shared for the file: React and the testing-library modules are
// imported once and cannot be re-bound to a replacement document per test.
const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
const previousGlobals = new Map();
for (const [name, value] of Object.entries({
  window: dom.window, document: dom.window.document, navigator: dom.window.navigator,
  sessionStorage: dom.window.sessionStorage, HTMLElement: dom.window.HTMLElement,
})) {
  previousGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}
after(() => {
  dom.window.close();
  for (const [name, descriptor] of previousGlobals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
});

test("device code input presents its label and format hint", async () => {
  const React = await import("react");
  const { cleanup, isInaccessible, render, screen } = await import("@testing-library/react");
  try {
    const dependencies = {
      "next/image": { __esModule: true, default: () => null },
      "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
      "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
      "@/lib/posthog": { capturePostHog: async () => {} },
      "@supabase/supabase-js": { createClient() { throw new Error("Unexpected client"); } },
    };
    const Component = compile(path.join(dirname, "device-authorization-client.tsx"),
      (name) => dependencies[name] ?? runtimeRequire(name)).default;
    render(React.createElement(Component));

    const hintText = "Enter 8 letters or numbers in the format XXXX-XXXX.";
    const input = screen.getByRole("textbox", { name: "Device code", description: (value) => value.includes(hintText) });
    const label = screen.getByText("Device code", { selector: "label" });
    const hint = screen.getByText(hintText);
    assert.equal(screen.getByLabelText("Device code"), input);
    assert.equal(screen.getByPlaceholderText("XXXX-XXXX"), input);
    assert.equal(input.value, "");
    assert.equal(label.control, input);
    assert.equal(isInaccessible(label), false);
    assert.equal(isInaccessible(hint), false);
  } finally {
    cleanup();
  }
});

test("lowercase device code characters are displayed uppercase as they are entered", async () => {
  const React = await import("react");
  const { cleanup, render, screen } = await import("@testing-library/react");
  const { default: userEvent } = await import("@testing-library/user-event");
  try {
    const dependencies = {
      "next/image": { __esModule: true, default: () => null },
      "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
      "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
      "@/lib/posthog": { capturePostHog: async () => {} },
      "@supabase/supabase-js": { createClient() { throw new Error("Unexpected client"); } },
    };
    const Component = compile(path.join(dirname, "device-authorization-client.tsx"),
      (name) => dependencies[name] ?? runtimeRequire(name)).default;
    const user = userEvent.setup();
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });

    for (const [character, displayed] of [
      ["a", "A"], ["b", "AB"], ["c", "ABC"], ["d", "ABCD"],
      ["e", "ABCD-E"], ["f", "ABCD-EF"], ["g", "ABCD-EFG"], ["h", "ABCD-EFGH"],
    ]) {
      await user.type(input, character);
      assert.equal(input.value, displayed);
    }
    assert.equal(screen.queryByRole("alert"), null);

    await user.clear(input);
    await user.click(input);
    await user.paste("aBcD-eFgH");
    assert.equal(input.value, "ABCD-EFGH");
    assert.equal(screen.queryByRole("alert"), null);
  } finally {
    cleanup();
  }
});

test("blank device code shows validation without starting authorization", async () => {
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
  }
});

test("surrounding whitespace is removed before displaying and validating a device code", async () => {
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
      "@/lib/posthog": { capturePostHog: async () => {} },
      "@supabase/supabase-js": { createClient() {
        clientCalls++;
        return { auth: { getSession: async () => ({ data: { session: null }, error: new Error("Synthetic session error") }) } };
      } },
    };
    const Component = compile(path.join(dirname, "device-authorization-client.tsx"),
      (name) => dependencies[name] ?? runtimeRequire(name)).default;
    const user = userEvent.setup();
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });

    for (const [pasted, displayed] of [[" \t \n ", ""], ["  abcd234  ", "ABCD-234"]]) {
      await user.clear(input);
      await user.click(input);
      await user.paste(pasted);
      assert.equal(input.value, displayed);
      await user.click(screen.getByRole("button", { name: "Authorize Device" }));
      assert.equal(input.value, displayed);
      assert.equal(screen.getByRole("alert").textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
      assert.equal(input.getAttribute("aria-invalid"), "true");
      assert.equal(clientCalls, 0);
    }

    await user.clear(input);
    await user.paste(" \tabcd-2345\n ");
    assert.equal(input.value, "ABCD-2345");
    await user.click(screen.getByRole("button", { name: "Authorize Device" }));
    assert.equal((await screen.findByRole("alert")).textContent, "Unable to read your sign-in session. Please try again.");
    assert.equal(input.value, "ABCD-2345");
    assert.equal(clientCalls, 1);
    assert.equal(requests, 0);
  } finally {
    cleanup();
    globalThis.fetch = originalFetch;
  }
});

test("corrected device code resubmits past the prior validation error", async () => {
  const originalFetch = globalThis.fetch;
  let clientCalls = 0;
  const requests = [];
  globalThis.fetch = async (endpoint, request) => {
    requests.push({ endpoint, request });
    return { ok: true };
  };

  const React = await import("react");
  const { cleanup, render, screen } = await import("@testing-library/react");
  const { default: userEvent } = await import("@testing-library/user-event");
  const validationError = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";
  try {
    const dependencies = {
      "next/image": { __esModule: true, default: () => null },
      "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
      "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
      "@/lib/posthog": { capturePostHog: async () => { /* Analytics is intentionally inert in this test. */ } },
      "@supabase/supabase-js": { createClient() {
        clientCalls++;
        return { auth: { getSession: async () => ({ data: { session: { access_token: "synthetic-session" } }, error: null }) } };
      } },
    };
    const Component = compile(path.join(dirname, "device-authorization-client.tsx"),
      (name) => dependencies[name] ?? runtimeRequire(name)).default;
    const user = userEvent.setup();
    render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    const button = screen.getByRole("button", { name: "Authorize Device" });

    // An invalid entry is rejected locally before any network or sign-in work.
    await user.type(input, "phm123");
    await user.click(button);
    assert.equal(screen.getByRole("alert").textContent, validationError);
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.equal(clientCalls, 0);
    assert.equal(requests.length, 0);

    // Correcting the entry leaves the prior error rendered; resubmitting must
    // clear it instead of letting it block the now-valid submission.
    await user.clear(input);
    await user.type(input, "wxyz6789");
    assert.equal(input.value, "WXYZ-6789");
    assert.equal(screen.getByRole("alert").textContent, validationError);
    await user.click(button);

    assert.ok(await screen.findByRole("heading", { name: "Device Authorized" }));
    assert.equal(screen.queryByRole("alert"), null);
    assert.equal(clientCalls, 1);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].endpoint, "/api/v1/auth/device/approve");
    assert.equal(requests[0].request.headers.Authorization, "Bearer synthetic-session");
    assert.deepEqual(JSON.parse(requests[0].request.body), { user_code: "WXYZ6789" });
    assert.equal(dom.window.sessionStorage.length, 0);
  } finally {
    cleanup();
    globalThis.fetch = originalFetch;
  }
});
