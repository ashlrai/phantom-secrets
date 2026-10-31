import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import type { ComponentProps, ComponentType } from "react";
import test, { after, afterEach } from "node:test";
import { compileFunction } from "node:vm";
import ts from "typescript";

// Install the DOM before importing React Testing Library, which binds screen to it.
const runtimeRequire = createRequire(__filename);
const { JSDOM } = runtimeRequire("jsdom");
const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
const previousGlobals = new Map<string, PropertyDescriptor | undefined>();
for (const [name, value] of Object.entries({
  window: dom.window, document: dom.window.document, navigator: dom.window.navigator,
  sessionStorage: dom.window.sessionStorage, HTMLElement: dom.window.HTMLElement,
})) {
  previousGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}
const { cleanup, render, screen } = runtimeRequire("@testing-library/react") as typeof import("@testing-library/react");
const userEvent = (runtimeRequire("@testing-library/user-event") as typeof import("@testing-library/user-event")).default;
const originalFetch = globalThis.fetch;

afterEach(() => {
  cleanup();
  dom.window.sessionStorage.clear();
  globalThis.fetch = originalFetch;
});
after(() => {
  dom.window.close();
  for (const [name, descriptor] of previousGlobals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
  }
});

function compile(filename: string, localRequire: NodeRequire) {
  const output = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const compiled = { exports: {} };
  compileFunction(output, ["require", "module", "exports"], { filename })(localRequire, compiled, compiled.exports);
  return compiled.exports;
}

function renderDevice(getSession: () => Promise<unknown>) {
  const dirname = path.dirname(__filename);
  const dependencies: Record<string, unknown> = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }: ComponentProps<"a">) => <a {...props}>{children}</a> },
    "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => ({ auth: { getSession } }) },
  };
  const localRequire = ((name: string) => dependencies[name] ?? runtimeRequire(name)) as NodeRequire;
  const Component = compile(path.join(dirname, "device-authorization-client.tsx"), localRequire) as { default: ComponentType };
  return render(<Component.default />);
}

const hint = "Enter 8 letters or numbers in the format XXXX-XXXX.";
const validation = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";

test("device code has an accessible label and instructions", () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const input = screen.getByRole("textbox", { name: "Device code", description: /Enter 8 letters or numbers/ });
  assert.equal(screen.getByLabelText("Device code"), input);
  assert.equal(input.getAttribute("aria-invalid"), "false");
  assert.ok(input.getAttribute("aria-describedby")?.split(/\s+/).some((id) => document.getElementById(id)?.textContent === hint));
  assert.equal(screen.queryByRole("alert"), null);
});

test("invalid codes announce an associated error without starting sign-in", async () => {
  let signIns = 0;
  renderDevice(async () => { signIns++; throw new Error("Unexpected sign-in"); });
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: "Device code" });
  for (const value of ["", "ABC123"]) {
    if (value) await user.type(input, value);
    await user.click(screen.getByRole("button", { name: "Authorize Device" }));
    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, validation);
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.ok(input.getAttribute("aria-describedby")?.split(/\s+/).includes(alert.id));
    assert.equal(screen.getByRole("textbox", { name: "Device code", description: /Enter 8 letters or numbers.*Enter 8 letters or numbers/ }), input);
  }
  assert.equal(signIns, 0);
});

test("an approval error is announced and clears when a corrected code is submitted", async () => {
  let resolveRetry: (value: unknown) => void = () => {};
  let sessions = 0;
  renderDevice(() => {
    sessions++;
    if (sessions === 1) return Promise.resolve({ data: { session: { access_token: "synthetic-session" } }, error: null });
    return new Promise((resolve) => { resolveRetry = resolve; });
  });
  globalThis.fetch = async () => ({ ok: false, json: async () => ({ error: "Code expired. Try another code." }) }) as Response;
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: "Device code" });
  await user.type(input, "ABCD1234");
  await user.click(screen.getByRole("button", { name: "Authorize Device" }));
  const alert = await screen.findByRole("alert");
  assert.equal(alert.textContent, "Code expired. Try another code.");
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.ok(input.getAttribute("aria-describedby")?.split(/\s+/).includes(alert.id));
  assert.equal(screen.getByRole("textbox", { name: "Device code", description: /Code expired/ }), input);

  await user.clear(input);
  await user.type(input, "WXYZ5678");
  await user.click(screen.getByRole("button", { name: "Authorize Device" }));
  assert.equal(screen.queryByRole("alert"), null);
  assert.equal(input.getAttribute("aria-invalid"), "false");
  assert.equal(screen.queryByRole("textbox", { name: "Device code", description: /Code expired/ }), null);
  assert.equal(sessions, 2);
  resolveRetry({ data: { session: null }, error: { message: "Synthetic retry failure" } });
  assert.ok(await screen.findByRole("alert"));
});
