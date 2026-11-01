import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { createElement, type ComponentProps, type ComponentType } from "react";
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

const dirname = path.dirname(__filename);
const deviceCode = compile(
  path.resolve(dirname, "../../lib/device-code.ts"),
  runtimeRequire,
) as typeof import("../../lib/device-code");

function renderDevice(getSession: () => Promise<unknown>) {
  const dependencies: Record<string, unknown> = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }: ComponentProps<"a">) => createElement("a", props, children) },
    "@/lib/device-code": deviceCode,
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => ({ auth: { getSession } }) },
  };
  const localRequire = ((name: string) => dependencies[name] ?? runtimeRequire(name)) as NodeRequire;
  const Component = compile(path.join(dirname, "device-authorization-client.tsx"), localRequire) as { default: ComponentType };
  return render(<Component.default />);
}

const label = "Device code";
const placeholder = "XXXX-XXXX";

test("the device code input pairs the XXXX-XXXX placeholder with an accessible label", () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const input = screen.getByRole("textbox", { name: label });
  assert.equal(screen.getByLabelText(label), input);
  assert.equal(input.getAttribute("placeholder"), placeholder);

  // The placeholder spells out the accepted shape, so filling each X with a
  // code character must already satisfy the formatter and validator.
  const filled = placeholder.replace(/X/g, "A");
  assert.equal(deviceCode.formatDeviceUserCode(filled.toLowerCase()), filled);
  assert.ok(deviceCode.isValidDeviceUserCode(filled));

  // The accessible description names the same format the placeholder shows.
  const describedBy = input.getAttribute("aria-describedby")?.split(/\s+/) ?? [];
  const descriptions = describedBy.map((id) => document.getElementById(id)?.textContent ?? "");
  assert.ok(descriptions.some((text) => text.includes(placeholder)));
});

test("the placeholder never stands in for the label or a real value", async () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;
  // A real <label> supplies the name: nothing relies on the placeholder,
  // which browsers hide as soon as the field holds text.
  assert.equal(input.value, "");
  assert.equal(input.hasAttribute("aria-label"), false);
  assert.equal(input.hasAttribute("aria-labelledby"), false);
  await user.type(input, "wxyz6789");
  assert.equal(input.value, "WXYZ-6789");
  await user.clear(input);
  assert.equal(input.value, "");
  assert.equal(input.getAttribute("placeholder"), placeholder);
  assert.equal(screen.getByRole("textbox", { name: label }), input);
});

test("the label and placeholder remain usable after a validation error", async () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;

  await user.click(screen.getByRole("button", { name: "Authorize Device" }));
  const error = screen.getByRole("alert");
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.equal(screen.getByPlaceholderText(placeholder), input);
  assert.equal(screen.getByRole("textbox", { name: label, description: /Enter 8 letters or numbers.*code is displayed/ }), input);
  assert.ok(input.getAttribute("aria-describedby")?.split(/\s+/).includes(error.id));

  // A click on the visible label must focus the same field even after errors.
  await user.click(screen.getByText(label, { selector: "label" }));
  assert.equal(document.activeElement, input);
});
