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
const { cleanup, isInaccessible, render, screen, within } = runtimeRequire("@testing-library/react") as typeof import("@testing-library/react");
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
    "next/link": { __esModule: true, default: ({ children, ...props }: ComponentProps<"a">) => createElement("a", props, children) },
    "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => ({ auth: { getSession } }) },
  };
  const localRequire = ((name: string) => dependencies[name] ?? runtimeRequire(name)) as NodeRequire;
  const Component = compile(path.join(dirname, "device-authorization-client.tsx"), localRequire) as { default: ComponentType };
  return render(<Component.default />);
}

const title = "Authorize Device";
const purpose = /code shown in your terminal to authorize this device/;

test("the visible heading names the device-code form", () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const heading = screen.getByRole("heading", { level: 1, name: title });
  assert.equal(isInaccessible(heading), false);

  // The form landmark's accessible name is the visible heading itself: the
  // association is a real aria-labelledby reference, not shared screen text.
  const form = screen.getByRole("form", { name: title });
  assert.equal(form.tagName, "FORM");
  assert.equal(form.getAttribute("aria-labelledby"), heading.id);

  // The named form holds the controls its heading describes: the labelled
  // device-code field and the submit that authorizes it.
  const input = within(form).getByRole("textbox", { name: "Device code" });
  assert.equal(screen.getByLabelText("Device code"), input);
  assert.ok(within(form).getByRole("button", { name: title }));
});

test("the purpose copy describes the named form through a validation error", async () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const form = screen.getByRole("form", { name: title, description: purpose });
  const purposeNode = screen.getByText(purpose);
  assert.equal(isInaccessible(purposeNode), false);
  assert.ok(purposeNode.id.length > 0);
  assert.ok(form.getAttribute("aria-describedby")?.split(/\s+/).includes(purposeNode.id));

  const user = userEvent.setup();
  await user.click(within(form).getByRole("button", { name: title }));
  const alert = screen.getByRole("alert");
  assert.equal(alert.textContent, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");

  // Rejected input must not detach the heading from the form it names.
  const heading = screen.getByRole("heading", { level: 1, name: title });
  assert.equal(isInaccessible(heading), false);
  assert.equal(screen.getByRole("form", { name: title, description: purpose }), form);
});
