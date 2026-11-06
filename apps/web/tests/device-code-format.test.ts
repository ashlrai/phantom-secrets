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
  path.resolve(dirname, "../src/lib/device-code.ts"),
  runtimeRequire,
) as typeof import("../src/lib/device-code");

function renderDevice(calls: string[]) {
  const dependencies: Record<string, unknown> = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }: ComponentProps<"a">) => createElement("a", props, children) },
    "@/lib/device-code": deviceCode,
    "@/lib/posthog": { capturePostHog: async () => { calls.push("posthog"); } },
    "@supabase/supabase-js": {
      createClient: () => ({
        auth: {
          getSession: async () => { calls.push("getSession"); return { data: { session: null }, error: null }; },
          signInWithOAuth: async () => { calls.push("signInWithOAuth"); return { error: null }; },
        },
      }),
    },
  };
  const localRequire = ((name: string) => dependencies[name] ?? runtimeRequire(name)) as NodeRequire;
  const Component = compile(path.join(dirname, "../src/app/device/device-authorization-client.tsx"), localRequire) as { default: ComponentType };
  return render(createElement(Component.default));
}

const message = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";

// Whitespace is not part of the code alphabet, so a whitespace-only entry
// formats to an empty field and must be rejected as a length error without
// starting sign-in, approval, or analytics.
for (const [name, pasted] of [
  ["spaces", "   "],
  ["mixed whitespace", " \t\n "],
  ["unicode whitespace", "\u00a0\u2007\u2009"],
  ["separator-only", " - . "],
] as const) {
  test(`a pasted whitespace-only code (${name}) shows the format error without submitting`, async () => {
    const calls: string[] = [];
    let fetched = false;
    globalThis.fetch = (async () => { fetched = true; return { ok: true } as Response; }) as typeof fetch;
    renderDevice(calls);
    const user = userEvent.setup();
    const input = screen.getByRole("textbox", { name: "Device code" }) as HTMLInputElement;
    const button = screen.getByRole("button", { name: "Authorize Device" });

    await user.click(input);
    await user.paste(pasted);
    assert.equal(input.value, "");
    assert.equal(screen.queryByRole("alert"), null);
    await user.click(button);

    const alert = screen.getByRole("alert");
    assert.equal(alert.textContent, message);
    assert.equal(alert.id, "device-error");
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.ok(input.getAttribute("aria-describedby")?.split(/\s+/).includes(alert.id));

    // Nothing was submitted: no sign-in, no network call, no stored code, and
    // the form stays editable so the user can enter the real code.
    assert.deepEqual(calls, []);
    assert.equal(fetched, false);
    assert.equal(dom.window.sessionStorage.length, 0);
    assert.equal(input.disabled, false);
    assert.equal(button.hasAttribute("disabled"), false);
    assert.equal(input.value, "");
  });
}

test("typed spaces followed by Enter show the same feedback without submitting", async () => {
  const calls: string[] = [];
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return { ok: true } as Response; }) as typeof fetch;
  renderDevice(calls);
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: "Device code" }) as HTMLInputElement;

  await user.type(input, "   ");
  assert.equal(input.value, "");
  assert.equal(screen.queryByRole("alert"), null);
  await user.keyboard("{Enter}");

  const alert = screen.getByRole("alert");
  assert.equal(alert.textContent, message);
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.ok(input.getAttribute("aria-describedby")?.split(/\s+/).includes(alert.id));
  assert.deepEqual(calls, []);
  assert.equal(fetched, false);
  assert.equal(dom.window.sessionStorage.length, 0);
  assert.equal(input.disabled, false);
});
