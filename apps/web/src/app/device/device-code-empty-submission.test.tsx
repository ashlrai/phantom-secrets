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
const { cleanup, isInaccessible, render, screen } = runtimeRequire("@testing-library/react") as typeof import("@testing-library/react");
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

function renderDevice(calls: string[]) {
  const dependencies: Record<string, unknown> = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }: ComponentProps<"a">) => createElement("a", props, children) },
    "@/lib/device-code": compile(path.resolve(dirname, "../../lib/device-code.ts"), runtimeRequire),
    "@/lib/posthog": { capturePostHog: async () => { calls.push("posthog"); } },
    "@supabase/supabase-js": {
      createClient: () => {
        calls.push("createClient");
        return {
          auth: {
            getSession: async () => { calls.push("getSession"); return { data: { session: null }, error: null }; },
            signInWithOAuth: async () => { calls.push("signInWithOAuth"); return { error: null }; },
          },
        };
      },
    },
  };
  const localRequire = ((name: string) => dependencies[name] ?? runtimeRequire(name)) as NodeRequire;
  const Component = compile(path.join(dirname, "device-authorization-client.tsx"), localRequire) as { default: ComponentType };
  return render(<Component.default />);
}

const message = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";
const follows = dom.window.Node.DOCUMENT_POSITION_FOLLOWING;

function assertEmptySubmissionRejected(input: HTMLInputElement, button: HTMLElement, calls: string[], fetched: () => boolean) {
  // Exactly one error presents as visible inline text, announced through the field's description.
  const alerts = screen.getAllByRole("alert");
  assert.equal(alerts.length, 1);
  const alert = alerts[0];
  assert.equal(alert.tagName, "P");
  assert.equal(alert.id, "device-error");
  assert.equal(alert.textContent, message);
  assert.equal(isInaccessible(alert), false);

  // The error sits between the format hint and the submit control inside the named form.
  const form = screen.getByRole("form", { name: "Authorize Device" });
  const hint = document.getElementById("device-code-hint");
  assert.ok(hint !== null && form.contains(hint));
  assert.equal(alert.parentElement, form);
  assert.ok(hint.compareDocumentPosition(alert) & follows);
  assert.ok(alert.compareDocumentPosition(button) & follows);
  assert.equal(input.getAttribute("aria-describedby"), "device-code-hint device-error device-help");
  assert.equal(input.getAttribute("aria-invalid"), "true");

  // Nothing was submitted and nothing stale blocks retry: no sign-in, no
  // network, no stored code, no success panel, controls stay enabled.
  assert.equal(input.value, "");
  assert.equal(input.disabled, false);
  assert.equal(button.textContent, "Authorize Device");
  assert.equal(button.hasAttribute("disabled"), false);
  assert.equal(input.closest("section")?.getAttribute("aria-busy"), "false");
  assert.equal(screen.queryByRole("heading", { name: "Device Authorized" }), null);
  assert.equal(screen.queryByRole("button", { name: "Signing in with GitHub..." }), null);
  assert.deepEqual(calls, []);
  assert.equal(fetched(), false);
  assert.equal(dom.window.sessionStorage.length, 0);
  return alert;
}

test("submitting the untouched empty field presents the validation message in place", async () => {
  const calls: string[] = [];
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return { ok: true } as Response; }) as typeof fetch;
  renderDevice(calls);
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: "Device code" }) as HTMLInputElement;
  const button = screen.getByRole("button", { name: "Authorize Device" });

  // Before submitting there is no error: the field is simply empty.
  assert.equal(input.value, "");
  assert.equal(screen.queryByRole("alert"), null);
  assert.equal(input.getAttribute("aria-invalid"), "false");

  await user.click(button);
  assertEmptySubmissionRejected(input, button, calls, () => fetched);
});

test("pressing Enter on the empty field presents the same validation message", async () => {
  const calls: string[] = [];
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return { ok: true } as Response; }) as typeof fetch;
  renderDevice(calls);
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: "Device code" }) as HTMLInputElement;
  const button = screen.getByRole("button", { name: "Authorize Device" });

  await user.click(input);
  await user.keyboard("{Enter}");
  assertEmptySubmissionRejected(input, button, calls, () => fetched);
});

test("a cleared code presents the validation message on submission", async () => {
  const calls: string[] = [];
  let fetched = false;
  globalThis.fetch = (async () => { fetched = true; return { ok: true } as Response; }) as typeof fetch;
  renderDevice(calls);
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: "Device code" }) as HTMLInputElement;
  const button = screen.getByRole("button", { name: "Authorize Device" });

  // Clearing returns to the same empty state; submitting must not resurrect the erased code.
  await user.type(input, "abcd2345");
  assert.equal(input.value, "ABCD-2345");
  await user.clear(input);
  assert.equal(input.value, "");

  await user.click(button);
  assertEmptySubmissionRejected(input, button, calls, () => fetched);
});

test("submitting the empty field again re-presents the same single error", async () => {
  const calls: string[] = [];
  renderDevice(calls);
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: "Device code" }) as HTMLInputElement;
  const button = screen.getByRole("button", { name: "Authorize Device" });

  await user.click(button);
  const first = screen.getByRole("alert");

  // A second empty submission re-presents the same error element — no duplicates.
  await user.click(button);
  const alerts = screen.getAllByRole("alert");
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0], first);
  assert.equal(alerts[0].textContent, message);
  assert.equal(input.value, "");
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.deepEqual(calls, []);
});
