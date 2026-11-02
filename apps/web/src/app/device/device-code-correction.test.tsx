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

function renderDevice(auth: Record<string, unknown>) {
  const dependencies: Record<string, unknown> = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }: ComponentProps<"a">) => createElement("a", props, children) },
    "@/lib/device-code": deviceCode,
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient: () => ({ auth }) },
  };
  const localRequire = ((name: string) => dependencies[name] ?? runtimeRequire(name)) as NodeRequire;
  const Component = compile(path.join(dirname, "device-authorization-client.tsx"), localRequire) as { default: ComponentType };
  return render(<Component.default />);
}

const label = "Device code";
const message = "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.";

test("backspacing the extra character off a rejected nine-character code corrects it in place", async () => {
  let sessionCalls = 0;
  const requests: { endpoint: string; body: unknown }[] = [];
  renderDevice({
    getSession: async () => {
      sessionCalls++;
      return { data: { session: { access_token: "synthetic-session" } }, error: null };
    },
    signInWithOAuth: async () => { throw new Error("Unexpected OAuth"); },
  });
  globalThis.fetch = (async (endpoint: RequestInfo | URL, init?: RequestInit) => {
    requests.push({ endpoint: String(endpoint), body: JSON.parse(String(init?.body)) });
    return { ok: true } as Response;
  }) as typeof fetch;
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;
  const button = screen.getByRole("button", { name: "Authorize Device" });

  // Nine characters are presented exactly as typed — the extra character is
  // not silently truncated — and the submission is rejected without sign-in.
  await user.type(input, "abcd23456");
  assert.equal(input.value, "ABCD-23456");
  await user.click(button);
  const alert = screen.getByRole("alert");
  assert.equal(alert.textContent, message);
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.equal(input.disabled, false);
  assert.equal(sessionCalls, 0);
  assert.equal(requests.length, 0);

  // The field still takes focus and edits in place: one Backspace removes the
  // extra character, the display re-formats, and the same error stays
  // rendered until a valid submission replaces it.
  await user.click(input);
  assert.equal(document.activeElement, input);
  await user.keyboard("{Backspace}");
  assert.equal(input.value, "ABCD-2345");
  assert.equal(screen.getByRole("alert"), alert);
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.equal(input.disabled, false);
  assert.equal(sessionCalls, 0);
  assert.equal(requests.length, 0);

  // The corrected value is what the retry submits.
  await user.click(button);
  assert.ok(await screen.findByRole("heading", { name: "Device Authorized" }));
  assert.equal(screen.queryByRole("alert"), null);
  assert.equal(sessionCalls, 1);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].endpoint, "/api/v1/auth/device/approve");
  assert.deepEqual(requests[0].body, { user_code: "ABCD2345" });
});

test("deleting characters and typing replacements corrects a rejected short code", async () => {
  let oauthCalls = 0;
  renderDevice({
    getSession: async () => ({ data: { session: null }, error: null }),
    signInWithOAuth: async () => { oauthCalls++; return { error: null }; },
  });
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;
  const button = screen.getByRole("button", { name: "Authorize Device" });

  await user.type(input, "wxyz12");
  assert.equal(input.value, "WXYZ-12");
  await user.click(button);
  const alert = screen.getByRole("alert");
  assert.equal(alert.textContent, message);
  assert.equal(oauthCalls, 0);
  assert.equal(dom.window.sessionStorage.length, 0);

  // Backspacing lifts the rejected suffix — including the separator — and
  // fresh typing re-flows into the same XXXX-XXXX presentation while the
  // error remains on screen.
  await user.click(input);
  await user.keyboard("{Backspace}{Backspace}");
  assert.equal(input.value, "WXYZ");
  await user.type(input, "3456");
  assert.equal(input.value, "WXYZ-3456");
  assert.equal(screen.getByRole("alert"), alert);
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.equal(input.disabled, false);

  // The corrected code clears the error and is the one carried into sign-in.
  await user.click(button);
  await screen.findByRole("button", { name: "Signing in with GitHub..." });
  assert.equal(screen.queryByRole("alert"), null);
  assert.equal(input.getAttribute("aria-invalid"), "false");
  assert.equal(oauthCalls, 1);
  assert.equal(dom.window.sessionStorage.getItem("phantom_device_code"), "WXYZ-3456");
  assert.equal(dom.window.sessionStorage.getItem("phantom_device_oauth_pending"), "1");
});

test("selecting a stray character mid-code and deleting it corrects the rejected entry", async () => {
  let sessionCalls = 0;
  const requests: { endpoint: string; body: unknown }[] = [];
  renderDevice({
    getSession: async () => {
      sessionCalls++;
      return { data: { session: { access_token: "synthetic-session" } }, error: null };
    },
    signInWithOAuth: async () => { throw new Error("Unexpected OAuth"); },
  });
  globalThis.fetch = (async (endpoint: RequestInfo | URL, init?: RequestInit) => {
    requests.push({ endpoint: String(endpoint), body: JSON.parse(String(init?.body)) });
    return { ok: true } as Response;
  }) as typeof fetch;
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;

  // A stray X leaves nine code characters, rejected like any wrong length.
  await user.type(input, "abcd2x456");
  assert.equal(input.value, "ABCD-2X456");
  await user.click(screen.getByRole("button", { name: "Authorize Device" }));
  const alert = screen.getByRole("alert");
  assert.equal(alert.textContent, message);
  assert.equal(sessionCalls, 0);
  assert.equal(requests.length, 0);

  // The user can target the stray character inside the field — select it and
  // press Backspace — instead of re-entering the whole code.
  await user.click(input);
  input.setSelectionRange(6, 7);
  await user.keyboard("{Backspace}");
  assert.equal(input.value, "ABCD-2456");
  assert.equal(screen.getByRole("alert"), alert);
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.equal(input.disabled, false);

  // Resubmitting the corrected code replaces the error with progress.
  await user.click(screen.getByRole("button", { name: "Authorize Device" }));
  assert.ok(await screen.findByRole("heading", { name: "Device Authorized" }));
  assert.equal(screen.queryByRole("alert"), null);
  assert.equal(sessionCalls, 1);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].body, { user_code: "ABCD2456" });
});
