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

const label = "Device code";
const hint = "Enter 8 letters or numbers in the format XXXX-XXXX.";
const follows = dom.window.Node.DOCUMENT_POSITION_FOLLOWING;
const describedBy = (input: HTMLElement) => input.getAttribute("aria-describedby")?.split(/\s+/) ?? [];

test("the empty field presents a visible label above the input and a visible format hint below it", () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const input = screen.getByRole("textbox", { name: label });

  // The announced name is the text on screen: a real <label> rendered in
  // reading order before the field, not the placeholder or an aria override.
  const labelNode = screen.getByText(label, { selector: "label" }) as HTMLLabelElement;
  assert.equal(isInaccessible(labelNode), false);
  assert.equal(labelNode.classList.contains("sr-only"), false);
  assert.equal(labelNode.htmlFor, input.id);
  assert.equal(screen.getByLabelText(label), input);
  assert.ok(labelNode.compareDocumentPosition(input) & follows, "the label renders before the input");

  // The hint is a visible paragraph rendered below the field — not the
  // sr-only status line — and the field's description points at it so it is
  // also announced when the field receives focus.
  const hintNode = screen.getByText(hint);
  assert.equal(hintNode.tagName, "P");
  assert.equal(isInaccessible(hintNode), false);
  assert.equal(hintNode.getAttribute("aria-hidden"), null);
  assert.equal(hintNode.classList.contains("sr-only"), false);
  assert.ok(input.compareDocumentPosition(hintNode) & follows, "the hint renders after the input");
  assert.ok(describedBy(input).includes(hintNode.id));
  assert.equal(screen.getByRole("textbox", { name: label, description: /format XXXX-XXXX/ }), input);

  // The hint spells out the same shape the placeholder draws inside the field.
  const placeholder = input.getAttribute("placeholder") ?? "";
  assert.match(placeholder, /^X{4}-X{4}$/);
  assert.ok(hintNode.textContent?.includes(placeholder));

  // One obvious path: a single labelled field, its hint, and one submit,
  // presented in that order inside the named form.
  const form = input.closest("form");
  assert.ok(form);
  assert.equal(within(form).getAllByRole("textbox").length, 1);
  const submit = within(form).getByRole("button", { name: "Authorize Device" });
  assert.ok(hintNode.compareDocumentPosition(submit) & follows, "the submit renders after the hint");
});

test("the empty field displays the XXXX-XXXX placeholder inside the input", () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;

  // The format picture is drawn inside the empty field itself: the rendered
  // input carries the exact placeholder a user sees before typing, so the
  // field can be found by that displayed text.
  assert.equal(input.value, "");
  assert.equal(input.placeholder, "XXXX-XXXX");
  assert.equal(screen.getByPlaceholderText("XXXX-XXXX"), input);
});

test("the label and hint stay visible once typed text replaces the placeholder and after validation feedback", async () => {
  renderDevice(async () => { throw new Error("Unexpected sign-in"); });
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;
  const labelNode = screen.getByText(label, { selector: "label" });
  const hintNode = screen.getByText(hint);

  // The placeholder disappears as soon as the field holds text; the label and
  // hint carry the format guidance on their own from that point.
  await user.type(input, "ab");
  assert.equal(input.value, "AB");
  assert.equal(isInaccessible(labelNode), false);
  assert.equal(isInaccessible(hintNode), false);
  assert.equal(screen.getByRole("textbox", { name: label, description: /format XXXX-XXXX/ }), input);

  await user.click(screen.getByRole("button", { name: "Authorize Device" }));
  const alert = screen.getByRole("alert");
  assert.equal(isInaccessible(labelNode), false);
  assert.equal(isInaccessible(hintNode), false);
  // The error joins the field's description; it does not replace the hint.
  assert.ok(describedBy(input).includes(hintNode.id));
  assert.ok(describedBy(input).includes(alert.id));
  assert.equal(
    screen.getByRole("textbox", { name: label, description: /format XXXX-XXXX.*code is displayed/ }),
    input,
  );
});

test("the label and hint stay presented while authorization runs and retire with the form on success", async () => {
  let resolveSession: (value: unknown) => void = () => {};
  renderDevice(() => new Promise((resolve) => { resolveSession = resolve; }));
  globalThis.fetch = async () => ({ ok: true }) as Response;
  const user = userEvent.setup();
  const input = screen.getByRole("textbox", { name: label }) as HTMLInputElement;
  const labelNode = screen.getByText(label, { selector: "label" });
  const hintNode = screen.getByText(hint);

  await user.type(input, "wxyz6789");
  await user.click(screen.getByRole("button", { name: "Authorize Device" }));
  await screen.findByRole("button", { name: "Signing in with GitHub..." });

  // Busy greys out the control but keeps its guidance in place and announced.
  assert.equal(input.disabled, true);
  assert.equal(isInaccessible(labelNode), false);
  assert.equal(isInaccessible(hintNode), false);
  assert.ok(describedBy(input).includes(hintNode.id));
  assert.equal(screen.getByRole("textbox", { name: label }), input);

  // When the flow completes, the whole input presentation retires together:
  // nothing stale remains behind the success panel.
  resolveSession({ data: { session: { access_token: "synthetic-session" } }, error: null });
  assert.ok(await screen.findByRole("heading", { name: "Device Authorized" }));
  assert.equal(screen.queryByRole("textbox"), null);
  assert.equal(screen.queryByText(label, { selector: "label" }), null);
  assert.equal(screen.queryByText(hint), null);
});
