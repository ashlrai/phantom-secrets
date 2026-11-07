const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { after, test } = require("node:test");
const ts = require("typescript");
const { JSDOM } = require("jsdom");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://phm.dev/device" });
for (const name of ["window", "document", "navigator", "HTMLElement"]) {
  Object.defineProperty(globalThis, name, { value: dom.window[name], configurable: true, writable: true });
}
const React = require("react");
const { render, cleanup } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

after(() => dom.window.close());

const docsDir = path.resolve(__dirname, "../../../docs");
const reference = fs.readFileSync(path.join(docsDir, "device-code-format-reference.md"), "utf8");
const sourcePath = path.join(__dirname, "../src/app/device/device-authorization-client.tsx");
const source = fs.readFileSync(sourcePath, "utf8");

function compile(filename, dependencies = {}) {
  const filename_ = path.join(__dirname, "../src", filename);
  const output = ts.transpileModule(fs.readFileSync(filename_, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", output)(
    (name) => dependencies[name] ?? require(name), module, module.exports,
  );
  return module.exports;
}

test("the format reference records the exact displayed placeholder and length-error copy", async () => {
  // The page records each quoted string on its own "> " line, matching the
  // sibling device-code copy pages.
  const quotes = reference.split("\n").filter((line) => line.startsWith("> ")).map((line) => line.slice(2));
  assert.equal(quotes.length, 2, "the reference should record the hint and the length-error copy");

  const recorded = reference.match(/displays `([^`]+)`/);
  assert.ok(recorded, "the reference should record the placeholder");
  const sourcePlaceholder = source.match(/placeholder="([^"]+)"/);
  assert.ok(sourcePlaceholder, "the form should set a placeholder attribute");
  assert.equal(recorded[1], sourcePlaceholder[1], "recorded placeholder must match the source literal");

  // Each recorded string must appear verbatim in the form source: the hint in
  // the JSX body and the length error in the isValidDeviceUserCode guard.
  for (const quote of quotes) assert.ok(source.includes(quote), `source drifted from recorded copy: ${quote}`);
  const lengthError = source.match(/!isValidDeviceUserCode\(code\)[\s\S]{0,160}?setError\("([^"]+)"\)/);
  assert.ok(lengthError, "the form should reject invalid lengths before sign-in");
  assert.equal(quotes[1], lengthError[1], "recorded length-error copy must match the source literal");

  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts"),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient() { throw new Error("Unexpected authentication"); } },
  };
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error("Unexpected network request"); };
  const DeviceAuthorizationClient = compile("app/device/device-authorization-client.tsx", dependencies).default;
  const user = userEvent.setup();
  try {
    const screen = render(React.createElement(DeviceAuthorizationClient));
    const input = screen.getByRole("textbox", { name: "Device code" });
    assert.equal(input.placeholder, recorded[1], "displayed placeholder must match the reference");
    assert.equal(screen.container.querySelector("#device-code-hint").textContent.trim(), quotes[0]);

    await user.type(input, "abcd234");
    assert.equal(input.value, "ABCD-234");
    await user.click(screen.getByRole("button", { name: "Authorize Device" }));
    assert.equal((await screen.findByRole("alert")).textContent, quotes[1]);
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});

test("format reference source links resolve to tracked files", () => {
  const targets = [...reference.matchAll(/\]\(([^)\s]+)\)/g)].map((match) => match[1]);
  assert.ok(targets.length > 0, "the reference should cite its sources");
  for (const target of targets) {
    if (target.startsWith("http") || target.startsWith("#") || target.startsWith("mailto:")) continue;
    assert.ok(
      fs.statSync(path.resolve(docsDir, target.split("#")[0]), { throwIfNoEntry: false })?.isFile(),
      `missing source reference: ${target}`,
    );
  }
  // The rendered placeholder and copy live in the form; the counting rules it
  // describes live in the shared helper. Both must stay linked.
  for (const required of [
    "../apps/web/src/app/device/device-authorization-client.tsx",
    "../apps/web/src/lib/device-code.ts",
  ]) {
    assert.ok(reference.includes(`](${required}`), `missing source reference: ${required}`);
  }
});


test("copy checklist matches the rendered placeholder and length error", async () => {
  const checklist = fs.readFileSync(path.join(docsDir, "device-code-copy-checklist.md"), "utf8");
  const placeholder = checklist.match(/\*\*Placeholder\*\*[^\n]*`([^`]+)`/);
  const error = checklist.match(/^  > (.+)$/m);
  assert.ok(placeholder, "checklist should include the placeholder");
  assert.ok(error, "checklist should include the length error");
  assert.ok(checklist.includes("](../apps/web/src/app/device/device-authorization-client.tsx)"));

  let authCalls = 0;
  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts"),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient() { authCalls++; throw new Error("Unexpected authentication"); } },
  };
  const originalFetch = global.fetch;
  let requests = 0;
  global.fetch = async () => { requests++; throw new Error("Unexpected network request"); };
  try {
    const Component = compile("app/device/device-authorization-client.tsx", dependencies).default;
    const user = userEvent.setup();
    const screen = render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    assert.equal(input.placeholder, placeholder[1]);
    for (const value of ["", "abcd234", "abcd23456"]) {
      await user.clear(input);
      if (value) await user.type(input, value);
      await user.click(screen.getByRole("button", { name: "Authorize Device" }));
      assert.equal(screen.getByRole("alert").textContent, error[1]);
    }
    assert.equal(authCalls, 0);
    assert.equal(requests, 0);
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});

test("display example matches the form's placeholder, hint, and length message", async () => {
  const exampleDoc = fs.readFileSync(path.join(docsDir, "device-code-display-example.md"), "utf8");
  const example = exampleDoc.match(/`([A-Z0-9]{4}-[A-Z0-9]{4})` is a\s+fictional/)?.[1];
  assert.ok(example, "include a fictional formatted example");
  assert.equal(example.length, 9);
  assert.equal(example.replace("-", "").length, 8);
  assert.ok(exampleDoc.includes("](internal/notes.md#device-auth-wave)"));
  assert.ok(exampleDoc.includes("](../apps/web/src/app/device/device-authorization-client.tsx)"));
  assert.ok(fs.readFileSync(path.join(docsDir, "README.md"), "utf8").includes("](device-code-display-example.md)"));

  const dependencies = {
    "next/image": { __esModule: true, default: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    "@/lib/device-code": compile("lib/device-code.ts"),
    "@/lib/posthog": { capturePostHog: async () => {} },
    "@supabase/supabase-js": { createClient() { throw new Error("Unexpected authentication"); } },
  };
  try {
    const Component = compile("app/device/device-authorization-client.tsx", dependencies).default;
    const user = userEvent.setup();
    const screen = render(React.createElement(Component));
    const input = screen.getByRole("textbox", { name: "Device code" });
    assert.ok(exampleDoc.includes(`placeholder and this hint`) && exampleDoc.includes(`\`${input.placeholder}\``));
    assert.ok(exampleDoc.includes(`> ${screen.container.querySelector("#device-code-hint").textContent.trim()}`));
    for (const value of ["abcd234", "abcd23456"]) {
      await user.clear(input);
      await user.type(input, value);
      await user.click(screen.getByRole("button", { name: "Authorize Device" }));
      assert.ok(exampleDoc.includes(`> ${screen.getByRole("alert").textContent}`));
    }
    await user.clear(input);
    await user.type(input, example.replace("-", "").toLowerCase());
    assert.equal(input.value, example);
  } finally {
    cleanup();
  }
});
