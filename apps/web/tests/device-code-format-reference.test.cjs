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
