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
const doc = fs.readFileSync(path.join(docsDir, "device-code-display-reference.md"), "utf8");
const sourcePath = path.join(__dirname, "../src/app/device/device-authorization-client.tsx");
const source = fs.readFileSync(sourcePath, "utf8");
const notes = fs.readFileSync(path.join(docsDir, "internal/notes.md"), "utf8");

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

const { formatDeviceUserCode, isValidDeviceUserCode, normalizeDeviceUserCode, DEVICE_USER_CODE_LENGTH } =
  compile("lib/device-code.ts");

test("display reference describes the displayed format and cites its sources", () => {
  assert.match(doc, /^# /m, "the reference needs a title");
  assert.ok(doc.includes("`XXXX-XXXX`"), "the reference must name the display shape");
  assert.match(doc, /eight uppercase\s+(?:ASCII\s+)?letters or digits\s+in two groups of four/);
  assert.match(doc, /readability separator/);
  assert.match(doc, /eight code characters and nine displayed characters/);
  assert.match(doc, /not a ninth code character/);

  // The fictional example must round-trip through the real helpers.
  const example = doc.match(/fictional display `([A-Z0-9]{4}-[A-Z0-9]{4})` corresponds to the canonical value `([A-Z0-9]{8})`/);
  assert.ok(example, "the reference must pair a fictional displayed code with its canonical value");
  const [, displayed, canonical] = example;
  assert.equal(displayed.length, DEVICE_USER_CODE_LENGTH + 1);
  assert.equal(canonical.length, DEVICE_USER_CODE_LENGTH);
  assert.equal(formatDeviceUserCode(canonical), displayed);
  assert.equal(normalizeDeviceUserCode(displayed), canonical);
  assert.equal(isValidDeviceUserCode(displayed), true);

  // Sources: the form, the shared helpers, and the notes section behind them.
  assert.ok(doc.includes("](../apps/web/src/app/device/device-authorization-client.tsx)"));
  assert.ok(doc.includes("](../apps/web/src/lib/device-code.ts)"));
  assert.ok(doc.includes("](internal/notes.md#device-auth-wave)"));
  assert.match(notes, /### Device Auth Wave\n[\s\S]*?eight uppercase letters or digits/);
});

test("no real codes: every complete display-shaped literal is the declared fictional code", () => {
  assert.match(doc, /Every\s+code shown on this page is fictional/);
  // `XXXX-XXXX` is the format mask, not a code; the only other complete
  // display-shaped literal allowed is the declared fictional example.
  const displayed = [...doc.matchAll(/`([A-Z0-9]{4}-[A-Z0-9]{4})`/g)]
    .map((m) => m[1]).filter((code) => code !== "XXXX-XXXX");
  assert.ok(displayed.length > 0, "the reference should show a formatted example");
  for (const code of displayed) {
    assert.equal(code, "ABCD-2345", `unexpected display-shaped code in the reference: ${code}`);
  }
  const canonical = [...doc.matchAll(/`([A-Z0-9]{8})`/g)].map((m) => m[1]);
  for (const code of canonical) {
    assert.equal(code, "ABCD2345", `unexpected canonical code in the reference: ${code}`);
  }
});

test("typed-to-displayed table rows match the real formatter", () => {
  const rows = [...doc.matchAll(/^\| `([^`]+)` \| `([A-Z0-9-]*)` \|$/gm)];
  assert.ok(rows.length >= 4, "the reference should tabulate typed input against displayed output");
  for (const [, input, displayed] of rows) {
    assert.equal(formatDeviceUserCode(input), displayed, `formatter drifted for input ${input}`);
    assert.equal(isValidDeviceUserCode(displayed), normalizeDeviceUserCode(displayed).length === 8);
  }
  // The table must show retention, not truncation: an overlong value stays
  // visible with more than eight normalized characters.
  const overlong = rows.find(([, , displayed]) => normalizeDeviceUserCode(displayed).length > 8);
  assert.ok(overlong, "the table should include an overlong retained example");
});

test("length-error copy and fail-closed order match the rendered form", async () => {
  const quotes = doc.split("\n").filter((line) => line.startsWith("> ")).map((line) => line.slice(2));
  assert.equal(quotes.length, 1, "the reference should record exactly the length-error copy");
  const lengthError = source.match(/!isValidDeviceUserCode\(code\)[\s\S]{0,160}?setError\("([^"]+)"\)/);
  assert.ok(lengthError, "the form should reject invalid lengths before sign-in");
  assert.equal(quotes[0], lengthError[1], "recorded length-error copy must match the source literal");
  assert.ok(doc.includes("eight normalized ASCII letters or digits"), "the reference must describe the counted characters");
  assert.match(doc, /display hyphen is not counted/);
  assert.match(doc, /before any sign-in or network work/);

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
    assert.equal(input.placeholder, "XXXX-XXXX");

    for (const [typed, displayed] of [["abcd234", "ABCD-234"], ["abcd23456", "ABCD-23456"]]) {
      await user.clear(input);
      await user.type(input, typed);
      assert.equal(input.value, displayed, "typed input must be displayed with the format described");
      await user.click(screen.getByRole("button", { name: "Authorize Device" }));
      assert.equal((await screen.findByRole("alert")).textContent, quotes[0]);
    }
    // Length validation fails closed: no OAuth client or approval request.
    assert.equal(authCalls, 0);
    assert.equal(requests, 0);
  } finally {
    cleanup();
    global.fetch = originalFetch;
  }
});

test("display reference links resolve to tracked files and the index lists it", () => {
  const targets = [...doc.matchAll(/\]\(([^)\s]+)\)/g)].map((match) => match[1]);
  assert.ok(targets.length > 0, "the reference should cite its sources");
  for (const target of targets) {
    if (target.startsWith("http") || target.startsWith("#") || target.startsWith("mailto:")) continue;
    assert.ok(
      fs.statSync(path.resolve(docsDir, target.split("#")[0]), { throwIfNoEntry: false })?.isFile(),
      `missing source reference: ${target}`,
    );
  }
  const index = fs.readFileSync(path.join(docsDir, "README.md"), "utf8");
  assert.ok(index.includes("](device-code-display-reference.md)"), "docs/README.md must list the reference");
});
