const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.join(__dirname, "../src/lib/device-code.ts"), "utf8");
const output = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const deviceCodeModule = { exports: {} };
new Function("module", "exports", output)(deviceCodeModule, deviceCodeModule.exports);
const { DEVICE_USER_CODE_LENGTH, formatDeviceUserCode, isValidDeviceUserCode, normalizeDeviceUserCode } = deviceCodeModule.exports;

test("complete device user codes display in two four-character groups and normalize for storage", () => {
  for (const canonical of ["ABCD2345", "WXYZ6789"]) {
    const displayed = formatDeviceUserCode(canonical);
    assert.match(displayed, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.equal(displayed, `${canonical.slice(0, 4)}-${canonical.slice(4)}`);
    assert.equal(normalizeDeviceUserCode(displayed), canonical);
  }
});

test("the internal note's display and canonical example matches the formatter", () => {
  const notesPath = path.join(__dirname, "../../../docs/internal/notes.md");
  const notes = fs.readFileSync(notesPath, "utf8");
  const example = notes.match(/`([A-Z0-9]{4}-[A-Z0-9]{4})` corresponds to `([A-Z0-9]{8})` in storage/);
  assert.ok(example, "the note should pair a displayed code with its canonical storage value");
  const formLink = notes.match(/\[device authorization form\]\(([^)]+)\)/);
  assert.ok(formLink, "the note should link to the device authorization form");
  assert.equal(
    path.resolve(path.dirname(notesPath), formLink[1]),
    path.resolve(__dirname, "../src/app/device/device-authorization-client.tsx"),
  );
  assert.ok(fs.statSync(path.resolve(path.dirname(notesPath), formLink[1])).isFile());
  const [, displayed, canonical] = example;
  assert.match(notes, /format it as `XXXX-XXXX`: two groups of four code characters separated by a hyphen/);
  assert.match(notes, /The hyphen is a readability separator/);
  assert.match(notes, /The hyphen is display formatting, not part of the canonical/);
  assert.equal(canonical.length, DEVICE_USER_CODE_LENGTH);
  assert.equal(displayed.length, DEVICE_USER_CODE_LENGTH + 1);
  assert.equal(displayed.replace("-", ""), canonical);
  assert.equal(isValidDeviceUserCode(displayed), true);
  assert.equal(formatDeviceUserCode(canonical), displayed);
  assert.equal(normalizeDeviceUserCode(displayed), canonical);
});

test("display contract example matches formatting, normalization, and migration", () => {
  const docsDir = path.resolve(__dirname, "../../../docs");
  const contract = fs.readFileSync(path.join(docsDir, "device-code-display-contract.md"), "utf8");
  const example = contract.match(/display `([A-Z0-9]{4}-[A-Z0-9]{4})` represents\s+the canonical value `([A-Z0-9]{8})`/);
  assert.ok(example, "the contract should pair a displayed code with its canonical value");
  const [, displayed, canonical] = example;
  assert.equal(displayed.length, DEVICE_USER_CODE_LENGTH + 1);
  assert.equal(formatDeviceUserCode(canonical), displayed);
  assert.equal(normalizeDeviceUserCode(displayed.toLowerCase()), canonical);
  assert.equal(isValidDeviceUserCode(displayed), true);
  assert.equal(isValidDeviceUserCode(`${displayed}6`), false);

  const migrationPath = path.resolve(docsDir, "../apps/web/supabase/migrations/20260523000016_canonical_device_user_codes.sql");
  const migration = fs.readFileSync(migrationPath, "utf8");
  assert.equal(displayed.toLowerCase().replaceAll("-", "").toUpperCase(), canonical);
  assert.match(migration, /set user_code = upper\(replace\(user_code, '-', ''\)\)/i);
  assert.match(migration, /create unique index[\s\S]*?on public\.device_tokens\(user_code\)\s+where status = 'pending'/i);
  for (const target of ["device-code-format.md", "internal/notes.md", "../apps/web/src/lib/device-code.ts", "../apps/web/src/app/device/device-authorization-client.tsx", "../apps/web/supabase/migrations/20260523000016_canonical_device_user_codes.sql"]) {
    assert.ok(contract.includes(`](${target}`), `missing contract reference: ${target}`);
    assert.ok(fs.statSync(path.resolve(docsDir, target)).isFile());
  }
});

test("device code guide examples match the current formatter and validator", () => {
  const guidePath = path.join(__dirname, "../../../docs/device-code-format.md");
  const guide = fs.readFileSync(guidePath, "utf8");
  const rows = [...guide.matchAll(/^\| `([^`]+)` \| `([^`]+)` \| (Yes|No) \|$/gm)];
  assert.equal(rows.length, 5, "the guide should retain its input examples");
  for (const [, input, displayed, valid] of rows) {
    assert.equal(formatDeviceUserCode(input), displayed, input);
    assert.equal(isValidDeviceUserCode(input), valid === "Yes", input);
  }
  for (const target of ["../apps/web/src/app/device/device-authorization-client.tsx", "../apps/web/src/lib/device-code.ts", "internal/notes.md"]) {
    assert.ok(guide.includes(`](${target}`), `missing guide reference: ${target}`);
    assert.ok(fs.statSync(path.resolve(path.dirname(guidePath), target)).isFile());
  }
});

test("normalization removes non-ASCII characters and validation accepts the full ASCII alphabet", () => {
  assert.equal(formatDeviceUserCode("abé-cd2345"), "ABCD-2345");
  assert.equal(normalizeDeviceUserCode("ab01-il23"), "AB01IL23");
  assert.equal(isValidDeviceUserCode("ab01-il23"), true);
  assert.equal(isValidDeviceUserCode("---"), false);
});

test("initiation returns the formatted user code while storing its canonical form", async () => {
  const filename = path.join(__dirname, "../src/app/api/v1/auth/device/initiate/route.ts");
  const route = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  let issued;
  const dependencies = {
    "@/lib/supabase-server": { createServiceClient: () => ({
      rpc: async (name, args) => {
        assert.equal(name, "issue_device_code");
        issued = args;
        return { data: "issued", error: null };
      },
    }) },
    "@/lib/device-code": deviceCodeModule.exports,
    "@/lib/commissioning": { requireHostedService: () => null },
  };
  const routeModule = { exports: {} };
  new Function("require", "module", "exports", route)(
    (name) => dependencies[name] ?? require(name), routeModule, routeModule.exports,
  );
  const response = await routeModule.exports.POST(new Request("https://example.test", {
    method: "POST",
    headers: { "x-vercel-forwarded-for": "192.0.2.1" },
  }));
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.match(issued.p_user_code, /^[A-HJKMNP-Z2-9]{8}$/);
  assert.equal(body.user_code, formatDeviceUserCode(issued.p_user_code));
  assert.match(body.user_code, /^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$/);
  assert.equal(normalizeDeviceUserCode(body.user_code), issued.p_user_code);
  assert.equal(body.device_code, issued.p_device_code);
  assert.notEqual(body.device_code, body.user_code);
});

test("input normalization accepts lowercase and separators while requiring eight characters", () => {
  for (const input of ["abcd2345", "abcd-2345", "ab cd-23 45!"]) {
    assert.equal(normalizeDeviceUserCode(input), "ABCD2345");
    assert.equal(formatDeviceUserCode(input), "ABCD-2345");
    assert.equal(isValidDeviceUserCode(input), true);
  }
  for (const [input, displayed] of [["ab-cd", "ABCD"], ["abc-d2", "ABCD-2"]]) {
    assert.equal(formatDeviceUserCode(input), displayed);
    assert.equal(isValidDeviceUserCode(input), false);
  }
});

test("formatting preserves extra characters so overlong codes remain invalid", () => {
  const displayed = formatDeviceUserCode("abcd-23456");
  assert.equal(displayed, "ABCD-23456");
  assert.equal(normalizeDeviceUserCode(displayed), "ABCD23456");
  assert.equal(isValidDeviceUserCode(displayed), false);
});
