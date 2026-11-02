const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const helperSource = fs.readFileSync(path.join(__dirname, "../src/lib/device-code.ts"), "utf8");
const helperOutput = ts.transpileModule(helperSource, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const helperModule = { exports: {} };
new Function("module", "exports", helperOutput)(helperModule, helperModule.exports);
const { DEVICE_USER_CODE_LENGTH, formatDeviceUserCode, isValidDeviceUserCode, normalizeDeviceUserCode } = helperModule.exports;

const notesPath = path.join(__dirname, "../../../docs/internal/notes.md");
const notes = fs.readFileSync(notesPath, "utf8");
const formPath = path.resolve(__dirname, "../src/app/device/device-authorization-client.tsx");
const form = fs.readFileSync(formPath, "utf8");

const noteSection = notes.match(/### Device Code Display Convention Wave\n([\s\S]*?)(?=\n### |\n## |$)/);

test("internal notes distinguish the XXXX-XXXX presentation from the eight-character validation message", () => {
  assert.ok(noteSection, "notes.md should record the device code display convention");
  const note = noteSection[1];

  // Readable presentation: the display shape shared by the placeholder, the
  // formatted input, and the format mask — eight code characters rendered as
  // two groups of four plus a separator, for nine displayed characters.
  assert.match(note, /`XXXX-XXXX`/);
  assert.match(note, /two groups of four code characters/);
  assert.match(note, /eight code characters and nine displayed characters/);
  assert.match(note, /separator rather than a ninth code character/);
  assert.equal(form.match(/placeholder="([^"]+)"/)?.[1], "XXXX-XXXX");

  // Validation message: the note quotes the form's exact length-error literal
  // and records that eight counts normalized code characters, not glyphs.
  const literal = form.match(/!isValidDeviceUserCode\(code\)[\s\S]{0,200}?setError\("([^"]+)"\)/);
  assert.ok(literal, "the form should reject invalid lengths before sign-in");
  const message = literal[1];
  assert.equal(message, "Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.");
  assert.ok(note.includes(`"${message}"`), "the note must quote the validation message verbatim");
  assert.match(note, /eight-character validation message/);
  assert.match(note, /normalized ASCII letters or digits, not displayed/);
  assert.match(note, /DEVICE_USER_CODE_LENGTH = 8/);
  assert.equal(DEVICE_USER_CODE_LENGTH, 8);

  // The static hint is distinct copy sharing the same convention, not the error.
  const hint = "Enter 8 letters or numbers in the format XXXX-XXXX.";
  assert.ok(form.includes(hint), "the form should render the static field hint");
  assert.ok(note.includes(`"${hint}"`), "the note must quote the hint verbatim");
  assert.notEqual(hint, message);
});

test("the documented counts agree with the shared device-code helpers", () => {
  assert.ok(noteSection, "notes.md should record the device code display convention");
  // Nine displayed characters hold eight code characters; the hyphen is not counted.
  assert.equal(formatDeviceUserCode("ABCD2345"), "ABCD-2345");
  assert.equal(formatDeviceUserCode("ABCD2345").length, DEVICE_USER_CODE_LENGTH + 1);
  assert.equal(normalizeDeviceUserCode("ABCD-2345"), "ABCD2345");
  assert.equal(isValidDeviceUserCode("ABCD-2345"), true);
  // Hyphenated and bare forms of the same wrong length fail identically.
  for (const bad of ["ABCD-234", "ABCD234", "ABCD-23456"]) {
    assert.equal(isValidDeviceUserCode(bad), false, bad);
  }
});

test("the note cites the form source and preserves the earlier format record", () => {
  assert.ok(noteSection, "notes.md should record the device code display convention");
  const link = noteSection[1].match(/\]\(([^)]+device-authorization-client\.tsx)\)/);
  assert.ok(link, "the note should link to the device authorization form");
  assert.equal(path.resolve(path.dirname(notesPath), link[1]), formPath);
  assert.ok(fs.statSync(path.resolve(path.dirname(notesPath), link[1])).isFile());
  // The Device Auth Wave remains the canonical format record.
  assert.match(notes, /### Device Auth Wave\n[\s\S]*?eight uppercase letters or digits/);
  assert.match(notes, /`XXXX-XXXX`: two groups of four code characters separated by a hyphen/);
});
