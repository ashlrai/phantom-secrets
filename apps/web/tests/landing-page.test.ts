import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import ts from "typescript";

const webRoot = path.resolve(__dirname, "..");

test("landing-page action buttons explicitly use type button", () => {
  const landingDir = path.join(webRoot, "src/components/landing");
  const files = fs.readdirSync(landingDir)
    .filter((file) => file.endsWith(".tsx"))
    .map((file) => path.join(landingDir, file));
  files.push(path.join(webRoot, "src/app/page.tsx"), path.join(webRoot, "src/app/secrets/page.tsx"));

  let count = 0;
  for (const file of files) {
    const source = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if ((ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) && node.tagName.getText(source) === "button") {
        count++;
        const attributes = node.attributes.properties;
        const typeIndex = attributes.findIndex((attribute) => ts.isJsxAttribute(attribute) && attribute.name.getText(source) === "type");
        const type = attributes[typeIndex];
        const location = `${path.relative(webRoot, file)}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`;
        assert.ok(type && ts.isJsxAttribute(type) && type.initializer && ts.isStringLiteral(type.initializer) && type.initializer.text === "button", `${location}: expected type="button"`);
        assert.ok(!attributes.slice(typeIndex + 1).some(ts.isJsxSpreadAttribute), `${location}: a later spread could override the button type`);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  assert.ok(count > 0, "expected to inspect landing React buttons");

  const { JSDOM } = require("jsdom");
  const markup = JSON.parse(fs.readFileSync(path.join(landingDir, "phantom-world-markup.json"), "utf8"));
  const dom = new JSDOM(markup);
  try {
    const buttons = dom.window.document.querySelectorAll("button");
    assert.ok(buttons.length > 0, "expected to inspect demo buttons");
    for (const button of buttons) {
      assert.equal(button.getAttribute("type"), "button", `demo button ${button.textContent?.trim()} must explicitly use type="button"`);
    }
  } finally {
    dom.window.close();
  }
});
