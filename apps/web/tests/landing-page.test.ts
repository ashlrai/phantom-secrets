import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

const { JSDOM } = require("jsdom");

function load(relativePath: string, localRequire: NodeRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "..", relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

// Inspect JSX rather than one rendered state, so links in alternate branches
// and shared public components are covered as well.
function newTabLinkIssues(source: string, filename: string) {
  const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const issues: string[] = [];
  let newTabLinks = 0;
  const literal = (attribute: ts.JsxAttribute | undefined) => {
    const value = attribute?.initializer;
    if (value && ts.isStringLiteral(value)) return value.text;
    if (value && ts.isJsxExpression(value) && value.expression && ts.isStringLiteral(value.expression)) return value.expression.text;
    return undefined;
  };
  function visit(node: ts.Node) {
    if ((ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) &&
        (node.tagName.getText(file) === "a" || node.tagName.getText(file) === "Link")) {
      const location = `${filename}:${file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1}`;
      const attributes = node.attributes.properties;
      const attribute = (name: string) => attributes.find(
        (item): item is ts.JsxAttribute => ts.isJsxAttribute(item) && item.name.getText(file) === name,
      );
      // Spreads or dynamic targets can hide a new-tab link from this guard.
      if (attributes.some(ts.isJsxSpreadAttribute)) issues.push(`${location}: link props must be explicit`);
      const target = attribute("target");
      const targetValue = literal(target);
      if (target && targetValue === undefined) issues.push(`${location}: link target must be a string literal`);
      if (targetValue?.toLowerCase() === "_blank") {
        newTabLinks++;
        const rel = literal(attribute("rel"))?.toLowerCase().split(/\s+/) ?? [];
        for (const token of ["noopener", "noreferrer"]) {
          if (!rel.includes(token)) issues.push(`${location}: new-tab link needs rel=${token}`);
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
  return { issues, newTabLinks };
}

test("public JSX new-tab links include noopener and noreferrer", () => {
  function tsxFiles(directory: string): string[] {
    return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      const file = path.join(directory, entry.name);
      return entry.isDirectory() ? tsxFiles(file) : entry.name.endsWith(".tsx") ? [file] : [];
    });
  }
  const root = path.join(__dirname, "../src");
  const files = ["app", "components"].flatMap((directory) => tsxFiles(path.join(root, directory)));
  let newTabLinks = 0;
  const issues = files.flatMap((file) => {
    const result = newTabLinkIssues(fs.readFileSync(file, "utf8"), path.relative(root, file));
    newTabLinks += result.newTabLinks;
    return result.issues;
  });
  assert.ok(newTabLinks > 0, "expected to inspect the documentation assistant's new-tab link");
  assert.deepEqual(issues, []);
});

test("new-tab link guard detects missing rel tokens and obscured link props", () => {
  const check = (jsx: string) => newTabLinkIssues(`const fixture = ${jsx};`, "fixture.tsx").issues;
  assert.deepEqual(check('<a target="_blank" rel="noreferrer noopener" />'), []);
  assert.deepEqual(check('<Link target={"_BLANK"} rel={"noopener noreferrer"} />'), []);
  assert.deepEqual(check('<a href="https://example.com" />'), []);
  assert.match(check('<a target="_blank" />').join(" "), /noopener.*noreferrer/);
  assert.match(check('<a target="_blank" rel="noopener" />').join(" "), /noreferrer/);
  assert.match(check('<a target="_blank" rel="noreferrer" />').join(" "), /noopener/);
  assert.match(check('<a target="_blank" rel="not-noopener noreferrer" />').join(" "), /noopener/);
  assert.match(check('<a target={destination} rel="noopener noreferrer" />').join(" "), /target must be a string literal/);
  assert.match(check('<a {...props} />').join(" "), /props must be explicit/);
});

test("QuickStart displays expanded multiline commands for every platform", () => {
  let selected = "macOS";
  const hooks = { ...React, useState: () => [selected, (value: string) => { selected = value; }] };
  const release = load("src/lib/public-release.ts") as Record<string, string>;
  const icons = load("src/components/landing/Icons.tsx");
  const copyButton = load("src/components/landing/CopyButton.tsx", ((name: string) => {
    if (name === "./Icons") return icons;
    if (name === "@/lib/posthog") return { capturePostHog: () => {} };
    return require(name);
  }) as NodeRequire);
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", ((name: string) => {
    if (name === "react") return hooks;
    if (name === "./CopyButton") return copyButton;
    if (name === "@/lib/public-release") return release;
    if (name === "next/link") return { __esModule: true, default: "a" };
    return require(name);
  }) as NodeRequire) as { QuickStart: React.ComponentType };
  const css = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");

  for (const platform of ["macOS", "Windows", "Linux"]) {
    selected = platform;
    const html = renderToStaticMarkup(React.createElement(QuickStart));
    const dom = new JSDOM(`<!doctype html><style>${css}</style>${html}`, { url: "http://localhost/" });
    const commandText = dom.window.document.querySelector(".platform-install-card__command .copy-command > span:first-child") as HTMLElement | null;
    assert.ok(commandText, `${platform}: command is displayed`);
    const command = Array.from(commandText.childNodes)
      .filter((node: ChildNode) => node.nodeType === dom.window.Node.TEXT_NODE)
      .map((node: ChildNode) => node.textContent)
      .join("");
    assert.ok(command.split("\n").length > 2, `${platform}: command has multiple lines`);
    assert.equal(dom.window.getComputedStyle(commandText).whiteSpace, "pre-wrap", `${platform}: line breaks remain visible`);
    assert.equal(dom.window.getComputedStyle(commandText).userSelect, "text", `${platform}: command is selectable`);
    const textNodes = Array.from(commandText.childNodes).filter((node: ChildNode) => node.nodeType === dom.window.Node.TEXT_NODE);
    assert.equal(textNodes.length, 1, `${platform}: command is one selectable text node`);
    const range = dom.window.document.createRange();
    range.selectNodeContents(textNodes[0]);
    const selection = dom.window.getSelection();
    assert.ok(selection);
    selection.addRange(range);
    assert.equal(selection.toString(), command, `${platform}: selection preserves the complete command and its line breaks`);
    // The Unix shell parameter expansion is intentional; JavaScript template expressions are not.
    assert.doesNotMatch(command, /\$\{(?!TMPDIR:-\/tmp\})/, `${platform}: no unexpanded template expressions`);
    assert.ok(command.includes(release.PUBLIC_RELEASE_SOURCE_COMMIT), `${platform}: source revision is expanded`);
    assert.ok(command.includes(platform === "Windows" ? release.PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256 : release.PUBLIC_RELEASE_UNIX_INSTALLER_SHA256), `${platform}: checksum is expanded`);
    dom.window.close();
  }
});
