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
    // The Unix shell parameter expansion is intentional; JavaScript template expressions are not.
    assert.doesNotMatch(command, /\$\{(?!TMPDIR:-\/tmp\})/, `${platform}: no unexpanded template expressions`);
    assert.ok(command.includes(release.PUBLIC_RELEASE_SOURCE_COMMIT), `${platform}: source revision is expanded`);
    assert.ok(command.includes(platform === "Windows" ? release.PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256 : release.PUBLIC_RELEASE_UNIX_INSTALLER_SHA256), `${platform}: checksum is expanded`);
    dom.window.close();
  }
});
