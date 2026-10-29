import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import ts from "typescript";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

// The web suite uses Node's CommonJS runner; the companion .cjs file loads this test.
const { JSDOM } = require("jsdom");
const webRoot = path.resolve(__dirname, "..");

function loadPageModule(filename: string): Record<string, any> {
  const source = fs.readFileSync(filename, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const exports = {};
  const localRequire = (name: string): any => {
    if (name === "next/link") return { __esModule: true, default: ({ children, ...props }: any) => React.createElement("a", props, children) };
    if (name === "next/image") return { __esModule: true, default: ({ priority: _priority, ...props }: any) => React.createElement("img", props) };
    if (name === "next/navigation") return { usePathname: () => "/" };
    if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
    if (name === "@/lib/workbench-release") return { WORKBENCH_RELEASE: null };
    if (name.startsWith("@/") || name.startsWith(".")) {
      const base = name.startsWith("@/") ? path.join(webRoot, "src", name.slice(2)) : path.resolve(path.dirname(filename), name);
      for (const candidate of [base, `${base}.tsx`, `${base}.ts`, `${base}.js`, `${base}.json`]) {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          return candidate.endsWith(".json") ? require(candidate) : loadPageModule(candidate);
        }
      }
      throw new Error(`Cannot resolve ${name} from ${filename}`);
    }
    return require(name);
  };
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

function assertAlt(alt: string | null, purpose: "informative" | "decorative", label: string) {
  if (purpose === "decorative") assert.equal(alt, "", `${label}: decorative images need an empty alt`);
  else assert.ok(alt?.trim(), `${label}: informative images need nonempty alt text`);
}

test("landing images have alt text appropriate to their purpose", () => {
  const page = loadPageModule(path.join(webRoot, "src/app/page.tsx"));
  const dom = new JSDOM(renderToStaticMarkup(React.createElement(page.default)));
  try {
    // Every current inline image repeats adjacent text or an accessible control name.
    // New images must be explicitly reviewed and classified here.
    const decorative = [
      ['nav[aria-label="Primary navigation"] img[src="/favicon.svg"]', 1],
      ['.phantom-workbench__center img[src="/favicon.svg"]', 1],
      ['footer img[src="/favicon.svg"]', 1],
      ['.pw-provider img[src^="/phantom-world/provider-"]', 6],
      ['.pw-provider img[src="/phantom-world/devin-mark.svg"]', 1],
      ['.pw-agent img[src="/phantom-world/phantom-mark.svg"]', 3],
      ['.pw-toolkit a[href="/secrets"] img[src="/phantom-world/phantom-mark.svg"]', 1],
    ] as const;
    const images = [...dom.window.document.querySelectorAll("img")] as HTMLImageElement[];
    assert.ok(images.length > 0, "the actual landing page must render images");
    for (const [selector, count] of decorative) {
      assert.equal(dom.window.document.querySelectorAll(selector).length, count, selector);
    }
    for (const image of images) {
      const matches = decorative.filter(([selector]) => image.matches(selector));
      assert.equal(matches.length, 1, `classify landing image ${image.getAttribute("src")}`);
      assertAlt(image.getAttribute("alt"), "decorative", image.getAttribute("src") ?? "image");
    }
    const socialImages = page.metadata.openGraph.images;
    assert.ok(socialImages.length > 0, "the landing page must have a social preview image");
    for (const image of socialImages) assertAlt(image.alt, "informative", "social preview image");
  } finally {
    dom.window.close();
  }
});

test("alt checks reject missing, whitespace-only, and incorrectly decorative descriptions", () => {
  assertAlt("A useful description", "informative", "fixture");
  assertAlt("", "decorative", "fixture");
  for (const alt of [null, "", "  "]) assert.throws(() => assertAlt(alt, "informative", "fixture"));
  for (const alt of [null, " ", "A description"]) assert.throws(() => assertAlt(alt, "decorative", "fixture"));
});
