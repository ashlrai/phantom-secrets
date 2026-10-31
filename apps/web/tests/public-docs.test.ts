import assert from "node:assert/strict";
import test from "node:test";

function assertLinkLabels(document: Document, path: string, computeAccessibleName: (element: Element) => string) {
  const links = document.querySelectorAll("main a[href]");
  assert.ok(links.length > 0, `${path}: expected documentation links`);
  for (const link of links) {
    assert.ok(
      computeAccessibleName(link).trim(),
      `${path}: link ${link.getAttribute("href")} needs an accessible label`,
    );
  }
}

// Registered by the CommonJS documentation suite, which provides its page renderer.
export function registerPublicDocsLinkLabelTests(
  renderPages: () => Promise<Array<{ path: string; document: Document }>>,
  createDocument: (html: string) => Document,
  computeAccessibleName: (element: Element) => string,
) {
  test("public documentation links have nonempty accessible labels", async () => {
    for (const { path, document } of await renderPages()) {
      assertLinkLabels(document, path, computeAccessibleName);
    }
  });

  test("link label checks respect accessible names and reject empty names", () => {
    const document = createDocument('<main><span id="label">Reference</span><a href="/text">Text</a><a href="/aria" aria-label="Guide"></a><a href="/reference" aria-labelledby="label"></a></main>');
    assert.doesNotThrow(() => assertLinkLabels(document, "fixture", computeAccessibleName));
    for (const markup of [
      '<a href="/empty">  </a>',
      '<a href="/hidden"><span aria-hidden="true">Invisible</span></a>',
      '<a href="/empty-aria" aria-label=" "></a>',
    ]) {
      document.querySelector("main")!.innerHTML = markup;
      assert.throws(() => assertLinkLabels(document, "fixture", computeAccessibleName), /needs an accessible label/);
    }
  });
}
