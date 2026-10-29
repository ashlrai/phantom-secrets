import assert from "node:assert/strict";
import test from "node:test";

export function registerPublicDocsHeadingTest(renderPage: () => Document) {
  test("the public documentation hub has one title and nested section headings", () => {
    const document = renderPage();
    const headings = [...document.querySelectorAll("h1, h2, h3, h4, h5, h6")];
    const levels = headings.map((heading) => Number(heading.tagName.slice(1)));

    assert.equal(document.querySelectorAll("h1").length, 1);
    assert.equal(levels[0], 1, "the page title is the first heading");
    assert.equal(headings[0]?.textContent, "Put your engineering agents to work.");
    assert.ok(document.querySelector("main")?.contains(headings[0]));
    assert.ok(levels.includes(2), "the page has section headings");
    for (let index = 1; index < levels.length; index++) {
      assert.ok(
        levels[index] <= levels[index - 1] + 1,
        `${headings[index].textContent}: heading level jumps from h${levels[index - 1]} to h${levels[index]}`,
      );
    }

    const collections = document.querySelector(".docs-page__collections");
    assert.ok(collections);
    assert.deepEqual(
      [...collections.querySelectorAll("h1, h2, h3, h4, h5, h6")].map((heading) => [heading.tagName, heading.textContent]),
      ["Use Phantom Secrets", "Connect an agent", "Evaluate trust", "Adopt and contribute"].map((title) => ["H3", title]),
    );
    assert.equal(collections.previousElementSibling?.querySelector("h2")?.textContent, "Phantom Secrets");
  });
}
