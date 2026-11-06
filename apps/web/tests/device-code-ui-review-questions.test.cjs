const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const docs = path.resolve(__dirname, "../../../docs");
const review = fs.readFileSync(path.join(docs, "device-code-ui-review-questions.md"), "utf8");
const component = fs.readFileSync(path.resolve(__dirname, "../src/app/device/device-authorization-client.tsx"), "utf8");

test("reviewed placeholder and example messages match the device form", () => {
  const placeholder = component.match(/placeholder="([^"]+)"/);
  assert.ok(placeholder);
  assert.ok(review.includes(`\`${placeholder[1]}\``));

  const quotes = [...review.matchAll(/^\s*> (.+)$/gm)].map((match) => match[1]);
  assert.equal(quotes.length, 3);
  for (const quote of quotes) {
    assert.ok(component.includes(quote), `review copy no longer matches the form: ${quote}`);
  }
});

test("review links resolve to the form, tests, and format reference", () => {
  const links = [...review.matchAll(/\]\(([^)]+)\)/g)].map((match) => match[1]);
  for (const target of [
    "../apps/web/src/app/device/device-authorization-client.tsx",
    "../apps/web/src/app/device/device-code-placeholder.test.tsx",
    "../apps/web/src/app/device/device-code-accessibility.test.tsx",
    "device-code-format-reference.md",
  ]) assert.ok(links.includes(target), `missing review link: ${target}`);
  for (const target of links) {
    assert.ok(fs.statSync(path.resolve(docs, target), { throwIfNoEntry: false })?.isFile(), `broken review link: ${target}`);
  }
});
