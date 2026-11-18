const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const web = path.resolve(__dirname, "..");
const repo = path.resolve(web, "../..");
const read = (file) => fs.readFileSync(file, "utf8");

const component = read(path.join(web, "src/components/landing/AshlrEcosystem.tsx"));
const secretsPage = read(path.join(web, "src/app/secrets/page.tsx"));
const readme = read(path.join(repo, "README.md"));
const readmeSection = readme.slice(
  readme.indexOf("## Part of the Ashlr ecosystem"),
  readme.indexOf("## Contributing"),
);

test("the /secrets page renders the Ashlr ecosystem section", () => {
  assert.match(secretsPage, /import \{ AshlrEcosystem \} from "@\/components\/landing\/AshlrEcosystem";/);
  assert.match(secretsPage, /<AshlrEcosystem \/>/);
});

test("every ecosystem tool link on the site also appears in the README", () => {
  assert.ok(readmeSection.length > 0, "README ecosystem section is missing");
  // Only the TOOLS entries (`href: "..."`); the AGENTS.md/CLAUDE.md links are
  // absolute on the site but relative in the README.
  const links = [...component.matchAll(/href: "(https:\/\/[^"]+)"/g)].map((match) => match[1]);
  assert.equal(links.length, 7, "expected one link per ecosystem tool");
  for (const link of links) {
    assert.ok(readme.includes(link), `${link} is not in README.md`);
  }
});

test("site and README name the same ecosystem tools and mission", () => {
  for (const name of ["Phantom", "Phantom Secrets", "Locus", "Lexicon", "Ashlr MD", "Ashlr Stack", "ashlr-plugin"]) {
    assert.ok(component.includes(`name: "${name}"`), `site is missing ${name}`);
    assert.ok(readmeSection.includes(name), `README is missing ${name}`);
  }
  for (const phrase of ["passive board member", "recursive", "self-improvement (RSI)", "compatibility contract"]) {
    assert.match(component.replace(/\s+/g, " "), new RegExp(phrase.replace(/[()]/g, "\\$&")));
    assert.match(readmeSection.replace(/\s+/g, " "), new RegExp(phrase.replace(/[()]/g, "\\$&")));
  }
});
