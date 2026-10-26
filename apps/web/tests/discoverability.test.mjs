import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { parse } from "parse5";
import { XMLParser, XMLValidator } from "fast-xml-parser";
import { extractHeadings, generateReferences } from "../scripts/generate-agent-references.mjs";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repo = path.resolve(web, "../..");
const app = path.join(web, "src/app");
const built = path.join(web, ".next/server/app");
const origin = "https://phm.dev";
const read = (file) => readFileSync(file, "utf8");
const catalog = JSON.parse(read(path.join(web, "docs-catalog.json")));

// These account/authorization routes are deliberately noindex, not public
// discovery targets. Every other source page must be represented, including
// any future route added without updating the sitemap.
const privatePrefixes = ["/dashboard", "/device", "/integrations"];
function publicPages(directory = app) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) return publicPages(file);
    if (entry.name !== "page.tsx") return [];
    const route = `/${path.relative(app, directory).split(path.sep).join("/")}`;
    if (privatePrefixes.some((prefix) => route === prefix || route.startsWith(`${prefix}/`))) return [];
    if (route === "/docs/[slug]") return catalog.map(({ slug }) => `/docs/${slug}`);
    assert.ok(!route.includes("[") && !route.includes("("), `Add explicit route expansion for ${route}`);
    return [route];
  });
}

function elements(root) {
  return (root.childNodes ?? []).flatMap((node) => [node, ...elements(node)]);
}
const attr = (node, name) => node.attrs?.find((attribute) => attribute.name === name)?.value;
const text = (node) => node.nodeName === "#text" ? node.value : (node.childNodes ?? []).map(text).join("");
function document(route) {
  const file = path.join(built, route === "/" ? "index.html" : `${route.slice(1)}.html`);
  assert.ok(existsSync(file), `Missing built ${route}; run npm run build before npm run test:discoverability`);
  return elements(parse(read(file)));
}
function structuredData(nodes) {
  return nodes.filter((node) => node.tagName === "script" && attr(node, "type") === "application/ld+json")
    .flatMap((node) => {
      const value = JSON.parse(text(node));
      const entries = Array.isArray(value) ? value : [value];
      for (const entry of entries) assert.equal(entry["@context"], "https://schema.org");
      return entries.flatMap((entry) => entry["@graph"] ?? entry);
    });
}

const routes = publicPages().sort();
assert.ok(routes.length >= 27, "Expected all public landing and documentation pages");
for (const route of routes) {
  test(`built ${route}: one canonical, one h1, semantic headings and social metadata`, () => {
    const nodes = document(route);
    const canonical = nodes.filter((node) => node.tagName === "link" && attr(node, "rel") === "canonical");
    assert.deepEqual(canonical.map((node) => new URL(attr(node, "href")).href), [new URL(route, origin).href]);
    const headings = nodes.filter((node) => /^h[1-6]$/.test(node.tagName));
    assert.equal(headings.filter((node) => node.tagName === "h1").length, 1);
    let previous = 0;
    for (const heading of headings) {
      const level = Number(heading.tagName[1]);
      assert.ok(text(heading).trim(), "Headings must have accessible text");
      assert.ok(level <= previous + 1, `Heading level jumps from h${previous} to ${heading.tagName}: ${text(heading)}`);
      previous = level;
    }
    for (const name of ["description", "og:title", "og:description", "og:url", "og:image"]) {
      const values = nodes.filter((node) => node.tagName === "meta" && (attr(node, "name") === name || attr(node, "property") === name));
      assert.equal(values.length, 1, `${route}: exactly one ${name}`);
      assert.ok(attr(values[0], "content")?.trim(), `${route}: nonempty ${name}`);
      if (name === "og:url") assert.equal(new URL(attr(values[0], "content")).href, new URL(route, origin).href);
    }
    assert.ok(structuredData(nodes).length >= 2, "Parse the actual JSON-LD scripts, not source patterns");
  });
}

for (const route of ["/secrets", "/secrets/capabilities"]) {
  test(`built ${route}: SoftwareApplication matches source and prices only the free CLI`, () => {
    const cargo = read(path.join(repo, "Cargo.toml")).split("[workspace.package]")[1].split("\n[")[0];
    const field = (key) => new RegExp(`^${key} = "([^"]+)"`, "m").exec(cargo)?.[1];
    const applications = structuredData(document(route)).filter((entry) => entry["@type"] === "SoftwareApplication");
    assert.equal(applications.length, 1);
    const software = applications[0];
    assert.equal(software.name, "Phantom Secrets");
    assert.equal(software["@id"], `${origin}/secrets#software`);
    assert.equal(software.softwareVersion, field("version"));
    assert.equal(software.codeRepository, field("repository"));
    assert.equal(software.license, `https://opensource.org/licenses/${field("license")}`);
    assert.match(read(path.join(repo, "LICENSE")), /MIT License/);
    assert.deepEqual(software.operatingSystem.split(", "), ["macOS", "Linux", "Windows"]);
    assert.equal(software.isAccessibleForFree, true);
    assert.equal(software.offers.price, "0");
    assert.equal(software.offers.name, "Local open-source CLI");
    assert.equal(software.offers.priceCurrency, "USD");
    assert.equal(software.downloadUrl, `${field("repository")}/releases/tag/v${field("version")}`);
    assert.equal(software.subjectOf.url, `${origin}/secrets/capabilities`);
    assert.match(text(parse(read(path.join(built, "secrets/capabilities.html")))), /The local CLI is free/);
  });
}

test("capabilities guide has actionable local links and explicit release and authority limits", () => {
  const nodes = document("/secrets/capabilities");
  const main = nodes.find((node) => node.tagName === "main");
  const content = text(main);
  assert.match(content, /phantom why OPENAI_API_KEY --json/);
  assert.match(content, /MCP effects are disabled by default/);
  assert.match(content, /Agents must not emulate that ceremony/);
  assert.match(content, /separately commissioned/);
  assert.match(content, /source may differ/);
  for (const node of elements(main).filter((candidate) => candidate.tagName === "a")) {
    const url = new URL(attr(node, "href"), `${origin}/secrets/capabilities`);
    if (url.origin !== origin) continue;
    if (routes.includes(url.pathname)) {
      if (url.hash) {
        const ids = document(url.pathname).map((element) => attr(element, "id"));
        assert.ok(ids.includes(decodeURIComponent(url.hash.slice(1))), `Broken guide link: ${url.href}`);
      }
    } else {
      assert.ok(existsSync(path.join(web, "public", url.pathname)), `Missing guide resource: ${url.href}`);
    }
  }
});

function sitemap(xml) {
  assert.equal(XMLValidator.validate(xml), true, "Sitemap must be well-formed XML");
  const parsed = new XMLParser({ ignoreAttributes: false, parseTagValue: false }).parse(xml);
  assert.equal(parsed.urlset["@_xmlns"], "http://www.sitemaps.org/schemas/sitemap/0.9");
  assert.ok(Array.isArray(parsed.urlset.url), "Sitemap must contain URL entries");
  const entries = parsed.urlset.url;
  for (const entry of entries) {
    assert.deepEqual(Object.keys(entry).sort(), ["lastmod", "loc"]);
    const url = new URL(entry.loc);
    assert.equal(url.origin, origin);
    assert.equal(url.hash, "");
    assert.equal(url.search, "");
    assert.ok(!privatePrefixes.some((prefix) => url.pathname.startsWith(prefix)));
    assert.match(entry.lastmod, /^\d{4}-\d{2}-\d{2}$/);
    assert.equal(new Date(entry.lastmod).toISOString().slice(0, 10), entry.lastmod);
  }
  assert.equal(new Set(entries.map(({ loc }) => loc)).size, entries.length, "No duplicate canonical URLs");
  return entries;
}

test("built and repository sitemap XML are valid, identical and cover every public HTML page", () => {
  const generated = sitemap(read(path.join(built, "sitemap.xml.body")));
  assert.deepEqual(sitemap(read(path.join(repo, "docs/sitemap.xml"))), generated);
  for (const route of routes) assert.ok(generated.some(({ loc }) => loc === new URL(route, origin).href), `Missing ${route}`);
  for (const { loc } of generated) {
    const route = new URL(loc).pathname;
    assert.ok(routes.includes(route) || existsSync(path.join(web, "public", route)) || existsSync(path.join(built, `${route}.body`)), `Sitemap entry has no page or asset: ${loc}`);
  }
});

test("generated llms references parse and every indexed documentation fragment exists in built HTML", () => {
  const expected = generateReferences();
  for (const filename of ["llms.txt", "llms-full.txt"]) {
    const content = read(path.join(web, "public", filename));
    assert.equal(content, expected.get(`apps/web/public/${filename}`));
    assert.equal(content, read(path.join(repo, "docs", filename)));
    assert.equal(extractHeadings(content).filter(({ level }) => level === 1).length, 1);
    assert.match(content, /https:\/\/phm.dev\/secrets\/capabilities/);
    const links = [...content.matchAll(/\[[^\]\n]+\]\((https:\/\/[^)\s]+)\)/g)].map(([, href]) => new URL(href));
    for (const { slug } of catalog) {
      const route = `/docs/${slug}`;
      const ids = new Set(document(route).map((node) => attr(node, "id")).filter(Boolean));
      const sections = links.filter((url) => url.origin === origin && url.pathname === route);
      assert.ok(sections.some((url) => !url.hash), `Missing canonical ${route}`);
      for (const section of sections) {
        if (section.hash) assert.ok(ids.has(decodeURIComponent(section.hash.slice(1))), `Broken heading link: ${section.href}`);
      }
    }
  }
});

test("XML validation rejects malformed documents instead of accepting a regex-shaped sitemap", () => {
  assert.notEqual(XMLValidator.validate('<urlset><url><loc>https://phm.dev</url></urlset>'), true);
  assert.throws(() => sitemap('<urlset xmlns="https://wrong.example"><url><loc>https://phm.dev</loc></url></urlset>'));
});
