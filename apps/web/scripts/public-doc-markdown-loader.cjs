/* eslint-disable @typescript-eslint/no-require-imports -- Both bundlers load webpack loaders as CommonJS. */
const { readFileSync } = require("node:fs");
const path = require("node:path");

const catalogPath = path.resolve(__dirname, "../docs-catalog.json");
const docsRoot = path.resolve(__dirname, "../../../docs");

// Called only by the build/dev bundler. Keep one authoritative Markdown copy,
// and reject imports outside the public catalog rather than bundling arbitrary
// repository documents. Returning JSON-escaped JavaScript also works with
// Turbopack's supported webpack-loader subset.
module.exports = function publicDocMarkdownLoader(source) {
  this.addDependency(catalogPath);
  const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
  const admitted = catalog.some(({ file }) =>
    /^[a-z0-9]+(?:-[a-z0-9]+)*\.md$/.test(file) &&
    path.resolve(this.resourcePath) === path.join(docsRoot, file),
  );
  if (!admitted) throw new Error("Markdown import is outside the public documentation catalog");
  const markdown = Buffer.isBuffer(source) ? source.toString("utf8") : source;
  if (typeof markdown !== "string") throw new Error("Public documentation must be UTF-8 text");
  return `export default ${JSON.stringify(markdown)};`;
};
// Loader-runner strips a leading BOM when converting to its default string
// input. Decode raw bytes ourselves so embedded text matches readFile(...utf8).
module.exports.raw = true;
