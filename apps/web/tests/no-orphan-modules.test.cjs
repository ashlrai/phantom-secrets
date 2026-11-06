const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webRoot = path.resolve(__dirname, "..");
const isModule = (file) => /\.[cm]?[jt]sx?$/.test(file);
const isTest = (file) => /\.(test|spec)\.[cm]?[jt]sx?$/.test(file);
// These files are loaded implicitly, rather than through a module import.
const entryPoints = [
  /^src\/app\/(?:.*\/)?(?:page|route|layout|loading|error|global-error|not-found|template|default|forbidden|unauthorized)\.[cm]?[jt]sx?$/,
  /^src\/app\/(?:.*\/)?(?:robots|sitemap|manifest|icon|apple-icon|opengraph-image|twitter-image)\.[cm]?[jt]sx?$/,
  /^src\/(?:middleware|instrumentation|instrumentation-client)\.[cm]?[jt]sx?$/,
  /\.d\.[cm]?ts$/, // TypeScript includes ambient declarations via tsconfig.
  /^src\/(?:.*\/)?(?:auth|device)\//, // Explicitly protected by this sweep.
];

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(file) : [file];
  });
}

function findOrphans(root) {
  const { config, error } = ts.readConfigFile(path.join(root, "tsconfig.json"), ts.sys.readFile);
  assert.equal(error, undefined, "tsconfig must be readable");
  const parsed = ts.parseJsonConfigFileContent(config, ts.sys, root);
  assert.deepEqual(parsed.errors, [], "tsconfig must be valid");
  const sourceFiles = walk(path.join(root, "src")).filter(isModule);
  // Tests are real consumers (including compile-time contracts); configuration
  // can also import source helpers. Neither may itself be reported as an orphan.
  const consumers = [
    ...sourceFiles,
    ...walk(path.join(root, "tests")).filter(isModule),
    ...fs.readdirSync(root).filter(isModule).map((file) => path.join(root, file)),
  ];
  const imported = new Set();
  for (const file of consumers) {
    const source = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
    function visit(node) {
      let specifier;
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) specifier = node.moduleSpecifier;
      if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
        specifier = node.moduleReference.expression;
      }
      if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) specifier = node.argument.literal;
      if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) && node.expression.text === "require"))) specifier = node.arguments[0];
      if (specifier && ts.isStringLiteralLike(specifier)) {
        const resolved = ts.resolveModuleName(specifier.text, file, parsed.options, ts.sys).resolvedModule;
        // A self-import is not evidence that another module uses this file.
        if (resolved && resolved.resolvedFileName !== file) imported.add(resolved.resolvedFileName);
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
  }
  return sourceFiles.map((file) => ({ file, relative: path.relative(root, file).split(path.sep).join("/") }))
    .filter(({ file, relative }) => !imported.has(file) && !isTest(file) && !entryPoints.some((pattern) => pattern.test(relative)))
    .map(({ relative }) => relative).sort();
}

test("every web source module has an importer or an explicit entry point", () => {
  assert.deepEqual(findOrphans(webRoot), [], "Unused modules: delete them or document an implicit entry point in the allowlist");
});

function withFixture(files, action) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-orphans-"));
  try {
    fs.mkdirSync(path.join(root, "tests"));
    fs.writeFileSync(path.join(root, "tsconfig.json"), JSON.stringify({ compilerOptions: {
      allowJs: true, module: "esnext", moduleResolution: "bundler", baseUrl: ".", paths: { "@/*": ["src/*"] },
    } }));
    for (const [file, source] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
      fs.writeFileSync(path.join(root, file), source);
    }
    action(findOrphans(root));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("detects new orphans, self-imports and names mentioned only in comments or strings", () => {
  withFixture({
    "src/app/page.tsx": "// import '../lib/commented'\nconst text = \"import('../lib/string')\"; export default text;",
    "src/lib/unused.ts": "export const unused = 1;",
    "src/lib/commented.ts": "export {};",
    "src/lib/string.ts": "export {};",
    "src/lib/self.ts": "import './self'; export {};",
    "src/lib/page.ts": "export {};", // Framework names outside app/ are not entry points.
  }, (orphans) => assert.deepEqual(orphans, [
    "src/lib/commented.ts", "src/lib/page.ts", "src/lib/self.ts", "src/lib/string.ts", "src/lib/unused.ts",
  ]));
});

test("resolves aliases, relative/index imports, re-exports, dynamic imports, require and types", () => {
  withFixture({
    "src/app/page.tsx": "import '@/lib/side-effect'; export * from '../lib/barrel'; import('../lib/lazy.mjs'); require('../lib/common.cjs'); import legacy = require('../lib/legacy'); type T = import('../lib/type').T;",
    "src/lib/barrel.ts": "export * from './folder';",
    "src/lib/folder/index.ts": "export const value = 1;",
    "src/lib/side-effect.ts": "export {};",
    "src/lib/lazy.mjs": "export {};",
    "src/lib/common.cjs": "module.exports = {};",
    "src/lib/legacy.ts": "export {};",
    "src/lib/type.ts": "export type T = string;",
    "src/lib/build.ts": "export {};",
    "next.config.ts": "import './src/lib/build';",
    "src/lib/contract.ts": "export type Contract = string;",
    "tests/contract.types.ts": "import type { Contract } from '../src/lib/contract';",
  }, (orphans) => assert.deepEqual(orphans, []));
});

test("preserves Next entries, ambient declarations, auth/device paths and colocated tests", () => {
  const files = Object.fromEntries([
    "src/app/page.tsx", "src/app/api/route.ts", "src/app/dashboard/layout.tsx",
    "src/app/robots.ts", "src/app/sitemap.ts", "src/app/manifest.ts", "src/app/error.tsx",
    "src/middleware.ts", "src/instrumentation.ts", "src/types/markdown.d.ts",
    "src/app/api/v1/auth/helper.ts", "src/app/device/client.tsx", "src/lib/helper.test.ts",
  ].map((file) => [file, "export {};"]));
  withFixture(files, (orphans) => assert.deepEqual(orphans, []));
});
