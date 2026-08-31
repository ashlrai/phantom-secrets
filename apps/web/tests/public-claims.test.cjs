const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webDir = path.resolve(__dirname, "..");
const repoDir = path.resolve(webDir, "../..");

function filesUnder(relativeDirectory, acceptedExtensions) {
  const absoluteDirectory = path.join(webDir, relativeDirectory);
  return fs.readdirSync(absoluteDirectory, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) return filesUnder(relativePath, acceptedExtensions);
    return acceptedExtensions.includes(path.extname(entry.name)) ? [relativePath] : [];
  });
}

function repoFilesUnder(relativeDirectory, acceptedExtensions) {
  const absoluteDirectory = path.join(repoDir, relativeDirectory);
  return fs.readdirSync(absoluteDirectory, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) return repoFilesUnder(relativePath, acceptedExtensions);
    return acceptedExtensions.includes(path.extname(entry.name)) ? [relativePath] : [];
  });
}

const claimPaths = [
  "src/app/layout.tsx",
  "src/app/manifest.ts",
  "src/app/pricing/page.tsx",
  "src/app/sitemap.ts",
  ...filesUnder("src/app/dashboard", [".tsx"]),
  ...filesUnder("src/components/landing", [".tsx"]),
  ...filesUnder("public", [".json", ".txt"]),
];

function read(relativePath) {
  return fs.readFileSync(path.join(webDir, relativePath), "utf8");
}

function readRepo(relativePath) {
  return fs.readFileSync(path.join(repoDir, relativePath), "utf8");
}

const claims = Object.fromEntries(
  claimPaths.map((relativePath) => [relativePath, read(relativePath)]),
);
const allClaims = Object.values(claims).join("\n");

const staticDocumentationPaths = repoFilesUnder("docs", [".html", ".md"]);
const staticDocumentationClaims = Object.fromEntries(
  staticDocumentationPaths.map((relativePath) => [relativePath, readRepo(relativePath)]),
);

const publishedPackageDocumentationPaths = ["npm", "npm-mcp", "mcp-registry"].flatMap(
  (directory) => repoFilesUnder(directory, [".md"]),
);
const publishedPackageDocumentationClaims = Object.fromEntries(
  publishedPackageDocumentationPaths.map((relativePath) => [
    relativePath,
    readRepo(relativePath),
  ]),
);

const repositoryGuidanceClaims = {
  "AGENTS.md": readRepo("AGENTS.md"),
  "README.md": readRepo("README.md"),
  "integrations/github-actions/example-workflow.yml": readRepo(
    "integrations/github-actions/example-workflow.yml",
  ),
  ...staticDocumentationClaims,
  ...publishedPackageDocumentationClaims,
  ...Object.fromEntries(
    Object.entries(claims).map(([relativePath, source]) => [
      `apps/web/${relativePath}`,
      source,
    ]),
  ),
};

const machineReadablePaths = [
  ...filesUnder("public", [".json", ".txt"]),
  "src/app/layout.tsx",
  "src/app/manifest.ts",
  "src/app/sitemap.ts",
];
const machineReadableClaims = Object.fromEntries(
  machineReadablePaths.map((relativePath) => [
    `apps/web/${relativePath}`,
    read(relativePath),
  ]),
);
for (const relativePath of ["docs/llms.txt", "docs/llms-full.txt", "docs/sitemap.xml"]) {
  machineReadableClaims[relativePath] = readRepo(relativePath);
}

const machineReadableGuides = Object.entries(machineReadableClaims).filter(
  ([file]) => /llms(?:-full)?\.txt$/.test(file),
);

const verifiedReleaseUrl =
  "https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3";
const gitGuardianReportUrl =
  "https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/";

function structuredMetadataBlock(source, type) {
  const marker = `"@type": "${type}"`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing ${type} structured metadata`);
  const end = source.indexOf("{/* JSON-LD:", start);
  assert.notEqual(end, -1, `missing boundary after ${type} structured metadata`);
  return source.slice(start, end);
}

test("public surfaces reject previously audited absolute claims", () => {
  for (const forbidden of [
    /backed up automatically/i,
    /zero data sent/i,
    /zero exposure/i,
    /about 0\.5\s*ms/i,
    /not measurable in practice/i,
    /phm_ tokens are session-scoped placeholders/i,
    /blocks any commit containing an unprotected secret/i,
    /real keys never leave your machine/i,
    /no plaintext ever touches disk/i,
    /without ever seeing the values/i,
    /AI sees only the phantoms/i,
    /MCP tools \(\d+ total\)/i,
    /Tests:\s*\d+\s*\(at last count\)/i,
    /Delegate everything/i,
    /Any tool that reads \.env files works automatically/i,
    /whose API calls go through the local proxy/i,
    /Pro tier ships shared cloud vaults/i,
    /Priority support/i,
    /Configured upstreams only/i,
    /Real output\. Nothing hidden/i,
    /postgres:\/\/[\s\S]*swaps the phm_/i,
  ]) {
    assert.doesNotMatch(allClaims, forbidden);
  }
});

test("active landing copy rejects universal agent, leak, timing, and competitor claims", () => {
  const landingFiles = [
    "src/components/landing/Comparison.tsx",
    "src/components/landing/FAQ.tsx",
    "src/components/landing/Install.tsx",
    "src/components/landing/QuickStart.tsx",
  ];
  const activeLandingClaims = landingFiles.map((file) => claims[file]).join("\n");

  for (const forbidden of [
    /Every other secrets manager/i,
    /moment you give (?:one|a key) to an AI tool, it leaks/i,
    /Every AI tool/i,
    /any other agent/i,
    /Install in (?:ten|10) seconds/i,
    /Sixty seconds to a safe \.env/i,
  ]) {
    assert.doesNotMatch(activeLandingClaims, forbidden);
  }

  const comparison = claims["src/components/landing/Comparison.tsx"];
  assert.match(comparison, /managed path with giving an agent a plaintext dotenv value/i);
  assert.match(comparison, /not a vendor feature benchmark/i);
  assert.doesNotMatch(comparison, /Doppler|1Password CLI|Infisical|AWS Secrets Mgr/i);
  assert.doesNotMatch(comparison, /default tier|as of April 2026|retrofitted/i);
});

test("repository guidance rejects stale token, traversal, streaming, pricing, and timing claims", () => {
  const forbidden = [
    // Persistent project mappings are not provider credentials, but they are
    // still sensitive metadata resolvable by an active authorized proxy.
    /\b(?:safe|worthless)\s+(?:persistent\s+)?(?:(?:phantom|phm_)\s*)?(?:tokens?|placeholders?)\b/i,
    /\b(?:phantom|phm_)\s*(?:tokens?|placeholders?)[^\n]{0,24}\b(?:are|is)\s+(?:only\s+)?(?:safe|worthless)\b/i,
    /\b(?:safe|worthless)[\s*`_-]{1,12}(?:phm_|phantom)[\s*`_-]{0,12}(?:tokens?|placeholders?|mappings?)\b/i,
    /\b(?:phm_|phantom)[\s*`_-]{0,12}(?:tokens?|placeholders?|mappings?)[\s*`_-]{0,12}(?:are|is|remain)[\s*`_-]{1,12}(?:safe|worthless)\b/i,

    // `init --all` is a bounded discovery operation, not an unqualified
    // promise to process an entire workspace.
    /\bprotect\s+every\s+git\s+repo\b/i,
    /\bevery\s+(?:git\s+)?repo(?:sitory)?[^\n]{0,48}\bone[- ]shot\b/i,
    /\bone[- ]shot[^\n]{0,48}\bevery\s+(?:git\s+)?repo(?:sitory)?\b/i,
    /phantom init --all[^\n]{0,100}\b(?:every|all)\s+(?:git\s+)?repo(?:sitor(?:y|ies))?\b/i,
    /\b(?:every|all)\s+(?:git\s+)?repo(?:sitor(?:y|ies))?[^\n]{0,100}phantom init --all\b/i,

    // Phantom buffers bounded request bodies; only responses retain
    // streaming/SSE semantics.
    /\brequest(?:-|\s+)stream(?:ing|ed)?[^\n]{0,80}\breplac(?:e|es|ed|ement|ing)\b/i,
    /\breplac(?:e|es|ed|ement|ing)[^\n]{0,80}\b(?:streaming\s+requests?|request(?:-|\s+)streams?)\b/i,

    // Price, upgrade remedies, and user limits are not commissioned public
    // entitlements until the hosted plan is live and evidenced.
    /\bPro\b[^\n]{0,80}\$8(?:\.00)?(?:\s*\/\s*(?:mo(?:nth)?|user))?/i,
    /\$8(?:\.00)?(?:\s*\/\s*(?:mo(?:nth)?|user))?[^\n]{0,80}\bPro\b/i,
    /\$8(?:\.00)?\s*(?:<[^>]+>\s*)?\/\s*(?:user\s*\/\s*)?(?:mo(?:nth)?)\b/i,
    /\bupgrade\s+to\s+Pro\b[^\n]{0,100}\b(?:fix|remed|unlock|increase|raise|unlimited)\w*\b/i,
    /\bPro\b[^\n]{0,100}\bunlimited\s+(?:cloud\s+)?vaults?\b/i,
    /\b(?:limit(?:ed)?\s+to|limit\s+of|up\s+to|maximum\s+of)\s+(?:ten|\d+)\s+(?:users?|members?)\b/i,

    // Installation duration depends on host, network, and package manager.
    /\binstall(?:ed|ation)?\s+in\s+(?:about\s+)?(?:ten|10|\d+)\s+seconds?\b/i,
    /\binstall\s*[-:]?\s*10\s+seconds?\b/i,
    /\binstall\s*\(\s*(?:ten|10|\d+)\s+seconds?\s*\)/i,
    /\b(?:Instalation|Installtion|Intallation)\b/i,
  ];

  for (const [file, source] of Object.entries(repositoryGuidanceClaims)) {
    for (const claim of forbidden) {
      assert.doesNotMatch(source, claim, file);
    }
  }
});

test("active static documentation rejects audited submission and deployment absolutes", () => {
  const forbidden = [
    /works in production without modification/i,
    /without leaking your keys/i,
    /If you are in a headless environment, set `PHANTOM_VAULT_PASSPHRASE` before running cloud commands/i,
    /An email draft was opened/i,
  ];

  for (const [file, source] of Object.entries(staticDocumentationClaims)) {
    for (const claim of forbidden) {
      assert.doesNotMatch(source, claim, file);
    }
  }
});

test("static waitlist reports a mail-app request and never claims a backend submission", () => {
  const waitlist = staticDocumentationClaims["docs/waitlist.html"];
  assert.match(waitlist, /A mail app was requested/i);
  assert.match(waitlist, /no waitlist backend and submitted nothing/i);
  assert.match(waitlist, /This page sends no request/i);
  assert.doesNotMatch(waitlist, /window\.open\s*\(/i);
  assert.doesNotMatch(waitlist, /\b(?:fetch|XMLHttpRequest)\s*\(|<form[^>]+\baction=/i);
});

test("static guides keep local-vault, cloud-key, and production authority distinct", () => {
  const troubleshooting = staticDocumentationClaims["docs/troubleshooting.md"];
  assert.match(troubleshooting, /Phantom Cloud push and pull currently require keychain access/i);
  assert.match(
    troubleshooting,
    /PHANTOM_VAULT_PASSPHRASE[^\n]*local encrypted-file vault[\s\S]{0,180}not a substitute[^\n]*cloud encryption key/i,
  );

  const codexGuide = staticDocumentationClaims["docs/codex.md"];
  assert.match(codexGuide, /production runtime must be provisioned separately/i);
  assert.match(codexGuide, /does not deploy or authorize production credentials/i);

  const landing = staticDocumentationClaims["docs/index.html"];
  assert.match(landing, /supported API work while reducing credential exposure to agent context/i);
});

test("machine-readable guidance rejects absolute security guarantees", () => {
  const forbidden = [
    /real keys never leave your machine/i,
    /no plaintext ever touches disk/i,
    /without ever seeing the values/i,
    /AI sees only the phantoms/i,
    /zero (?:data sent|exposure)/i,
    /(?:completely|100%) secure/i,
    /unhackable/i,
  ];

  for (const [file, source] of Object.entries(machineReadableClaims)) {
    for (const claim of forbidden) {
      assert.doesNotMatch(source, claim, file);
    }
  }
});

test("active wrapping guidance uses the installed local Phantom runtime", () => {
  for (const [file, source] of Object.entries(machineReadableClaims)) {
    assert.doesNotMatch(source, /npx\s+(?:-y\s+)?phantom-secrets\s+exec/i, file);
  }
});

test("active documentation does not execute Phantom through an unpinned registry fallback", () => {
  for (const [file, source] of Object.entries(repositoryGuidanceClaims)) {
    assert.doesNotMatch(source, /^\s*(?:run:\s*)?npx\s+(?:-y\s+)?phantom(?:-secrets|-secrets-mcp)?\b/im, file);
  }
});

test("machine-readable init --all guidance states its traversal bounds", () => {
  for (const [file, source] of machineReadableGuides) {
    assert.match(
      source,
      /phantom init --all <DIR>|Multi-project: --all <DIR>|`phantom init`[^\n]*`--all <DIR>`/i,
      file,
    );
    assert.match(source, /five[- ]level|within five levels/i, file);
    assert.match(source, /stops?(?: descending)? below the first matching repo(?:sitory)?/i, file);
    assert.match(source, /--dry-run/i, file);
  }
});

test("machine-readable Homebrew guidance uses the trusted fully qualified formula", () => {
  const homebrewGuides = machineReadableGuides.filter(([, source]) =>
    /brew (?:tap|install)/i.test(source),
  );
  assert.ok(homebrewGuides.length >= 2, "expected Homebrew guidance in public references");

  for (const [file, source] of homebrewGuides) {
    assert.match(
      source,
      /brew tap ashlrai\/phantom[\s\S]{0,240}brew trust --formula ashlrai\/phantom\/phantom[\s\S]{0,240}brew install ashlrai\/phantom\/phantom/i,
      file,
    );
    assert.doesNotMatch(source, /brew install phantom(?:\s|`|$)/im, file);
  }
});

test("public Cloud guidance does not promise machine-portable recovery", () => {
  const portableCloudClaims = [
    /\b(?:Phantom\s+)?Cloud(?:\s+(?:sync|push|pull|vault|backup))?[^\n]{0,120}\bacross\s+machines?\b/i,
    /\bacross\s+machines?[^\n]{0,120}\b(?:Phantom\s+)?Cloud\b/i,
    /\b(?:Phantom\s+)?Cloud(?:\s+(?:sync|push|pull))?[\s\S]{0,160}\b(?:new|another|second)\s+machine\b/i,
    /\b(?:new|another|second)\s+machine[\s\S]{0,160}\b(?:Phantom\s+)?Cloud(?:\s+(?:sync|push|pull))?\b/i,
    /\bphantom\s+cloud\s+pull[\s\S]{0,160}\b(?:new|another|second)\s+machine\b/i,
  ];

  for (const [file, source] of Object.entries(repositoryGuidanceClaims)) {
    for (const claim of portableCloudClaims) {
      assert.doesNotMatch(source, claim, file);
    }
  }

  const supportedBackupClaim =
    "Phantom Cloud can retain a client-encrypted backup for recovery on the same machine while its keychain-held key remains available.";
  for (const claim of portableCloudClaims) {
    assert.doesNotMatch(supportedBackupClaim, claim);
  }
});

test("current-release guidance routes installs through verified GitHub or Homebrew artifacts", () => {
  const canonicalReleaseGuides = {
    "README.md": repositoryGuidanceClaims["README.md"],
    "docs/getting-started.md": repositoryGuidanceClaims["docs/getting-started.md"],
    "docs/llms.txt": machineReadableClaims["docs/llms.txt"],
    "docs/llms-full.txt": machineReadableClaims["docs/llms-full.txt"],
    "apps/web/public/llms.txt": repositoryGuidanceClaims["apps/web/public/llms.txt"],
    "apps/web/public/llms-full.txt":
      repositoryGuidanceClaims["apps/web/public/llms-full.txt"],
  };

  for (const [file, source] of Object.entries(canonicalReleaseGuides)) {
    assert.match(source, new RegExp(verifiedReleaseUrl.replaceAll(".", "\\.")), file);
    assert.match(
      source,
      /brew tap ashlrai\/phantom[\s\S]{0,300}brew trust --formula ashlrai\/phantom\/phantom[\s\S]{0,300}brew install ashlrai\/phantom\/phantom/i,
      file,
    );
  }

  const unpinnedRegistryCommands = [
    /(?:^|[`"'(])(?:\$\s*)?npm\s+(?:install|i)\s+(?:-g\s+)?phantom-secrets(?:-mcp)?(?=$|[\s`"'<>),;])/im,
    /(?:^|[`"'(])(?:\$\s*)?npx(?:\s+-y)?\s+phantom-secrets(?:-mcp)?(?!\s+(?:agent|check|exec)\b)(?=$|[\s`"'<>),;])/im,
    /(?:^|[`"'(])(?:\$\s*)?cargo\s+install\s+phantom-secrets(?:-mcp)?(?=$|[\s`"'<>),;])/im,
  ];

  for (const [file, source] of Object.entries(repositoryGuidanceClaims)) {
    for (const command of unpinnedRegistryCommands) {
      for (const match of source.matchAll(new RegExp(command.source, `${command.flags}g`))) {
        const start = Math.max(0, match.index - 260);
        const end = Math.min(source.length, match.index + match[0].length + 260);
        const context = source.slice(start, end);
        assert.match(
          context,
          /legacy fallback[\s\S]{0,260}(?:older registry track|do not rely)|(?:older registry track|do not rely)[\s\S]{0,260}legacy fallback/i,
          `${file}: unpinned registry invocation is allowed only as a warning about the released legacy fallback`,
        );
      }
    }
  }
});

test("published package READMEs use verified local binaries and bounded claims", () => {
  assert.deepEqual(
    Object.keys(publishedPackageDocumentationClaims).sort(),
    ["mcp-registry/README.md", "npm-mcp/README.md", "npm/README.md"],
  );

  const forbidden = [
    /\bAI\s+never\s+sees\b/i,
    /\bwithout\s+(?:the\s+)?AI\s+ever\s+seeing\b/i,
    /\b(?:Phantom\s+)?Cloud[^\n]{0,100}\bacross\s+machines?\b/i,
    /\bacross\s+machines?[^\n]{0,100}\b(?:Phantom\s+)?Cloud\b/i,
    /\brole-based access control\b|\bRBAC\b/i,
    /\bevery\s+(?:npm\s+)?script\b/i,
    /\bworks with any (?:MCP )?(?:tool|client|platform)\b/i,
    /\b(?:all|every)\s+(?:operating systems?|platforms?|devices?)\b/i,
    /(?:^|[`"'(])(?:\$\s*)?npm\s+(?:install|i)\s+(?:-g\s+)?phantom-secrets(?:-mcp)?(?=$|[\s`"'<>),;])/im,
    /(?:^|[`"'(])(?:\$\s*)?npx(?:\s+-y)?\s+phantom-secrets(?:-mcp)?(?=$|[\s`"'<>),;])/im,
  ];

  for (const [file, source] of Object.entries(publishedPackageDocumentationClaims)) {
    assert.match(source, new RegExp(verifiedReleaseUrl.replaceAll(".", "\\.")), file);
    assert.match(source, /installed local `phantom`|installed local CLI/i, file);
    assert.match(source, /`phantom mcp serve`/i, file);
    assert.match(source, /Released `v0\.7\.3`[\s\S]{0,500}legacy fallback/i, file);
    assert.match(source, /Current main[\s\S]{0,180}(?:fails closed|removes the network fallback)/i, file);
    assert.match(source, /older (?:release|registry) track/i, file);
    assert.match(
      source,
      /same machine[\s\S]{0,160}keychain-held (?:cloud )?encryption key|keychain-held (?:cloud )?encryption key[\s\S]{0,160}same machine/i,
      file,
    );
    assert.match(source, /every registered member[\s\S]{0,180}(?:key )?share/i, file);
    assert.match(source, /offboarding/i, file);
    assert.match(source, /rotat(?:e|ing) affected provider credentials/i, file);

    for (const claim of forbidden) {
      assert.doesNotMatch(source, claim, file);
    }
  }
});

test("registry README catalog exactly matches the staged 54-tool schema", () => {
  const registryReadme = publishedPackageDocumentationClaims["mcp-registry/README.md"];
  const server = JSON.parse(readRepo("mcp-registry/server.json"));
  const start = registryReadme.indexOf("<!-- tool-catalog:start -->");
  const end = registryReadme.indexOf("<!-- tool-catalog:end -->");

  assert.ok(start >= 0 && end > start, "registry README must delimit its tool catalog");
  const documentedNames = [
    ...registryReadme.slice(start, end).matchAll(/`(phantom_[a-z0-9_]+)`/g),
  ].map((match) => match[1]);
  const schemaNames = server.tools.map((tool) => tool.name);

  assert.equal(schemaNames.length, 54, "staged schema must contain 54 tools");
  assert.equal(new Set(schemaNames).size, 54, "staged schema tool names must be unique");
  assert.equal(documentedNames.length, 54, "README catalog must contain 54 tool names");
  assert.equal(new Set(documentedNames).size, 54, "README catalog names must be unique");
  assert.deepEqual(documentedNames.sort(), schemaNames.sort());
  assert.match(registryReadme, /npm package and MCP Registry entry remain on the older `0\.6\.0` track/i);
  assert.match(registryReadme, /local `server\.json` stages version `0\.7\.4`/i);
  assert.match(registryReadme, /do not publish this manifest until/i);
});

test("released setup guidance separates v0.7.3 fallback from current-main hardening", () => {
  const setupBoundaryGuides = {
    "README.md": repositoryGuidanceClaims["README.md"],
    "docs/getting-started.md": repositoryGuidanceClaims["docs/getting-started.md"],
    "docs/claude-code.md": repositoryGuidanceClaims["docs/claude-code.md"],
    "docs/codex.md": repositoryGuidanceClaims["docs/codex.md"],
    "docs/cursor.md": repositoryGuidanceClaims["docs/cursor.md"],
    "docs/windsurf.md": repositoryGuidanceClaims["docs/windsurf.md"],
    "docs/llms.txt": machineReadableClaims["docs/llms.txt"],
    "docs/llms-full.txt": machineReadableClaims["docs/llms-full.txt"],
    "apps/web/public/llms.txt": repositoryGuidanceClaims["apps/web/public/llms.txt"],
    "apps/web/public/llms-full.txt":
      repositoryGuidanceClaims["apps/web/public/llms-full.txt"],
  };

  for (const [file, source] of Object.entries(setupBoundaryGuides)) {
    assert.match(source, /Install both[^\n]*`v0\.7\.3`|both verified `v0\.7\.3` binaries/i, file);
    assert.match(
      source,
      /Released `v0\.7\.3`[\s\S]{0,420}legacy fallback[\s\S]{0,120}npx -y phantom-secrets-mcp/i,
      file,
    );
    assert.match(
      source,
      /Current main[\s\S]{0,160}(?:fails closed|removes (?:the )?network fallback)[\s\S]{0,180}(?:not (?:part of|in) `v0\.7\.3`|not `v0\.7\.3` behavior)/i,
      file,
    );
  }
});

test("HowTo and delegation guidance avoid timing and unpinned quickstart claims", () => {
  const installHowTo = structuredMetadataBlock(claims["src/app/layout.tsx"], "HowTo");
  const delegation = repositoryGuidanceClaims["docs/delegation-quickstart.md"];

  assert.doesNotMatch(installHowTo, /totalTime|PT1M/i);
  assert.match(installHowTo, /Released v0\.7\.3 normally registers its bundled `phantom mcp serve`/i);
  assert.match(installHowTo, /Current main removes that network fallback and fails closed/i);
  assert.match(delegation, /both `phantom` and `phantom-mcp` from the reviewed `v0\.7\.3` distribution/i);
  assert.match(delegation, /phantom agent setup --dry-run/i);
  assert.doesNotMatch(delegation, /npx(?:\s+-y)?\s+phantom-secrets\s+agent setup/i);
});

test("dashboard surfaces describe uncommissioned pilot metadata, not live entitlements", () => {
  const dashboardPaths = filesUnder("src/app/dashboard", [".tsx"]);
  const dashboardClaims = dashboardPaths.map((file) => read(file)).join("\n");

  for (const forbidden of [
    /\b1\s+cloud\s+vault\b/i,
    /Pro tier required/i,
    /View your cloud vaults, billing, and team membership/i,
    /No cloud vaults yet/i,
    /upload an encrypted backup/i,
  ]) {
    assert.doesNotMatch(dashboardClaims, forbidden);
  }

  for (const file of [
    "src/app/dashboard/layout.tsx",
    "src/app/dashboard/page.tsx",
    "src/app/dashboard/team/page.tsx",
    "src/app/dashboard/projects/[id]/page.tsx",
  ]) {
    assert.match(
      read(file),
      /not commissioned|uncommissioned|commissioned pilot|separately commissioned/i,
      file,
    );
  }
});

test("current SoftwareApplication and HowTo metadata point at the verified release", () => {
  const layout = claims["src/app/layout.tsx"];
  const softwareApplication = structuredMetadataBlock(layout, "SoftwareApplication");
  const installHowTo = structuredMetadataBlock(layout, "HowTo");

  assert.match(softwareApplication, /softwareVersion:\s*"0\.7\.3"/);
  assert.match(softwareApplication, /releases\/tag\/v0\.7\.3/);
  assert.doesNotMatch(softwareApplication, /npmjs\.com\/package\/phantom-secrets/i);
  assert.match(
    installHowTo,
    /(?:releases\/tag\/v0\.7\.3|brew trust --formula ashlrai\/phantom\/phantom)/i,
  );
  assert.doesNotMatch(
    installHowTo,
    /\b(?:npm\s+(?:install|i)|npx(?:\s+-y)?|cargo\s+install)\s+phantom-secrets(?:-mcp)?\b/i,
  );
});

test("public leak statistics use the primary GitGuardian 2026 report accurately", () => {
  const statisticalClaims = Object.entries(repositoryGuidanceClaims).filter(
    ([, source]) =>
      /GitGuardian|AI-assisted\s+commits?[^\n]{0,80}(?:leak|baseline)|(?:secrets?|credentials)[^\n]{0,80}(?:public\s+)?GitHub[^\n]{0,80}2025/i.test(
        source,
      ),
  );
  assert.ok(statisticalClaims.length >= 4, "expected public leak-statistic references");

  for (const [file, source] of statisticalClaims) {
    assert.doesNotMatch(source, /39\.6\s*(?:M|million)\b/i, file);
    assert.match(source, /28\.65\s*(?:M|million)\b|28,?649,?024\b/i, file);
    assert.match(
      source,
      /34\s*%[^\n]{0,80}year[- ]over[- ]year|year[- ]over[- ]year[^\n]{0,80}34\s*%/i,
      file,
    );
    assert.match(source, new RegExp(gitGuardianReportUrl.replaceAll(".", "\\.")), file);

    for (const line of source.split("\n").filter((value) => /81\s*%/.test(value))) {
      assert.match(
        line,
        /AI[- ]service[^\n]{0,80}81\s*%|81\s*%[^\n]{0,80}AI[- ]service/i,
        `${file}: ${line}`,
      );
    }
  }
});

test("machine-readable Pro copy is planned rather than active checkout evidence", () => {
  const proGuides = machineReadableGuides.filter(([, source]) => /\bPro\b/.test(source));
  assert.ok(proGuides.length >= 2, "expected planned Pro guidance in public references");

  for (const [file, source] of proGuides) {
    assert.match(
      source,
      /planned|commissioning required|verify the deployed entitlement/i,
      file,
    );
    assert.doesNotMatch(source, /Pro \(\$8\/mo\): unlimited cloud vaults/i, file);
    assert.doesNotMatch(source, /Pro \$8\/mo: unlimited cloud vaults/i, file);
    assert.doesNotMatch(source, /subscription is active|active checkout/i, file);
  }
});

test("machine-readable wrapping guidance remains selective", () => {
  for (const [file, source] of machineReadableGuides) {
    assert.match(source, /phantom[_ ]wrap/i, file);
    assert.match(source, /selected|selective|heuristically picks/i, file);
    assert.match(
      source,
      /(?:skip|left unchanged)[^\n]*(?:test[^\n]*lint|lint[^\n]*test)|(?:test[^\n]*lint|lint[^\n]*test)[^\n]*left unchanged/i,
      file,
    );
  }
});

test("machine-readable team guidance states authorization and access boundaries", () => {
  for (const [file, source] of machineReadableGuides) {
    assert.match(
      source,
      /owner\/admin[^\n]*gate[^\n]*invitation|invitation[^\n]*owner\/admin-gated|owner and admin roles gate invitations|only an owner or admin may invite|phantom_team_invite[^\n]*owner or admin role/i,
      file,
    );
    assert.match(source, /vault (?:read\/write )?access is member-wide|all members can read and write/i, file);
    assert.match(source, /offboarding[^\n]*(?:not shipped|control)/i, file);
  }
});

test("deprecated AI-plugin metadata cannot advertise a missing OpenAPI surface", () => {
  assert.equal(
    fs.existsSync(path.join(webDir, "public/.well-known/ai-plugin.json")),
    false,
  );
  assert.equal(
    fs.existsSync(path.join(webDir, "public/.well-known/openapi.yaml")),
    false,
  );
  assert.doesNotMatch(allClaims, /ai-plugin\.json|openapi\.yaml/i);
});

test("dotenv recovery copy does not confuse init, unwrap, and encrypted recovery", () => {
  const faq = claims["src/components/landing/FAQ.tsx"];
  assert.match(faq, /does not leave a plaintext/);
  assert.match(faq, /phantom unwrap/);
  assert.match(faq, /only reverses package-script[\s\S]*does not restore dotenv/);

  for (const file of ["public/llms.txt", "public/llms-full.txt"]) {
    assert.match(claims[file], /no plaintext project-local backup/i);
  }
});

test("persistent placeholders and both exec session credentials stay distinct", () => {
  for (const file of [
    "src/app/layout.tsx",
    "src/components/landing/FAQ.tsx",
    "public/llms.txt",
    "public/llms-full.txt",
  ]) {
    assert.match(claims[file], /persist\w* until/i, file);
    assert.match(claims[file], /fresh session[^\n]*phm_/i, file);
    assert.match(claims[file], /PHANTOM_PROXY_TOKEN/, file);
  }
});

test("connection strings are detection-only and absent from proxy visuals", () => {
  const proxyVisuals = [
    claims["src/components/landing/BrandLogos.tsx"],
    claims["src/components/landing/Transformation.tsx"],
  ].join("\n");
  assert.doesNotMatch(proxyVisuals, /DATABASE_URL|MONGODB_URI/);

  for (const file of ["public/llms.txt", "public/llms-full.txt"]) {
    assert.match(claims[file], /Connection strings?[\s\S]*database drivers do not use Phantom's HTTP proxy/i, file);
    assert.match(claims[file], /phantom exec[^\n]*fails closed/i, file);
  }
});

test("scanner copy names the staged and bounded behavior", () => {
  for (const file of [
    "src/components/landing/Features.tsx",
    "public/llms.txt",
    "public/llms-full.txt",
  ]) {
    assert.match(claims[file], /phantom check --staged/, file);
    assert.match(claims[file], /bounded[^\n]*(credential )?prefix/i, file);
  }
  assert.doesNotMatch(
    claims["src/components/landing/QuickStart.tsx"],
    /pre-commit hook installed/i,
  );
});

test("enterprise claims remain explicitly unavailable or contractual", () => {
  for (const [file, source] of Object.entries(claims)) {
    for (const line of source.split("\n")) {
      if (/SSO|SAML|on-prem/i.test(line)) {
        assert.match(line, /not shipped|planned/i, `${file}: ${line}`);
      }
    }
  }

  assert.doesNotMatch(allClaims, /SOC\s*2[-\s]*(certified|compliant)/i);
  assert.doesNotMatch(allClaims, /role-based access control|\bRBAC\b/i);
  assert.doesNotMatch(allClaims, /guaranteed uptime|uptime SLA/i);
  assert.match(claims["public/llms.txt"], /contractual SLA[^\n]*not shipped/i);
  assert.match(claims["public/llms.txt"], /written agreement with Ashlr AI/i);
  assert.match(allClaims, /fixed-membership pilots/i);
});

test("public guidance preserves upstream and production-authority boundaries", () => {
  assert.match(allClaims, /configured upstream/i);
  assert.match(claims["public/llms.txt"], /requests still leave the machine/i);
  assert.match(claims["public/llms-full.txt"], /requests still leave the machine/i);
  assert.match(claims["public/llms.txt"], /do not activate production execution/i);
  assert.match(claims["public/llms-full.txt"], /do not activate production execution/i);
});

test("structured metadata preserves supported-route and fail-closed boundaries", () => {
  const layout = claims["src/app/layout.tsx"];
  assert.match(layout, /supported HTTP SDK routes/);
  assert.match(layout, /configured supported HTTP routes/);
  assert.match(layout, /database connection strings fail closed/);
  assert.doesNotMatch(layout, /Any tool that reads \.env files works automatically/i);
});

test("team and support copy distinguishes source-backed pilots from hosted service", () => {
  const faq = claims["src/components/landing/FAQ.tsx"];
  assert.match(faq, /Pro-gated team-vault source/);
  assert.match(faq, /Hosted availability[\s\S]*commissioned Phantom Cloud deployment/);
  assert.doesNotMatch(claims["src/app/pricing/page.tsx"], /Priority support/i);
});

test("quickstart labels machine-dependent output as illustrative", () => {
  const quickstart = claims["src/components/landing/QuickStart.tsx"];
  assert.match(quickstart, /illustrative output/);
  assert.match(quickstart, /ephemeral-port/);
  assert.doesNotMatch(quickstart, /127\.0\.0\.1:8484/);
});

test("monorepo guidance scopes execution to one initialized subproject", () => {
  const fullReference = claims["public/llms-full.txt"];
  assert.match(fullReference, /Run `phantom exec` from the subproject/);
  assert.match(fullReference, /one session does not aggregate/);
  assert.doesNotMatch(fullReference, /A single `phantom exec` session handles all of them/i);
});

test("visible and structured FAQs retain conservative latency language", () => {
  assert.match(claims["src/components/landing/FAQ.tsx"], /Measure overhead in your own/);
  assert.match(claims["src/app/layout.tsx"], /measure overhead in your own/);
});
