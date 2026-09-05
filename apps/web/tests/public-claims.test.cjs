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
  "src/app/page.tsx",
  "src/app/pricing/page.tsx",
  "src/app/enterprise/page.tsx",
  "src/app/government/page.tsx",
  "src/app/security/page.tsx",
  "src/app/sitemap.ts",
  "src/lib/public-release.ts",
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
  "CODE_OF_CONDUCT.md": readRepo("CODE_OF_CONDUCT.md"),
  "CONTRIBUTING.md": readRepo("CONTRIBUTING.md"),
  "GOVERNANCE.md": readRepo("GOVERNANCE.md"),
  "ROADMAP.md": readRepo("ROADMAP.md"),
  "SECURITY.md": readRepo("SECURITY.md"),
  "SUPPORT.md": readRepo("SUPPORT.md"),
  "examples/README.md": readRepo("examples/README.md"),
  "integrations/github-actions/example-workflow.yml": readRepo(
    "integrations/github-actions/example-workflow.yml",
  ),
  "integrations/railway/README.md": readRepo("integrations/railway/README.md"),
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
  "https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.5";
const candidateReleaseUrl =
  "https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.8";

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

test("authority-sensitive command guidance stays fail-closed and value-blind", () => {
  const canonicalGuides = {
    "README.md": repositoryGuidanceClaims["README.md"],
    "AGENTS.md": repositoryGuidanceClaims["AGENTS.md"],
    "docs/llms.txt": machineReadableClaims["docs/llms.txt"],
    "docs/llms-full.txt": machineReadableClaims["docs/llms-full.txt"],
    "apps/web/public/llms.txt": repositoryGuidanceClaims["apps/web/public/llms.txt"],
    "apps/web/public/llms-full.txt":
      repositoryGuidanceClaims["apps/web/public/llms-full.txt"],
  };

  for (const [file, source] of Object.entries(canonicalGuides)) {
    assert.match(source, /export[\s\S]{0,300}passphrase[- ]file[\s\S]{0,180}(?:reject|disable)|export[^\n]{0,220}(?:reject|disable)[^\n]*passphrase[- ]file/i, file);
    assert.match(source, /import[\s\S]{0,700}(?:exact|typed)[^\n]*(?:challenge|consent|ceremon|plan)/i, file);
    assert.match(source, /--force[^\n]{0,120}(?:never|does not|cannot)[^\n]{0,80}(?:bypass|skip)/i, file);
    assert.doesNotMatch(source, /export[^\n]{0,180}passphrase[- ]file[^\n]*(?:automation|headless)/i, file);
    assert.doesNotMatch(source, /import[^\n]{0,180}--force[^\n]*(?:without prompt|skip confirmation)/i, file);
  }

  const machineCatalog = machineReadableClaims["apps/web/public/llms-full.txt"];
  assert.match(machineCatalog, /phantom_cloud_status[\s\S]{0,180}confirm[\s\S]{0,100}approval_token/i);
  assert.match(machineCatalog, /phantom_team_list[\s\S]{0,180}confirm[\s\S]{0,100}approval_token/i);
  assert.match(machineCatalog, /phantom_team_members[\s\S]{0,180}confirm[\s\S]{0,100}approval_token/i);
  assert.doesNotMatch(machineCatalog, /role \("member" \| "admin" \| "owner"\)/i);
  assert.doesNotMatch(machineCatalog, /Any other word becomes|full URLs pass through/i);
  assert.match(machineCatalog, /phantom cloud status[\s\S]{0,180}attached[\s\S]{0,120}exact[\s\S]{0,120}challenge/i);
  assert.match(machineCatalog, /CLI `list` and `members`[\s\S]{0,220}attached[\s\S]{0,120}exact typed challenge/i);
  assert.match(machineCatalog, /phantom_apply_expiry_policy[\s\S]{0,360}does not recall/i);
  assert.doesNotMatch(machineCatalog, /advisory `VaultMode`/i);

  const cli = readRepo("crates/phantom-cli/src/main.rs");
  assert.doesNotMatch(cli, /Skip the standalone self-replacement confirmation prompt/i);
  assert.doesNotMatch(cli, /Role to assign \(member, admin, owner\)/i);
  assert.match(cli, /cannot bypass the standalone replacement ceremonies/i);
  assert.match(cli, /ownership transfer is not exposed/i);
});

test("MCP setup guidance stays proposal-first and Linux storage matches the built backend", () => {
  const setupGuides = {
    "docs/llms-full.txt": machineReadableClaims["docs/llms-full.txt"],
    "apps/web/public/llms-full.txt":
      machineReadableClaims["apps/web/public/llms-full.txt"],
  };

  for (const [file, source] of Object.entries(setupGuides)) {
    assert.match(source, /ask Claude to propose protection/i, file);
    assert.match(source, /review mutations[\s\S]{0,120}trusted terminal/i, file);
    assert.doesNotMatch(source, /Claude runs phantom_init/i, file);
  }

  const linuxVaultStorageGuides = [
    "README.md",
    "docs/llms.txt",
    "docs/platform-support.md",
    "docs/troubleshooting.md",
    "apps/web/public/llms.txt",
    "apps/web/public/llms-full.txt",
  ];

  for (const file of linuxVaultStorageGuides) {
    const source = readRepo(file);
    assert.match(source, /Linux[\s\S]{0,120}(?:keyutils|kernel keyring)/i, file);
    assert.match(
      source,
      /(?:migrate-linux|explicit[\s\S]{0,120}Secret Service|Secret Service[\s\S]{0,120}migrat)/i,
      file,
    );
    assert.match(source, /(?:does not|do not) survive a reboot/i, file);
  }

  const loginGuide = readRepo("docs/login.md");
  assert.match(loginGuide, /Linux[\s\S]{0,120}kernel keyring/i);
  assert.match(loginGuide, /(?:does not|do not) survive a reboot/i);
  assert.doesNotMatch(loginGuide, /Secret Service/i);
});

test("Railway guidance separates deployment sync from encrypted cloud backup", () => {
  const railway = repositoryGuidanceClaims["integrations/railway/README.md"];
  assert.match(railway, /sends selected values directly to the\s+Railway API/i);
  assert.match(railway, /phantom cloud push[\s\S]{0,160}never deploys or auto-syncs Railway/i);
  assert.doesNotMatch(railway, /cloud push[^\n]*auto-syncs to Railway/i);
});

test("CLI and crate metadata state bounded credential-exposure claims", () => {
  const metadata = {
    "Cargo.toml": readRepo("Cargo.toml"),
    "crates/phantom-cli/Cargo.toml": readRepo("crates/phantom-cli/Cargo.toml"),
    "crates/phantom-cli/src/main.rs": readRepo("crates/phantom-cli/src/main.rs"),
  };

  for (const [file, source] of Object.entries(metadata)) {
    assert.doesNotMatch(source, /prevents? AI coding agents from leaking/i, file);
    assert.doesNotMatch(source, /AI agent never sees a real secret/i, file);
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
    assert.ok(source.includes(verifiedReleaseUrl), file);
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
    if (file === "mcp-registry/README.md") {
      assert.ok(source.includes(verifiedReleaseUrl), file);
      assert.match(
        source,
        /Released `v0\.7\.5`[\s\S]{0,300}no network package-runner fallback[\s\S]{0,120}fails closed/i,
        file,
      );
    } else {
      assert.ok(source.includes(candidateReleaseUrl), file);
      assert.match(
        source,
        /version `0\.7\.8`[\s\S]{0,180}(?:do not prove|does not prove)[\s\S]{0,80}(?:npm|published)/i,
        file,
      );
      assert.match(
        source,
        /(?:npm query|release|checksum)[\s\S]{0,120}unavailable[\s\S]{0,120}stop/i,
        file,
      );
      assert.match(
        source,
        /Version `0\.7\.8`[\s\S]{0,250}no network package-runner fallback[\s\S]{0,80}fails closed/i,
        file,
      );
      assert.doesNotMatch(source, /releases\/tag\/v0\.7\.3/i, file);
    }
    assert.match(source, /installed local `phantom`|installed local CLI/i, file);
    assert.match(source, /`phantom mcp serve`/i, file);
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
  assert.match(registryReadme, /npm `0\.7\.4` wrappers are public only under `release-candidate`/i);
  assert.match(registryReadme, /local `server\.json` stages version `0\.7\.8`/i);
  assert.match(registryReadme, /do not publish this manifest until/i);
});

test("released setup guidance uses the verified v0.7.5 fail-closed local runtime", () => {
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
    assert.match(source, /Install both[^\n]*`v0\.7\.5`|both verified `v0\.7\.5`(?: GitHub release)? binaries/i, file);
    assert.match(source, /(?:Version|Released) `?v?0\.7\.5/i, file);
    assert.match(
      source,
      /no network\s+package-runner fallback[\s\S]{0,80}fails closed|fails closed instead of generating a registry-backed command/i,
      file,
    );
    assert.doesNotMatch(source, /Released `v0\.7\.3`[\s\S]{0,500}legacy fallback/i, file);
  }
});

test("HowTo and delegation guidance avoid timing and unpinned quickstart claims", () => {
  const installHowTo = claims["src/components/landing/LandingStructuredData.tsx"];
  const publicRelease = claims["src/lib/public-release.ts"];
  const delegation = repositoryGuidanceClaims["docs/delegation-quickstart.md"];

  assert.doesNotMatch(installHowTo, /totalTime|PT1M/i);
  assert.match(installHowTo, /review the generated local MCP entry/i);
  assert.match(publicRelease, /PUBLIC_RELEASE_VERSION\s*=\s*"0\.7\.5"/);
  assert.match(installHowTo, /no network package-runner fallback/i);
  assert.match(delegation, /both `phantom` and `phantom-mcp` from the reviewed `v0\.7\.5`[^\n]*GitHub release/i);
  assert.match(delegation, /phantom agent setup --dry-run/i);
  assert.doesNotMatch(delegation, /npx(?:\s+-y)?\s+phantom-secrets\s+agent setup/i);
});

test("dashboard surfaces describe uncommissioned pilot metadata, not live entitlements", () => {
  const dashboardPaths = filesUnder("src/app/dashboard", [".tsx"]);
  const dashboardClaims = dashboardPaths.map((file) => read(file)).join("\n");
  const dashboardLayout = read("src/app/dashboard/layout.tsx");

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

  assert.match(dashboardLayout, /"unavailable"/);
  assert.match(dashboardLayout, /Hosted boundary closed/);
  assert.match(dashboardLayout, /browser-auth configuration/);
});

test("current SoftwareApplication and HowTo metadata point at the verified release", () => {
  const layout = claims["src/app/layout.tsx"];
  const publicRelease = claims["src/lib/public-release.ts"];
  const softwareApplication = structuredMetadataBlock(layout, "SoftwareApplication");
  const installHowTo = claims["src/components/landing/LandingStructuredData.tsx"];

  assert.match(publicRelease, /PUBLIC_RELEASE_VERSION\s*=\s*"0\.7\.5"/);
  assert.match(publicRelease, /PUBLIC_RELEASE_TAG\s*=\s*`v\$\{PUBLIC_RELEASE_VERSION\}`/);
  assert.match(publicRelease, /releases\/tag\/\$\{PUBLIC_RELEASE_TAG\}/);
  assert.match(softwareApplication, /softwareVersion:\s*PUBLIC_RELEASE_VERSION/);
  assert.match(softwareApplication, /downloadUrl:\s*PUBLIC_RELEASE_URL/);
  assert.doesNotMatch(softwareApplication, /npmjs\.com\/package\/phantom-secrets/i);
  assert.match(
    installHowTo,
    /(?:PUBLIC_RELEASE_URL|brew trust --formula ashlrai\/phantom\/phantom)/i,
  );
  assert.doesNotMatch(
    installHowTo,
    /\b(?:npm\s+(?:install|i)|npx(?:\s+-y)?|cargo\s+install)\s+phantom-secrets(?:-mcp)?\b/i,
  );

  const quickStart = claims["src/components/landing/QuickStart.tsx"];
  const install = claims["src/components/landing/Install.tsx"];
  assert.match(quickStart, /Verify both \$\{PUBLIC_RELEASE_TAG\} binaries/);
  assert.match(quickStart, /PUBLIC_RELEASE_RECEIPT/);
  assert.match(install, /both pinned \{PUBLIC_RELEASE_TAG\} binaries/);
  assert.doesNotMatch(`${quickStart}\n${install}`, /(?:Install|reviewed) v0\.7\.3/i);
});

test("public release references bind v0.7.5 to its immutable publication receipt", () => {
  const releaseGuides = [
    readRepo("docs/llms.txt"),
    readRepo("docs/llms-full.txt"),
    readRepo("apps/web/public/llms.txt"),
    readRepo("apps/web/public/llms-full.txt"),
    readRepo("docs/platform-support.md"),
  ];

  for (const source of releaseGuides) {
    assert.match(source, /2026-09-03/);
    assert.match(source, /d2969e73995cc139e6253e0c8a70f1d683f88e20/);
    assert.match(source, /33709338577/);
    assert.match(source, /19 assets/i);
    assert.match(source, /all six native|six-row native/i);
    assert.match(source, /attestations/i);
    assert.match(source, /Homebrew[^\n]*v0\.7\.5/i);
  }

  const fullReferences = [
    readRepo("docs/llms-full.txt"),
    readRepo("apps/web/public/llms-full.txt"),
  ];
  for (const source of fullReferences) {
    assert.equal(
      source.match(/releases\/download\/v0\.7\.5\/phantom-(?:aarch64|x86_64)-(?:apple-darwin|unknown-linux-gnu|pc-windows-msvc)\.(?:tar\.gz|zip)/g)?.length,
      6,
      "full reference must link all six exact v0.7.5 archives",
    );
  }
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
    assert.match(
      source,
      /https:\/\/blog\.gitguardian\.com\/the-state-of-secrets-sprawl-2026\//,
      file,
    );

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

test("persistent placeholders remain inert and the proxy bearer stays distinct", () => {
  for (const file of [
    "src/components/landing/FAQ.tsx",
    "public/llms.txt",
    "public/llms-full.txt",
  ]) {
    assert.match(claims[file], /persist\w* until/i, file);
    assert.match(claims[file], /(?:fresh[^\n]*(?:phm_|placeholder)|child[^\n]*fresh[^\n]*placeholder)/i, file);
    assert.match(claims[file], /PHANTOM_PROXY_TOKEN/, file);
    assert.match(claims[file], /(?:never[^\n]*resolv|remain[^\n]*inert)/i, file);
  }
});

test("connection strings are detection-only and absent from proxy visuals", () => {
  const proxyVisuals = [
    claims["src/components/landing/RequestTrace.tsx"],
    claims["src/components/landing/TrustBoundary.tsx"],
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
        assert.match(
          line,
          /not shipped|planned|no\b.*\b(?:available|offered)|not (?:available|offered|represented)/i,
          `${file}: ${line}`,
        );
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

test("organization pages preserve written-scope and certification boundaries", () => {
  const enterprise = claims["src/app/enterprise/page.tsx"];
  const government = claims["src/app/government/page.tsx"];
  const security = claims["src/app/security/page.tsx"];
  const commercialOfferings = read("src/lib/commercial-offerings.ts");

  assert.match(enterprise, /written[- ]scope/i);
  assert.match(enterprise, /non-production/i);
  assert.match(enterprise, /COMMERCIAL_NON_CLAIMS/);
  assert.match(commercialOfferings, /only as written|written agreement/i);
  assert.match(enterprise, /not represented as shipped, certified, commissioned/i);

  assert.match(government, /not represented as FedRAMP authorized or FIPS validated/i);
  assert.match(government, /No government contract vehicle/i);
  assert.match(government, /outside a signed agreement/i);
  assert.doesNotMatch(government, /FedRAMP authorized(?! or)|FIPS validated(?!\.)/i);

  assert.match(security, /not a sandbox/i);
  assert.match(security, /not live integrations/i);
  assert.match(security, /not claimed/i);
  assert.doesNotMatch(security, /zero exposure|unhackable|guaranteed/i);
});

test("public guidance preserves upstream and production-authority boundaries", () => {
  assert.match(allClaims, /configured upstream/i);
  assert.match(claims["public/llms.txt"], /requests still leave the machine/i);
  assert.match(claims["public/llms-full.txt"], /requests still leave the machine/i);
  assert.match(claims["public/llms.txt"], /do not activate production execution/i);
  assert.match(claims["public/llms-full.txt"], /do not activate production execution/i);
});

test("structured metadata preserves supported-route and fail-closed boundaries", () => {
  const metadata = `${claims["src/app/layout.tsx"]}\n${claims["src/components/landing/LandingStructuredData.tsx"]}`;
  assert.match(metadata, /supported HTTP SDK routes/);
  assert.match(metadata, /Exact matched routes/);
  assert.match(metadata, /route-owned authentication/);
  assert.match(metadata, /placeholders stay inert/);
  assert.match(metadata, /database connection strings fail closed/);
  assert.doesNotMatch(metadata, /Any tool that reads \.env files works automatically/i);
});

test("team and support copy distinguishes source-backed pilots from hosted service", () => {
  const faq = claims["src/components/landing/FAQ.tsx"];
  assert.match(faq, /Pro-gated team-vault source/);
  assert.match(faq, /Hosted availability[\s\S]*commissioned Phantom Cloud deployment/);
  assert.doesNotMatch(claims["src/app/pricing/page.tsx"], /Priority support/i);
});

test("quickstart labels machine-dependent output as illustrative", () => {
  const quickstart = claims["src/components/landing/QuickStart.tsx"];
  const install = claims["src/components/landing/Install.tsx"];
  assert.match(quickstart, /illustrative output/);
  assert.match(install, /phantom agent doctor/);
  assert.match(install, /phantom exec --/);
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
  assert.match(claims["src/components/landing/LandingStructuredData.tsx"], /QUESTIONS\.map/);
});

test("community health metadata preserves release and support boundaries", () => {
  for (const file of [
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "ROADMAP.md",
    "SECURITY.md",
    "SUPPORT.md",
    "examples/README.md",
    ".github/ISSUE_TEMPLATE/documentation.yml",
  ]) {
    assert.equal(fs.existsSync(path.join(repoDir, file)), true, `missing ${file}`);
  }

  assert.equal(
    fs.existsSync(path.join(repoDir, ".github/FUNDING.yml")),
    false,
    "do not expose a Sponsor button until a real sponsorship program exists",
  );

  const readme = readRepo("README.md");
  assert.match(readme, /release-state snapshot[^\n]*2026-09-03/i);
  assert.match(readme, /v0\.7\.5[\s\S]{0,80}reviewed[\s\S]{0,30}immutable GitHub release/i);
  assert.match(readme, /d2969e73995cc139e6253e0c8a70f1d683f88e20/);
  assert.match(readme, /workflow[\s\S]{0,120}33709338577/i);
  assert.match(readme, /Homebrew publishes the same reviewed `v0\.7\.5`/i);

  const roadmap = readRepo("ROADMAP.md");
  assert.match(roadmap, /ordered engineering gates, not delivery dates/i);
  assert.match(roadmap, /\| Released \|[\s\S]*\| Staged \|[\s\S]*\| Gated \|[\s\S]*\| Exploratory \|/);
  assert.match(roadmap, /Completed at exact source commit[\s\S]*prerequisite, not publication evidence/i);

  const support = readRepo("SUPPORT.md");
  assert.match(
    support,
    /does\s+not promise paid support, priority response, uptime, or a contractual service\s+level/i,
  );
  assert.match(support, /security\/advisories\/new/);
  assert.match(support, /Persistent mappings are sensitive metadata/i);

  const citation = readRepo("CITATION.cff");
  assert.match(citation, /^cff-version: 1\.2\.0$/m);
  assert.match(citation, /^version: 0\.7\.8$/m);
  assert.match(citation, /immutable v0\.7\.7 GitHub release/i);
  assert.match(citation, /repository URL and full commit SHA/i);
  assert.doesNotMatch(
    citation,
    /^date-released:/m,
    "unpublished source candidates must not claim a release date",
  );
});

test("cloud-signed audit remains an explicit network-free protocol foundation", () => {
  const coreAudit = readRepo("crates/phantom-core/src/audit.rs");
  const setup = readRepo("crates/phantom-cli/src/commands/setup.rs");
  const security = readRepo("SECURITY.md");
  const enterprise = readRepo("docs/enterprise-adoption.md");

  assert.doesNotMatch(coreAudit, /https:\/\/phm\.dev\/api\/audit\/ingest/i);
  assert.doesNotMatch(setup, /https:\/\/phm\.dev\/compliance/i);
  assert.doesNotMatch(setup, /will be signed and uploaded/i);
  assert.doesNotMatch(coreAudit, /compliance-grade tamper-proof audit delivery/i);
  assert.match(setup, /cloud-signed audit delivery is not commissioned/i);
  assert.match(security, /legacy shell settings retain events with local encryption/i);
  assert.match(security, /making no audit-delivery network request/i);
  assert.match(enterprise, /protocol-only and hard-disabled/i);
  assert.match(enterprise, /without network I\/O/i);
});

test("add guidance keeps headless creation separate from replacement authority", () => {
  const addSource = readRepo("crates/phantom-cli/src/commands/add.rs");
  const gettingStarted = readRepo("docs/getting-started.md");
  const machineGuides = [
    readRepo("docs/llms.txt"),
    readRepo("docs/llms-full.txt"),
    readRepo("apps/web/public/llms.txt"),
    readRepo("apps/web/public/llms-full.txt"),
  ].join("\n");

  assert.match(addSource, /refuses replacement before reading a value/i);
  assert.match(gettingStarted, /existing protected name is denied[\s\S]*before Phantom reads/i);
  assert.match(machineGuides, /existing names are denied before prompt\/stdin read/i);
  assert.doesNotMatch(machineGuides, /replace(?:s|ment)? an existing (?:protected )?(?:name|secret)/i);
});

test("contributor templates keep secrets and evidence layers separated", () => {
  const bug = readRepo(".github/ISSUE_TEMPLATE/bug_report.yml");
  assert.match(bug, /placeholder: "phantom 0\.7\.7"/);
  assert.match(bug, /persistent `phm_` mappings; mappings are sensitive metadata/i);
  assert.doesNotMatch(bug, /phm_ tokens are safe to share/i);
  assert.match(bug, /private vulnerability reporting/i);

  const feature = readRepo(".github/ISSUE_TEMPLATE/feature_request.yml");
  assert.match(feature, /Source, artifact, publication, deployment, provider activation, and user acceptance are separate outcomes/i);
  assert.match(feature, /Acceptance and rollback/i);

  const pullRequest = readRepo(".github/pull_request_template.md");
  assert.match(pullRequest, /cargo test --workspace --all-targets --locked --no-fail-fast/);
  assert.match(pullRequest, /cargo clippy --workspace --all-targets --locked -- -D warnings/);
  assert.match(pullRequest, /\| Native artifact \| Not claimed \/ \|/);
  assert.match(pullRequest, /authority, rollback, and recovery analysis/i);
});

test("community and entry-point Markdown links resolve inside the repository", () => {
  const files = [
    "README.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "ROADMAP.md",
    "SECURITY.md",
    "SUPPORT.md",
    "docs/README.md",
    "examples/README.md",
  ];

  for (const file of files) {
    const source = readRepo(file).replace(/```[\s\S]*?```/g, "");
    const links = source.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g);
    for (const match of links) {
      let target = match[1].trim();
      if (target.startsWith("<") && target.endsWith(">")) {
        target = target.slice(1, -1);
      }
      if (/^(?:https?:|mailto:)/i.test(target)) continue;

      const [relativeTarget, rawFragment] = target.split("#", 2);
      const resolved = relativeTarget
        ? path.resolve(repoDir, path.dirname(file), decodeURIComponent(relativeTarget))
        : path.join(repoDir, file);
      assert.ok(
        resolved === repoDir || resolved.startsWith(`${repoDir}${path.sep}`),
        `${file} link escapes repository: ${match[1]}`,
      );
      assert.equal(
        fs.existsSync(resolved),
        true,
        `${file} has missing relative link: ${match[1]}`,
      );

      if (rawFragment && path.extname(resolved).toLowerCase() === ".md") {
        const headings = fs
          .readFileSync(resolved, "utf8")
          .split("\n")
          .filter((line) => /^#{1,6}\s+/.test(line))
          .map((line) =>
            line
              .replace(/^#{1,6}\s+/, "")
              .trim()
              .toLowerCase()
              .replace(/[`*_~]/g, "")
              .replace(/[^\p{Letter}\p{Number}\s-]/gu, "")
              .replace(/\s+/g, "-"),
          );
        assert.ok(
          headings.includes(decodeURIComponent(rawFragment).toLowerCase()),
          `${file} has missing Markdown anchor: ${match[1]}`,
        );
      }
    }
  }
});
