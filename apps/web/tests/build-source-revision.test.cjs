const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const helperPath = path.resolve(__dirname, "../src/lib/build-source-revision.ts");
const compiled = ts.transpileModule(fs.readFileSync(helperPath, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const helper = { exports: {} };
new Function("require", "exports", "module", compiled)(require, helper.exports, helper);
const { readBuildSourceRevision } = helper.exports;

function buildMetadata(directory) {
  const configPath = path.resolve(__dirname, "../next.config.ts");
  const config = ts.transpileModule(fs.readFileSync(configPath, "utf8"), {
    compilerOptions: {
      esModuleInterop: true, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  const module = { exports: {} };
  function localRequire(name) {
    if (name === "./src/lib/build-source-revision") return helper.exports;
    if (name === "./src/lib/public-auth-configuration") {
      return { publicAuthConfigurationFingerprint: () => null };
    }
    if (name === "./docs-routes.json") return require("../docs-routes.json");
    return require(name);
  }
  new Function("require", "exports", "module", "__dirname", config)(
    localRequire, module.exports, module, directory,
  );
  return module.exports.default.env.PHANTOM_BUILD_SOURCE_REVISION;
}

function withRepository(action) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-build-source-"));
  const gitEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
  );
  function git(...args) {
    return execFileSync("git", ["-C", directory, ...args], {
      encoding: "utf8", env: gitEnvironment,
    }).trim();
  }
  try {
    git("init", "--quiet");
    fs.writeFileSync(path.join(directory, "source.txt"), "owned source\n");
    git("add", "source.txt");
    git("-c", "user.name=Phantom fixture", "-c", "user.email=fixture@example.invalid",
      "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
      "commit", "--quiet", "-m", "Owned source");
    action({ directory, git, revision: git("rev-parse", "HEAD") });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("build source observes an actual clean Git commit and tree, including detached HEAD", () => {
  withRepository(({ directory, git, revision }) => {
    assert.match(git("rev-parse", "HEAD^{tree}"), /^[0-9a-f]{40}$/);
    assert.equal(readBuildSourceRevision(directory), revision);
    git("checkout", "--quiet", "--detach", revision);
    assert.equal(readBuildSourceRevision(directory), revision);
  });
});

test("repeated reads of a stable source revision display the same value", () => {
  withRepository(({ directory, revision }) => {
    for (let read = 0; read < 3; read++) {
      assert.equal(readBuildSourceRevision(directory), revision);
      assert.equal(buildMetadata(directory), revision);
    }
  });
});

test("staged, unstaged and untracked source are unidentified", () => {
  for (const kind of ["unstaged", "staged", "untracked"]) {
    withRepository(({ directory, git }) => {
      fs.writeFileSync(path.join(directory, kind === "untracked" ? "new.txt" : "source.txt"), "changed source\n");
      if (kind === "staged") git("add", "source.txt");
      assert.equal(readBuildSourceRevision(directory), null, kind);
    });
  }
});

test("copied source without Git or a committed HEAD is unidentified", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-copied-source-"));
  try {
    assert.equal(readBuildSourceRevision(directory), null);
    execFileSync("git", ["-C", directory, "init", "--quiet"]);
    assert.equal(readBuildSourceRevision(directory), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("build metadata falls back when source revision is unavailable", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-build-metadata-"));
  try {
    assert.equal(buildMetadata(directory), "unidentified", "source without Git");
    execFileSync("git", ["-C", directory, "init", "--quiet"]);
    assert.equal(buildMetadata(directory), "unidentified", "repository without a commit");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
  withRepository(({ directory, revision }) => {
    assert.equal(buildMetadata(directory), revision, "clean committed source");
  });
});

test("caller source and Git environment overrides cannot bind a different checkout", () => {
  withRepository(({ directory, revision }) => {
    withRepository(({ directory: other, git: otherGit }) => {
      fs.writeFileSync(path.join(other, "other.txt"), "different source\n");
      otherGit("add", "other.txt");
      otherGit("-c", "user.name=Phantom fixture", "-c", "user.email=fixture@example.invalid",
        "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
        "commit", "--quiet", "-m", "Different source");
      assert.notEqual(otherGit("rev-parse", "HEAD"), revision);
      const values = {
        PHANTOM_BUILD_SOURCE_REVISION: "f".repeat(40),
        GIT_DIR: path.join(other, ".git"),
        GIT_WORK_TREE: other,
        GIT_INDEX_FILE: path.join(other, ".git/index"),
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.worktree",
        GIT_CONFIG_VALUE_0: other,
      };
      const previous = new Map(Object.keys(values).map((name) => [name, process.env[name]]));
      try {
        Object.assign(process.env, values);
        assert.equal(readBuildSourceRevision(directory), revision);
        fs.writeFileSync(path.join(directory, "source.txt"), "dirty real checkout\n");
        assert.equal(readBuildSourceRevision(directory), null);
      } finally {
        for (const [name, value] of previous) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
      }
    });
  });
});

for (const flag of ["--assume-unchanged", "--skip-worktree"]) {
  test(`hidden tracked changes (${flag}) cannot become a build witness`, () => {
    withRepository(({ directory, git }) => {
      git("update-index", flag, "source.txt");
      fs.writeFileSync(path.join(directory, "source.txt"), "hidden changed bytes\n");
      assert.equal(git("status", "--porcelain=v1"), "");
      assert.equal(readBuildSourceRevision(directory), null);
    });
  });
}

test("source drift between actual Git observations is refused", () => {
  withRepository(({ directory }) => {
    let changed = false;
    const module = { exports: {} };
    function localRequire(name) {
      if (name !== "node:child_process") return require(name);
      return { execFileSync(command, args, options) {
        const result = execFileSync(command, args, options);
        if (!changed && args.includes("status")) {
          changed = true;
          fs.writeFileSync(path.join(directory, "source.txt"), "source changed during observation\n");
        }
        return result;
      } };
    }
    new Function("require", "exports", "module", compiled)(localRequire, module.exports, module);
    assert.equal(module.exports.readBuildSourceRevision(directory), null);
    assert.equal(changed, true);
  });
});
