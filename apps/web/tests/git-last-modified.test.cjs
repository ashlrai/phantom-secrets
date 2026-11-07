const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.resolve(__dirname, "../src/lib/git-last-modified.ts"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const helper = { exports: {} };
new Function("require", "exports", "module", compiled)(require, helper.exports, helper);
const { gitLastModified } = helper.exports;

function assertDate(actual, expected) {
  assert.equal(typeof actual, "string");
  assert.equal(Date.parse(actual), Date.parse(expected));
}

function withRepository(action) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-lastmod-"));
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
  function git(args, extraEnvironment = {}) {
    return execFileSync("git", ["-C", directory, ...args], {
      encoding: "utf8", env: { ...environment, ...extraEnvironment }, stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  }
  function commit(file, date) {
    fs.mkdirSync(path.dirname(path.join(directory, file)), { recursive: true });
    fs.writeFileSync(path.join(directory, file), `Fixture content at ${date}\n`);
    git(["add", "--", file]);
    git(["-c", "user.name=Phantom fixture", "-c", "user.email=fixture@example.invalid",
      "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture change"],
    { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date });
  }
  try {
    git(["init", "--quiet"]);
    action({ directory, git, commit });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("lastmod follows the latest relevant content commit, not HEAD or the build clock", () => {
  withRepository(({ directory, commit }) => {
    commit("page.tsx", "2025-01-01T12:00:00+00:00");
    commit("components/card.tsx", "2025-02-02T12:00:00+00:00");
    commit("unrelated.txt", "2025-03-03T12:00:00+00:00");
    assertDate(gitLastModified(directory, ["page.tsx"]), "2025-01-01T12:00:00+00:00");
    assertDate(gitLastModified(directory, ["page.tsx", "components"]), "2025-02-02T12:00:00+00:00");
    fs.writeFileSync(path.join(directory, "page.tsx"), "Unpublished edits\n");
    assertDate(gitLastModified(directory, ["page.tsx"]), "2025-01-01T12:00:00+00:00");
  });
});

test("lastmod omits dates for empty inputs, untracked content, and repositories without a commit", () => {
  withRepository(({ directory, git, commit }) => {
    fs.writeFileSync(path.join(directory, "draft.tsx"), "Draft\n");
    assert.equal(gitLastModified(directory, []), undefined);
    assert.equal(gitLastModified(directory, ["draft.tsx"]), undefined);
    git(["add", "draft.tsx"]);
    assert.equal(gitLastModified(directory, ["draft.tsx"]), undefined);
    commit("page.tsx", "2025-01-01T12:00:00+00:00");
    fs.writeFileSync(path.join(directory, "new.tsx"), "Untracked\n");
    assert.equal(gitLastModified(directory, ["page.tsx", "new.tsx"]), undefined);
  });
});

test("copied source without Git does not invent a modification date", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-no-git-"));
  try {
    fs.writeFileSync(path.join(directory, "page.tsx"), "Copied content\n");
    assert.equal(gitLastModified(directory, ["page.tsx"]), undefined);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("caller Git overrides cannot source modification dates from another repository", () => {
  withRepository(({ directory, commit }) => {
    commit("page.tsx", "2025-01-01T12:00:00+00:00");
    withRepository(({ directory: other, commit: otherCommit }) => {
      otherCommit("page.tsx", "2025-04-04T12:00:00+00:00");
      const overrides = {
        GIT_DIR: path.join(other, ".git"), GIT_WORK_TREE: other,
        GIT_INDEX_FILE: path.join(other, ".git/index"), GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.worktree", GIT_CONFIG_VALUE_0: other,
      };
      const previous = new Map(Object.keys(overrides).map((key) => [key, process.env[key]]));
      try {
        Object.assign(process.env, overrides);
        assertDate(gitLastModified(directory, ["page.tsx"]), "2025-01-01T12:00:00+00:00");
      } finally {
        for (const [key, value] of previous) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
      }
    });
  });
});

test("shallow history never substitutes an unrelated boundary commit for a page's modification date", () => {
  withRepository(({ directory, commit }) => {
    commit("page.tsx", "2025-01-01T12:00:00+00:00");
    commit("unrelated.txt", "2025-05-05T12:00:00+00:00");
    const clone = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-shallow-"));
    const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
    try {
      execFileSync("git", ["clone", "--quiet", "--depth", "1", `file://${directory}`, clone], {
        env: environment, stdio: ["ignore", "pipe", "pipe"],
      });
      assert.equal(gitLastModified(clone, ["page.tsx"]), undefined);
    } finally {
      fs.rmSync(clone, { recursive: true, force: true });
    }
  });
});

test("lastmod ignores a caller PATH containing a counterfeit Git", () => {
  withRepository(({ directory, commit }) => {
    commit("page.tsx", "2025-01-01T12:00:00+00:00");
    const fakeBin = path.join(directory, "bin");
    fs.mkdirSync(fakeBin);
    const marker = path.join(directory, "counterfeit-ran");
    fs.writeFileSync(path.join(fakeBin, "git"), `#!/bin/sh\n: > '${marker}'\nexit 1\n`, { mode: 0o755 });
    const previous = process.env.PATH;
    try {
      process.env.PATH = fakeBin;
      assertDate(gitLastModified(directory, ["page.tsx"]), "2025-01-01T12:00:00+00:00");
      assert.equal(fs.existsSync(marker), false);
    } finally {
      if (previous === undefined) delete process.env.PATH;
      else process.env.PATH = previous;
    }
  });
});
