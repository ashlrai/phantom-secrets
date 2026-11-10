import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { Children, isValidElement, type ReactElement, type ReactNode } from "react";
import { QuickStart } from "./QuickStart";

// Offline: reads the displayed command from the element tree (no DOM, no
// network) and runs only its local staging prologue in bash.

interface Inspected {
  children?: ReactNode;
  text?: string;
  onClick?: () => void;
}
type El = ReactElement<Inspected>;

function find(node: ReactNode, pred: (el: El) => boolean): El[] {
  if (!isValidElement<Inspected>(node)) return [];
  return [
    ...(pred(node) ? [node] : []),
    ...Children.toArray(node.props.children).flatMap((child) => find(child, pred)),
  ];
}

function displayedCommand(platform: string): string {
  const button = find(QuickStart(), (el) => el.type === "button").find(
    (el) => el.props.children === platform,
  );
  assert.ok(button?.props.onClick, `${platform}: selector button is clickable`);
  button.props.onClick();
  const cards = find(QuickStart(), (el) => el.type === "article");
  assert.equal(cards.length, 1, `${platform}: one install card`);
  const commands = find(cards[0], (el) => typeof el.props.text === "string");
  assert.equal(commands.length, 1, `${platform}: one displayed command`);
  return commands[0].props.text as string;
}

const TEMPLATE = '"${TMPDIR:-/tmp}/phantom-install.XXXXXX"';

for (const platform of ["macOS", "Linux"]) {
  test(`${platform}: every displayed TMPDIR template defaults to /tmp`, () => {
    const displayed = displayedCommand(platform);
    const uses = displayed.match(/\$\{?TMPDIR[^\s"]*/g) ?? [];
    assert.ok(uses.length > 0, `${platform}: a TMPDIR staging template is displayed`);
    for (const use of uses) {
      assert.ok(use.startsWith("${TMPDIR:-/tmp}"), `${platform}: bare TMPDIR use: ${use}`);
    }
    assert.ok(displayed.includes(TEMPLATE), `${platform}: quoted template is displayed`);
  });

  test(`${platform}: displayed staging stages under /tmp when TMPDIR is unset`, () => {
    const lines = displayedCommand(platform).split("\n");
    const trap = lines.findIndex((line) => line.startsWith("trap "));
    assert.ok(trap > 0, `${platform}: EXIT trap precedes any download`);
    // Real prologue only; the download and install steps are dropped.
    const script = [...lines.slice(0, trap + 1), 'printf "%s\\n" "$phantom_stage"', ")"].join("\n");

    const home = mkdtempSync(path.join(tmpdir(), "phantom-fallback-home-"));
    try {
      const { TMPDIR: _unset, ...inherited } = process.env;
      const env: NodeJS.ProcessEnv = { ...inherited, HOME: home };
      const result = spawnSync("bash", ["-c", script], { env, encoding: "utf8", timeout: 30000 });
      assert.equal(result.status, 0, result.stderr);
      const stage = result.stdout.trim();
      assert.match(stage, /^\/tmp\/phantom-install\.[A-Za-z0-9]{6}$/, `${platform}: staged under /tmp`);
      assert.equal(existsSync(stage), false, `${platform}: staging directory removed on exit`);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
}

test("Windows displays no TMPDIR template", () => {
  assert.doesNotMatch(displayedCommand("Windows"), /TMPDIR/);
});
