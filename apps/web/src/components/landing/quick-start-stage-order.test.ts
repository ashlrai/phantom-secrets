import assert from "node:assert/strict";
import test from "node:test";
import { Children, isValidElement, type ReactElement, type ReactNode } from "react";
import { QuickStart } from "./QuickStart";

type Props = { children?: ReactNode; text?: string; onClick?: () => void };

function find(node: ReactNode, predicate: (element: ReactElement<Props>) => boolean): ReactElement<Props>[] {
  if (!isValidElement<Props>(node)) return [];
  return [
    ...(predicate(node) ? [node] : []),
    ...Children.toArray(node.props.children).flatMap((child) => find(child, predicate)),
  ];
}

function assertAssignedBeforeUse(command: string, assignment: RegExp, reference: RegExp) {
  const lines = command.split("\n");
  const index = lines.findIndex((line) => assignment.test(line));
  assert.notEqual(index, -1, "staging variable must be assigned");
  assert.ok(lines.some((line) => reference.test(line)), "staging variable must be used");
  // Check the assignment's right-hand side too: self-reference is not initialization.
  const before = [...lines.slice(0, index), lines[index].replace(assignment, "")].join("\n");
  assert.doesNotMatch(before, reference, "staging variable used before assignment");
}

const unixVariables = [
  [/^\s*phantom_stage=/, /\$(?:phantom_stage\b|\{phantom_stage\})/],
  [/^\s*phantom_installer=/, /\$(?:phantom_installer\b|\{phantom_installer\})/],
] as const;
const windowsVariables = [[/^\s*\$Installer\s*=/i, /\$Installer\b/i]] as const;

for (const platform of ["macOS", "Windows", "Linux"]) {
  test(`${platform} displayed installer assigns staging variables before use`, () => {
    const button = find(QuickStart(), (element) => element.type === "button")
      .find((element) => element.props.children === platform);
    assert.ok(button?.props.onClick, `${platform} selector exists`);
    button.props.onClick();
    const cards = find(QuickStart(), (element) => element.type === "article");
    assert.equal(cards.length, 1);
    const commands = find(cards[0], (element) => typeof element.props.text === "string");
    assert.equal(commands.length, 1);
    const command = commands[0].props.text!;
    for (const [assignment, reference] of platform === "Windows" ? windowsVariables : unixVariables) {
      assertAssignedBeforeUse(command, assignment, reference);
    }
  });
}

test("ordering check rejects missing, early, and self-referential assignments", () => {
  const [assignment, reference] = unixVariables[0];
  for (const command of ['echo "$phantom_stage"', 'echo "$phantom_stage"\nphantom_stage=ok', 'phantom_stage="$phantom_stage"']) {
    assert.throws(() => assertAssignedBeforeUse(command, assignment, reference));
  }
});
