import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { Children, isValidElement, type ReactElement, type ReactNode } from "react";
import { QuickStart } from "./QuickStart";
import {
  PUBLIC_RELEASE_SOURCE_COMMIT,
  PUBLIC_RELEASE_TAG,
  PUBLIC_RELEASE_UNIX_INSTALLER_SHA256,
  PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256,
} from "@/lib/public-release";

const repoRoot = path.resolve(__dirname, "../../../../..");
const sourceBase =
  `https://raw.githubusercontent.com/ashlrai/phantom-secrets/${PUBLIC_RELEASE_SOURCE_COMMIT}/scripts`;
const assetBase =
  `https://github.com/ashlrai/phantom-secrets/releases/download/${PUBLIC_RELEASE_TAG}`;

const platforms = [
  {
    name: "macOS",
    installer: "install.sh",
    digest: PUBLIC_RELEASE_UNIX_INSTALLER_SHA256,
    checksum: "shasum -a 256 -c -",
  },
  {
    name: "Windows",
    installer: "install.ps1",
    digest: PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256,
    checksum: "Get-FileHash -Algorithm SHA256",
  },
  {
    name: "Linux",
    installer: "install.sh",
    digest: PUBLIC_RELEASE_UNIX_INSTALLER_SHA256,
    checksum: "sha256sum -c -",
  },
] as const;

interface InspectedProps {
  children?: ReactNode;
  text?: string;
  href?: string;
  className?: string;
  onClick?: () => void;
}

type InspectedElement = ReactElement<InspectedProps>;

function findElements(
  element: ReactNode,
  predicate: (element: InspectedElement) => boolean,
): InspectedElement[] {
  if (!isValidElement<InspectedProps>(element)) return [];
  return [
    ...(predicate(element) ? [element] : []),
    ...Children.toArray(element.props.children).flatMap((child) =>
      findElements(child, predicate)),
  ];
}

function textContent(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join("");
  if (isValidElement<InspectedProps>(node)) return textContent(node.props.children);
  return "";
}

function displayedInstall(platform: string) {
  const selectors = findElements(QuickStart(), (element) => element.type === "button");
  const button = selectors.find((element) => element.props.children === platform);
  assert.ok(button, `${platform}: selector button is displayed`);
  const onClick = button.props.onClick;
  assert.ok(onClick, `${platform}: selector button is clickable`);
  onClick();

  const cards = findElements(QuickStart(), (element) => element.type === "article");
  assert.equal(cards.length, 1, `${platform}: one install card is displayed`);
  const commands = findElements(cards[0], (element) => typeof element.props.text === "string");
  assert.equal(commands.length, 1, `${platform}: one install command is displayed`);
  const links = findElements(
    cards[0],
    (element) => element.type === "a" && typeof element.props.href === "string",
  ).map((element) => element.props.href as string);
  const sources = findElements(
    cards[0],
    (element) => element.props.className === "platform-install-card__source",
  );
  assert.equal(sources.length, 1, `${platform}: one installer source link is displayed`);
  return {
    command: commands[0].props.text as string,
    source: sources[0].props.href as string,
    links,
  };
}

function ordered(command: string, fragments: string[], platform: string) {
  let position = 0;
  for (const fragment of fragments) {
    const index = command.indexOf(fragment, position);
    assert.notEqual(index, -1, `${platform}: missing or out of order: ${fragment}`);
    position = index + fragment.length;
  }
}

test("the ordering helper rejects missing and out-of-order fragments", () => {
  ordered("alpha\nbeta\ngamma", ["alpha", "beta", "gamma"], "fixture");
  assert.throws(
    () => ordered("alpha\nbeta\ngamma", ["alpha", "gamma", "beta"], "fixture"),
    /missing or out of order/,
  );
  assert.throws(
    () => ordered("alpha\nbeta\ngamma", ["delta"], "fixture"),
    /missing or out of order/,
  );
});

test("displayed install commands download the existing public installer at the pinned source commit", () => {
  for (const platform of platforms) {
    const { command, source, links } = displayedInstall(platform.name);
    const url = `${sourceBase}/${platform.installer}`;

    // The "View exact installer source" link and the command's download agree.
    assert.equal(source, url, `${platform.name}: installer source link`);
    assert.ok(command.includes(url), `${platform.name}: command downloads the source link target`);
    // Both point at a real installer path in this repository, pinned to the
    // immutable release-source commit rather than a moving branch or tag.
    assert.ok(url.includes(`/${PUBLIC_RELEASE_SOURCE_COMMIT}/scripts/`), platform.name);
    for (const file of [
      path.join("scripts", platform.installer),
      path.join("apps", "web", "public", platform.installer),
    ]) {
      assert.ok(existsSync(path.join(repoRoot, file)), `${platform.name}: ${file} exists`);
    }

    // The digest embedded in the displayed command is the digest of the exact
    // public installer bytes the pinned commit serves (fixtures are bound to
    // the release blob OIDs in tests/public-claims.test.cjs).
    const fixture = path.join(
      repoRoot,
      "apps/web/tests/fixtures/release-v0.7.9",
      platform.installer,
    );
    const pinned = createHash("sha256").update(readFileSync(fixture)).digest("hex");
    assert.equal(pinned, platform.digest, `${platform.name}: pinned installer digest`);
    assert.ok(
      command.includes(platform.digest),
      `${platform.name}: displayed command verifies the pinned digest`,
    );

    // Release download links stay on the immutable release assets as well.
    for (const href of links) {
      assert.ok(
        href === url || href.startsWith(`${assetBase}/`),
        `${platform.name}: unexpected download link ${href}`,
      );
    }
    // The command and links never resolve a mutable or retired endpoint.
    assert.doesNotMatch(
      `${command}\n${links.join("\n")}`,
      /releases\/latest|api\.github\.com|phm\.dev/i,
      platform.name,
    );
  }
});

test("displayed install commands stage the installer temporarily before executing it", () => {
  for (const platform of platforms) {
    const { command } = displayedInstall(platform.name);
    if (platform.installer === "install.sh") {
      // A temporary staging directory under TMPDIR (or /tmp) holds the
      // downloaded installer; the staged file keeps the installer's name.
      assert.ok(
        command.includes('phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'),
        `${platform.name}: TMPDIR staging template`,
      );
      assert.ok(
        command.includes(`phantom_installer="$phantom_stage/${platform.installer}"`),
        `${platform.name}: staged installer path`,
      );
      assert.ok(
        command.includes(
          `trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`,
        ),
        `${platform.name}: exit-trap cleanup`,
      );
      ordered(
        command,
        ["mktemp -d", "curl --fail", platform.checksum, `bash "$phantom_installer"`],
        platform.name,
      );
    } else {
      // Windows stages a unique temporary installer file under $env:TEMP and
      // removes it in a finally block.
      assert.ok(
        command.includes(`Join-Path $env:TEMP ('phantom-install-${PUBLIC_RELEASE_TAG}-{0}.ps1'`),
        `${platform.name}: temporary installer file`,
      );
      assert.match(command, /Remove-Item -LiteralPath \$Installer -Force/, platform.name);
      ordered(
        command,
        ["Invoke-WebRequest", platform.checksum, "& $Installer"],
        platform.name,
      );
    }
    // Download, verify against the pinned digest, then execute: never before.
    const download = command.indexOf(platform.installer === "install.sh" ? "curl --fail" : "Invoke-WebRequest");
    const verify = command.indexOf(platform.checksum);
    const execute = command.indexOf(platform.installer === "install.sh" ? `bash "$phantom_installer"` : "& $Installer");
    assert.ok(
      download >= 0 && download < verify && verify < execute,
      `${platform.name}: download, verify, then execute`,
    );
  }
});

test("the install note and public docs describe the same temporary staging the commands display", () => {
  const { command: unix } = displayedInstall("macOS");
  const { command: windows } = displayedInstall("Windows");

  const notes = findElements(
    QuickStart(),
    (element) => element.props.className === "platform-install-note",
  );
  assert.equal(notes.length, 1, "one install note is displayed");
  const note = textContent(notes[0]);
  for (const fragment of [
    "TMPDIR",
    "/tmp",
    "staging directory",
    "exit trap",
    "Windows uses a temporary installer file instead",
    "not the install directory",
  ]) {
    assert.ok(note.includes(fragment), `install note: ${fragment}`);
  }

  // The public docs that describe these commands document the same staging.
  for (const file of ["docs/quickstart-reading-guide.md", "docs/getting-started.md"]) {
    const doc = readFileSync(path.join(repoRoot, file), "utf8");
    for (const fragment of ["phantom-install", "TMPDIR", "/tmp"]) {
      assert.ok(doc.includes(fragment), `${file}: ${fragment}`);
    }
  }
  const guide = readFileSync(path.join(repoRoot, "docs/quickstart-reading-guide.md"), "utf8");
  assert.ok(guide.includes("$env:TEMP"), "quickstart-reading-guide.md: Windows staging");
  assert.ok(guide.includes("exit trap"), "quickstart-reading-guide.md: Unix cleanup");

  // The documented staging matches what the commands actually contain.
  assert.ok(unix.includes("${TMPDIR:-/tmp}"), "macOS: documented TMPDIR fallback is displayed");
  assert.ok(unix.includes("trap "), "macOS: documented exit trap is displayed");
  assert.ok(windows.includes("$env:TEMP"), "Windows: documented $env:TEMP staging is displayed");
});

test("cleanup review covers each displayed platform's staging and cleanup", () => {
  const review = readFileSync(path.join(repoRoot, "docs/quickstart-temp-cleanup-review.md"), "utf8");
  assert.ok(review.includes("../apps/web/src/components/landing/QuickStart.tsx"));
  for (const { name, installer, checksum } of platforms) {
    const section = review.split(`## ${name}\n`)[1]?.split("\n## ")[0];
    assert.ok(section, `${name}: review section`);
    const { command } = displayedInstall(name);
    const fragments = installer === "install.sh"
      ? ["mktemp -d", "TMPDIR", "/tmp", "install.sh", "EXIT", "rm -f", "rmdir", checksum]
      : ["$env:TEMP", "Invoke-WebRequest", "Get-FileHash", "finally", "Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue"];
    for (const fragment of fragments) {
      assert.ok(command.includes(fragment), `${name}: command contains ${fragment}`);
      assert.ok(section.includes(fragment), `${name}: review describes ${fragment}`);
    }
  }
  assert.match(review, /Cleanup is best effort/);
  assert.ok(review.includes("installer-staging.md"));
});
