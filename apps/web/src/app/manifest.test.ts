import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import manifest from "./manifest.ts";

const publicDir = join(import.meta.dirname, "..", "..", "public");
const nonEmpty = (value: unknown) =>
  typeof value === "string" && value.trim().length > 0;

test("manifest names the app and says where it starts", () => {
  const m = manifest();
  assert.ok(nonEmpty(m.name), "name");
  assert.ok(nonEmpty(m.short_name), "short_name");
  assert.ok(nonEmpty(m.description), "description");
  assert.ok(nonEmpty(m.start_url), "start_url");
  assert.ok(m.start_url!.startsWith("/"), "start_url is a root-relative path");
  assert.ok(m.scope === undefined || m.start_url!.startsWith(m.scope));
});

test("manifest colors are valid hex", () => {
  const m = manifest();
  for (const color of [m.background_color, m.theme_color]) {
    assert.match(color ?? "", /^#[0-9a-f]{6}$/i);
  }
});

test("manifest icons are valid and point at real files", () => {
  const icons = manifest().icons ?? [];
  assert.ok(icons.length > 0, "at least one icon");
  for (const icon of icons) {
    assert.ok(nonEmpty(icon.src) && icon.src.startsWith("/"), "icon src");
    assert.ok(
      icon.sizes === "any" ||
        /^\d+x\d+( \d+x\d+)*$/.test(icon.sizes ?? ""),
      `icon sizes: ${icon.sizes}`,
    );
    assert.match(icon.type ?? "", /^image\/[a-z0-9.+-]+$/);
    assert.ok(existsSync(join(publicDir, icon.src)), `${icon.src} exists`);
  }
});
