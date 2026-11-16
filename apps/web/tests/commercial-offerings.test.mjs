import assert from "node:assert/strict";
import test from "node:test";
import { COMMERCIAL_OFFERINGS, findCommercialOffering } from "../src/lib/commercial-offerings.ts";

test("a known id returns that exact offering", () => {
  for (const offering of COMMERCIAL_OFFERINGS) {
    assert.equal(findCommercialOffering(offering.id), offering);
  }
});

test("an unknown id returns undefined and never falls back to another offering", () => {
  const unknown = [
    "nonexistent",
    "",
    " community",
    "Community",
    "enterprise ",
    "government\n",
    "community,enterprise",
    "__proto__",
    "constructor",
    "toString",
  ];
  for (const id of unknown) {
    assert.equal(findCommercialOffering(id), undefined, `id ${JSON.stringify(id)}`);
  }
});
