const PACKAGE_PATTERN = "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$";
const FILTER_PATTERN = "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$";

function sameMembers(actual, expected) {
  return (
    Array.isArray(actual) &&
    actual.length === expected.length &&
    [...actual].sort().every((value, index) => value === [...expected].sort()[index])
  );
}

function own(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function resolveExactLocalRef(schema, property, expectedDefinition, label) {
  const expectedRef = `#/$defs/${expectedDefinition}`;
  if (
    !property ||
    typeof property !== "object" ||
    !sameMembers(Object.keys(property), ["$ref"]) ||
    property.$ref !== expectedRef ||
    !schema.$defs ||
    !own(schema.$defs, expectedDefinition)
  ) {
    throw new Error(`${label} must reference exactly ${expectedRef}`);
  }
  return schema.$defs[expectedDefinition];
}

function validateStringDefinition(definition, expectedPattern, label) {
  if (
    !definition ||
    definition.type !== "string" ||
    definition.minLength !== 1 ||
    definition.maxLength !== 128 ||
    definition.pattern !== expectedPattern
  ) {
    throw new Error(`${label} string constraints are missing or incorrect`);
  }
}

function validateNullableSelector(schema, property, expectedDefinition, expectedPattern, label) {
  if (
    !property ||
    typeof property !== "object" ||
    !sameMembers(Object.keys(property), ["anyOf"]) ||
    !Array.isArray(property.anyOf) ||
    property.anyOf.length !== 2
  ) {
    throw new Error(`${label} must be exactly one constrained string reference plus null`);
  }
  const nullBranches = property.anyOf.filter(
    (entry) =>
      entry &&
      typeof entry === "object" &&
      sameMembers(Object.keys(entry), ["type"]) &&
      entry.type === "null"
  );
  const refBranches = property.anyOf.filter(
    (entry) => entry && typeof entry === "object" && own(entry, "$ref")
  );
  if (nullBranches.length !== 1 || refBranches.length !== 1) {
    throw new Error(`${label} must be exactly one constrained string reference plus null`);
  }
  const definition = resolveExactLocalRef(
    schema,
    refBranches[0],
    expectedDefinition,
    label
  );
  validateStringDefinition(definition, expectedPattern, expectedDefinition);
}

export function validatePhantomDoSchema(schema) {
  if (
    !schema ||
    schema.type !== "object" ||
    schema.additionalProperties !== false ||
    !sameMembers(schema.required, ["action"]) ||
    !schema.properties?.action ||
    !schema.properties?.phase ||
    !sameMembers(Object.keys(schema.properties), ["action", "phase"])
  ) {
    throw new Error("phantom_do input schema is not the expected closed action object");
  }
  if (
    !sameMembers(Object.keys(schema.$defs || {}), [
      "EngineeringAction",
      "EngineeringDoPhase",
      "PackageName",
      "RelativeCwd",
      "TestFilter",
    ])
  ) {
    throw new Error("phantom_do schema has missing or unexpected definitions");
  }

  const phaseProperty = schema.properties.phase;
  const phase = resolveExactLocalRef(
    schema,
    { $ref: phaseProperty.$ref },
    "EngineeringDoPhase",
    "phantom_do phase"
  );
  if (
    !sameMembers(Object.keys(phaseProperty), ["$ref", "default", "description"]) ||
    phaseProperty.default !== "propose" ||
    !Array.isArray(phase.oneOf) ||
    phase.oneOf.length !== 2 ||
    !sameMembers(phase.oneOf.map((entry) => entry.const), ["propose", "execute"]) ||
    phase.oneOf.some((entry) => entry.type !== "string")
  ) {
    throw new Error("phantom_do phase schema is not the exact propose/execute enum");
  }

  const expectedActions = new Map([
    ["cargo_check", ["action", "cwd", "package"]],
    ["cargo_test", ["action", "cwd", "filter", "package"]],
    ["cargo_clippy", ["action", "cwd", "package"]],
    ["cargo_fmt_check", ["action", "cwd"]],
  ]);
  if (!sameMembers(Object.keys(schema.properties.action), ["$ref", "description"])) {
    throw new Error("phantom_do action property must be one closed local reference");
  }
  const actionDefinition = resolveExactLocalRef(
    schema,
    { $ref: schema.properties.action.$ref },
    "EngineeringAction",
    "phantom_do action"
  );
  const variants = actionDefinition.oneOf;
  if (!Array.isArray(variants) || variants.length !== expectedActions.size) {
    throw new Error("phantom_do action schema must contain exactly four variants");
  }
  const seenActions = new Set();
  for (const variant of variants) {
    const actionName = variant?.properties?.action?.const;
    const expectedProperties = expectedActions.get(actionName);
    if (
      !expectedProperties ||
      seenActions.has(actionName) ||
      variant.type !== "object" ||
      variant.additionalProperties !== false ||
      !sameMembers(variant.required, ["action", "cwd"]) ||
      !sameMembers(Object.keys(variant.properties || {}), expectedProperties) ||
      variant.properties.action.type !== "string"
    ) {
      throw new Error(`phantom_do has an open or unexpected action variant: ${actionName}`);
    }
    seenActions.add(actionName);
    const cwd = resolveExactLocalRef(
      schema,
      variant.properties.cwd,
      "RelativeCwd",
      `${actionName} cwd`
    );
    if (cwd?.type !== "string" || cwd.minLength !== 1 || cwd.maxLength !== 512) {
      throw new Error(`${actionName} cwd bounds are missing or incorrect`);
    }
    if (own(variant.properties, "package")) {
      validateNullableSelector(
        schema,
        variant.properties.package,
        "PackageName",
        PACKAGE_PATTERN,
        `${actionName} package`
      );
    }
    if (own(variant.properties, "filter")) {
      validateNullableSelector(
        schema,
        variant.properties.filter,
        "TestFilter",
        FILTER_PATTERN,
        `${actionName} filter`
      );
    }
  }
  if (seenActions.size !== expectedActions.size) {
    throw new Error("phantom_do action variants are incomplete");
  }
  return { actions: seenActions.size };
}

export const expectedSelectorPatterns = Object.freeze({
  PackageName: PACKAGE_PATTERN,
  TestFilter: FILTER_PATTERN,
});
