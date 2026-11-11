const assert = require("assert");

function nullableRef(name) {
  return { anyOf: [{ $ref: `#/$defs/${name}` }, { type: "null" }] };
}

function variant(action, fields) {
  return {
    type: "object",
    required: ["action", "cwd"],
    properties: {
      action: { type: "string", const: action },
      cwd: { $ref: "#/$defs/RelativeCwd" },
      ...fields,
    },
    additionalProperties: false,
  };
}

function validSchema() {
  return {
    type: "object",
    required: ["action"],
    properties: {
      action: { $ref: "#/$defs/EngineeringAction", description: "closed action" },
      phase: {
        $ref: "#/$defs/EngineeringDoPhase",
        default: "propose",
        description: "closed phase",
      },
    },
    additionalProperties: false,
    $defs: {
      EngineeringAction: {
        oneOf: [
          variant("cargo_check", { package: nullableRef("PackageName") }),
          variant("cargo_test", {
            filter: nullableRef("TestFilter"),
            package: nullableRef("PackageName"),
          }),
          variant("cargo_clippy", { package: nullableRef("PackageName") }),
          variant("cargo_fmt_check", {}),
        ],
      },
      EngineeringDoPhase: {
        oneOf: [
          { type: "string", const: "propose" },
          { type: "string", const: "execute" },
        ],
      },
      PackageName: {
        type: "string",
        minLength: 1,
        maxLength: 128,
        pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
      },
      RelativeCwd: { type: "string", minLength: 1, maxLength: 512 },
      TestFilter: {
        type: "string",
        minLength: 1,
        maxLength: 128,
        pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
      },
    },
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

(async () => {
  const { validatePhantomDoSchema } = await import(
    "../../scripts/release/mcp-schema-contract.mjs"
  );
  assert.deepStrictEqual(validatePhantomDoSchema(validSchema()), { actions: 4 });

  const reversed = validSchema();
  reversed.$defs.EngineeringAction.oneOf[0].properties.package.anyOf.reverse();
  validatePhantomDoSchema(reversed);

  const mutations = [
    (schema) => {
      schema.$defs.EngineeringAction.oneOf[0].properties.package.anyOf = [
        { type: "null" },
        { type: "number" },
      ];
    },
    (schema) => {
      schema.$defs.EngineeringAction.oneOf[0].properties.package.anyOf = [
        { type: "null" },
        { type: "string" },
      ];
    },
    (schema) => {
      schema.$defs.EngineeringAction.oneOf[0].properties.package.anyOf.push({ type: "null" });
    },
    (schema) => {
      schema.$defs.EngineeringAction.oneOf[0].properties.package.anyOf[0].$ref =
        "#/$defs/TestFilter";
    },
    (schema) => {
      schema.$defs.EngineeringAction.oneOf[1].properties.filter.anyOf[0].$ref =
        "https://example.invalid/schema";
    },
    (schema) => {
      schema.$defs.PackageName.pattern = "^.*$";
    },
    (schema) => {
      schema.$defs.TestFilter.maxLength = 1024;
    },
    (schema) => {
      schema.$defs.EngineeringAction.oneOf[0].properties.package.extra = true;
    },
  ];
  for (const mutate of mutations) {
    const schema = clone(validSchema());
    mutate(schema);
    assert.throws(() => validatePhantomDoSchema(schema));
  }

  console.log("MCP closed schema validator rejects open and mismatched nullable selectors");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
