import { createRequire } from "node:module";

// Load through the package's CommonJS entry so its minimatch import resolves
// to minimatch's CJS build: the pinned minimatch 11 ESM build has no default
// export, which the ESM entry's `import minimatch from "minimatch"` rejects.
const { FlatCompat } = createRequire(import.meta.url)("@eslint/eslintrc");

const compat = new FlatCompat({ baseDirectory: import.meta.dirname });

const eslintConfig = [
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    ignores: [
      "node_modules/**",
      ".next/**",
      ".vercel/**",
      "out/**",
      "build/**",
      "next-env.d.ts",
      "tests/**",
    ],
  },
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
];

export default eslintConfig;
