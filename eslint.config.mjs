import { dirname } from "path";
import { fileURLToPath } from "url";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({ baseDirectory: __dirname });

const config = [
  ...compat.extends("next/core-web-vitals", "next/typescript", "prettier"),
  {
    ignores: [
      "legacy/**",
      ".next/**",
      "node_modules/**",
      "prisma/generated/**",
      "next-env.d.ts",
      "postcss.config.mjs",
    ],
  },
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/consistent-type-imports": [
        "warn",
        { prefer: "type-imports", fixStyle: "separate-type-imports" },
      ],
      "no-console": ["warn", { allow: ["warn", "error"] }],
      "react/jsx-curly-brace-presence": ["warn", { props: "never", children: "never" }],
      eqeqeq: ["error", "always"],
    },
  },
];

export default config;
