import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import importPlugin from "eslint-plugin-import";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default [
  {
    ignores: ["dist/**", "node_modules/**"],
  },

  js.configs.recommended,

  ...tseslint.configs.recommended,

  {
    files: ["**/*.{js,jsx,ts,tsx}"],

    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",

      globals: {
        ...globals.browser,
        ...globals.node,
      },

      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },

    plugins: {
      import: importPlugin,
      react,
      "react-hooks": reactHooks,
    },

    rules: {
      ...reactHooks.configs.recommended.rules,

      "react-hooks/set-state-in-effect": "off",

      "react/jsx-uses-react": "off",
      "react/jsx-uses-vars": "error",
      "react/react-in-jsx-scope": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
        },
      ],

      "import/order": [
        "error",
        {
          groups: ["builtin", "external", "internal", ["parent", "sibling", "index"]],

          "newlines-between": "always",

          alphabetize: {
            order: "asc",
            caseInsensitive: true,
          },
        },
      ],

      "padding-line-between-statements": [
        "error",
        {
          blankLine: "always",
          prev: "const",
          next: "const",
        },
        {
          blankLine: "always",
          prev: "let",
          next: "let",
        },
        {
          blankLine: "always",
          prev: "var",
          next: "var",
        },
        {
          blankLine: "always",
          prev: "*",
          next: "return",
        },
      ],
    },

    settings: {
      react: {
        version: "detect",
      },
    },
  },

  prettier,
];
