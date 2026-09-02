export default {
  extends: ["stylelint-config-standard-scss"],

  rules: {
    "no-duplicate-selectors": true,
    "selector-class-pattern": "^[a-z][a-zA-Z0-9]*$",
    "keyframes-name-pattern": "^[a-z][a-zA-Z0-9]*$",
  },
};
