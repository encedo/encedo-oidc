// ESLint flat config (ESLint 9+). Replaces the old .eslintrc.json.
// Same rules as before: Node ESM, unused vars are errors (args prefixed with _
// are ignored), undefined references are errors, console is allowed.
import globals from 'globals';

export default [
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      // ignoreRestSiblings: allow `const { secret, ...safe } = obj` -- a common
      // way to omit a field (e.g. client_secret) from a response.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', ignoreRestSiblings: true }],
      'no-undef': 'error',
      'no-console': 'off',
    },
  },
];
