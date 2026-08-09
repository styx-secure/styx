// Parse/config-presence baseline for `npm run lint` (Issue #139 amendment).
// ESLint 9 was declared without a flat config, so the command could not run.
// This covers every source file, permits no inline suppression, and enforces
// only rules verified clean at the approved base. It is not a recommended-rule
// lint profile; existing rule debt outside Issue #139 remains follow-up work.
export default [
  {
    files: ['src/**/*.js'],
    linterOptions: {
      noInlineConfig: true,
      reportUnusedDisableDirectives: 'warn',
    },
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
    rules: {
      'no-unreachable': 'error',
      'no-dupe-keys': 'error',
      'no-dupe-class-members': 'error',
      'no-unsafe-finally': 'error',
      'no-fallthrough': 'error',
      'no-self-assign': 'error',
      'no-constant-condition': 'error',
    },
  },
];
