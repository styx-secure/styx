// test/error-boundary.test.js — the whole UI is wrapped in a React error
// boundary, so an exception thrown while rendering shows a recoverable error
// screen instead of an empty page. (The app's JSX is not transformed under
// jest; these checks read the sources, like no-stub-ui.test.js.)
import { describe, test, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

describe('render error boundary', () => {
  test('ErrorBoundary is a class component implementing both error hooks', () => {
    const src = read('../src/components/ErrorBoundary.jsx');
    expect(src).toMatch(/class ErrorBoundary extends Component/);
    expect(src).toMatch(/static getDerivedStateFromError\(/);
    expect(src).toMatch(/componentDidCatch\(/);
    expect(src).toMatch(/location\.reload\(\)/);
  });

  test('the error screen does not print the error message (it may carry chat content)', () => {
    const src = read('../src/components/ErrorBoundary.jsx');
    expect(src).not.toMatch(/error\.message|\.stack/);
  });

  test('main.jsx renders App inside ErrorBoundary', () => {
    const src = read('../src/main.jsx');
    expect(src).toMatch(/import ErrorBoundary from '\.\/components\/ErrorBoundary\.jsx'/);
    expect(src).toMatch(/<ErrorBoundary>\s*<App \/>\s*<\/ErrorBoundary>/);
  });
});
