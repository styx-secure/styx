import resolve from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';

export default {
  input: 'src/fidesvox-bundle.js',
  output: {
    file: 'dist/fidesvox.min.js',
    format: 'iife',
    name: 'Styx',
    sourcemap: false,
  },
  plugins: [
    resolve({ browser: true }),
    terser(),
  ],
};
