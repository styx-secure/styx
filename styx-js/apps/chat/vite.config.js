import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Self-contained SPA: no external hosts. All deps are bundled.
export default defineConfig({
  plugins: [react()],
  server: { port: 5175 },
});
