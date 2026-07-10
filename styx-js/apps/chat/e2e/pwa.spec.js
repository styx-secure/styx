import { test, expect } from '@playwright/test';

// The app must register a service worker, precache its shell, and still render
// the unlock screen after the network is cut and the page reloaded.
test('registers a service worker and loads offline', async ({ page, context }) => {
  await page.goto('/');

  // Wait until the service worker controls the page (precache done).
  await page.waitForFunction(async () => {
    if (!('serviceWorker' in navigator)) return false;
    const reg = await navigator.serviceWorker.getRegistration();
    return !!(reg && (reg.active || reg.installing || reg.waiting));
  }, null, { timeout: 60_000 });
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null, null, { timeout: 60_000 });

  // Cut the network and reload: the shell must still come from cache.
  await context.setOffline(true);
  await page.reload();

  // The unlock screen (password field) is the app shell entry point.
  await expect(page.locator('input[type="password"]')).toBeVisible({ timeout: 30_000 });

  await context.setOffline(false);
});
