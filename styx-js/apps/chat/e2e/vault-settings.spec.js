import { test, expect } from '@playwright/test';

const PASSWORD = 'STYX-TEST-ONLY-app-settings-password';

test('stage-enabled app creates the fixed vault, migrates exact legacy settings, and preserves legacy', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('styx-theme', 'dark');
    localStorage.setItem('styx-install-dismissed', '1');
    localStorage.setItem('styx-unrelated-sentinel', 'must-remain');
  });
  await page.goto('/');
  await page.getByLabel('Alias pubblico').fill('vault-test');
  await page.getByLabel('Password locale').fill(PASSWORD);
  await page.getByRole('button', { name: 'Crea identità' }).click();
  await expect(page.getByLabel('Password locale')).toBeHidden({ timeout: 90_000 });

  const evidence = await page.evaluate(async () => {
    const names = (await indexedDB.databases()).map(({ name }) => name);
    const persisted = await new Promise((resolve, reject) => {
      const request = indexedDB.open('styx-vault-default');
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction(['settings', 'migrations'], 'readonly');
        const record = tx.objectStore('settings').get('preferences');
        const marker = tx.objectStore('migrations').get('settings');
        tx.oncomplete = () => {
          const value = { record: record.result, marker: marker.result };
          db.close();
          resolve(value);
        };
        tx.onerror = () => reject(tx.error);
      };
    });
    return {
      names,
      persisted,
      legacy: {
        theme: localStorage.getItem('styx-theme'),
        dismissed: localStorage.getItem('styx-install-dismissed'),
        sentinel: localStorage.getItem('styx-unrelated-sentinel'),
      },
      serialized: JSON.stringify(persisted),
    };
  });

  expect(evidence.names).toContain('styx-vault-default');
  expect(evidence.persisted.record).toMatchObject({ ct: 'json', rv: 1 });
  expect(evidence.persisted.marker).toMatchObject({ namespace: 'settings', state: 'verified' });
  expect(evidence.legacy).toEqual({ theme: 'dark', dismissed: '1', sentinel: 'must-remain' });
  expect(evidence.serialized).not.toContain('dark');
  expect(evidence.serialized).not.toContain('installHintDismissed');
});

test('a non-empty peer profile remains legacy-only and never opens the product database', async ({ page }) => {
  await page.goto('/?ns=peer-settings-test');
  await page.getByLabel('Alias pubblico').fill('peer-test');
  await page.getByLabel('Password locale').fill(PASSWORD);
  await page.getByRole('button', { name: 'Crea identità' }).click();
  await expect(page.getByLabel('Password locale')).toBeHidden({ timeout: 90_000 });
  const names = await page.evaluate(async () => (await indexedDB.databases()).map(({ name }) => name));
  expect(names).not.toContain('styx-vault-default');
});

test('real worker dual-writes theme and install-hint dismissal after unlock', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'userAgent', {
      configurable: true,
      value: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    });
  });
  await page.goto('/');
  await page.getByLabel('Alias pubblico').fill('vault-settings-actions');
  await page.getByLabel('Password locale').fill(PASSWORD);
  await page.getByRole('button', { name: 'Crea identità' }).click();
  await expect(page.getByLabel('Password locale')).toBeHidden({ timeout: 90_000 });

  await page.getByRole('button', { name: 'Cambia tema' }).click();
  await expect.poll(() => page.evaluate(() => localStorage.getItem('styx-theme')))
    .toBe('dark');
  await page.getByRole('button', { name: 'Chiudi' }).last().click();
  await expect.poll(() => page.evaluate(() => localStorage.getItem('styx-install-dismissed')))
    .toBe('1');
});
