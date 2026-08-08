import { test, expect } from '@playwright/test';

const PASSWORD = 'STYX-TEST-ONLY-app-identity-password';
const LEGACY_KEY = 'styxchat:styx:identity';

async function createIdentity(page, alias) {
  await page.goto('/');
  await page.getByLabel('Alias pubblico').fill(alias);
  await page.getByLabel('Password locale').fill(PASSWORD);
  await page.getByRole('button', { name: 'Crea identità' }).click();
  await expect(page.getByLabel('Password locale')).toBeHidden({ timeout: 90_000 });
}

async function readIdentityShadow(page) {
  return page.evaluate(async () => {
    const legacy = localStorage.getItem('styxchat:styx:identity');
    const persisted = await new Promise((resolve, reject) => {
      const request = indexedDB.open('styx-vault-default');
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction(['identity', 'migrations'], 'readonly');
        const record = tx.objectStore('identity').get('self');
        const marker = tx.objectStore('migrations').get('identity');
        tx.oncomplete = () => {
          resolve({ record: record.result, marker: marker.result });
          db.close();
        };
        tx.onerror = () => reject(tx.error);
      };
    });
    return { legacy, persisted, serialized: JSON.stringify(persisted) };
  });
}

async function lock(page) {
  await page.getByLabel('Impostazioni').click();
  await page.getByRole('button', { name: 'Blocca' }).click();
  await expect(page.getByLabel('Password locale')).toBeVisible();
}

async function deleteProductVault(page) {
  await page.evaluate(() => new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase('styx-vault-default');
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('product vault deletion blocked'));
  }));
}

test('the PWA shadow-migrates the exact encrypted identity and leaves legacy bytes authoritative', async ({ page }) => {
  await createIdentity(page, 'identity-shadow');
  const first = await readIdentityShadow(page);
  const envelope = JSON.parse(first.legacy);

  expect(envelope).toMatchObject({ v: 1, iterations: 210000 });
  expect(first.persisted.record).toMatchObject({ ct: 'json', rv: 1 });
  expect(first.persisted.marker).toMatchObject({
    version: 1, namespace: 'identity', state: 'verified',
    counts: { source: 1, written: 1 },
  });
  expect(first.serialized).not.toContain(envelope.salt);
  expect(first.serialized).not.toContain(envelope.iv);
  expect(first.serialized).not.toContain(envelope.ct);

  await lock(page);
  await page.getByLabel('Password locale').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sblocca' }).click();
  await expect(page.getByLabel('Password locale')).toBeHidden({ timeout: 90_000 });
  const reopened = await readIdentityShadow(page);
  expect(reopened.legacy).toBe(first.legacy);
  expect(reopened.persisted.record.rv).toBe(1);
  expect(reopened.persisted.marker.state).toBe('verified');
});

test('a persisted pending invite blocks identity writes but transport still starts on legacy fallback', async ({ page }) => {
  await createIdentity(page, 'pairing-gate');
  await page.getByRole('button', { name: 'Nuovo contatto' }).click();
  await expect(page.getByTestId('my-invite')).not.toHaveValue('');
  const legacyBefore = await page.evaluate((key) => localStorage.getItem(key), LEGACY_KEY);
  await page.getByRole('dialog').getByLabel('Chiudi').click();

  await lock(page);
  await deleteProductVault(page);
  await page.getByLabel('Password locale').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sblocca' }).click();
  // Reaching the contact list proves the transport start followed safe fallback.
  await expect(page.getByRole('button', { name: 'Nuovo contatto' })).toBeVisible({ timeout: 90_000 });

  const evidence = await readIdentityShadow(page);
  expect(evidence.persisted.record).toBeUndefined();
  expect(evidence.persisted.marker).toBeUndefined();
  expect(evidence.legacy).toBe(legacyBefore);
});

test('a non-default profile neither reads the default identity nor opens the product vault', async ({ page }) => {
  await page.addInitScript((key) => {
    localStorage.setItem(key, 'default-profile-sentinel');
  }, LEGACY_KEY);
  await page.goto('/?ns=peer-identity-test');
  await page.getByLabel('Alias pubblico').fill('peer-identity');
  await page.getByLabel('Password locale').fill(PASSWORD);
  await page.getByRole('button', { name: 'Crea identità' }).click();
  await expect(page.getByLabel('Password locale')).toBeHidden({ timeout: 90_000 });

  const evidence = await page.evaluate(async (key) => ({
    names: (await indexedDB.databases()).map(({ name }) => name),
    sentinel: localStorage.getItem(key),
  }), LEGACY_KEY);
  expect(evidence.names).not.toContain('styx-vault-default');
  expect(evidence.sentinel).toBe('default-profile-sentinel');
});
