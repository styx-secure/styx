import { test, expect } from '@playwright/test';

// Two same-origin tabs (?ns=alice / ?ns=bob) hold separate identities but
// connect over the shared-origin BroadcastChannel. They pair via a QR invite
// and exchange a message encrypted end-to-end with the real MLS engine.

async function onboard(context, ns, alias) {
  const p = await context.newPage();
  // local=1 → BroadcastChannel transport (self-contained, no relay needed).
  await p.goto(`/?ns=${ns}&local=1`, { waitUntil: 'networkidle' });
  await p.getByPlaceholder('Alias pubblico').fill(alias);
  await p.getByPlaceholder('Password locale').fill('pw123');
  await p.getByRole('button', { name: /Crea identità/ }).click();
  await p.waitForSelector('.clist-footer', { timeout: 20_000 });
  return p;
}

test('two peers pair via QR invite and exchange an MLS-encrypted message', async ({ context }) => {
  const errors = [];
  context.on('page', (pg) => pg.on('pageerror', (e) => errors.push(e.message)));

  const alice = await onboard(context, 'alice', 'Alice');
  const bob = await onboard(context, 'bob', 'Bob');

  // Bob reveals his invite; Alice accepts it.
  await bob.getByRole('button', { name: /Nuovo contatto/ }).click();
  const invite = await bob.locator('[data-testid="my-invite"]').inputValue();
  await bob.getByRole('button', { name: /Chiudi/ }).click();

  await alice.getByRole('button', { name: /Nuovo contatto/ }).click();
  await alice.getByPlaceholder('styx://…').fill(invite);
  await alice.getByRole('button', { name: /Accetta invito/ }).click();
  await alice.getByPlaceholder('Come chiamarlo').fill('Bob');
  await alice.getByRole('button', { name: /Aggiungi contatto/ }).click();

  // Bob's side raises an explicit pairing request: a valid welcome proves the scan,
  // not consent. He must accept before Alice becomes a contact.
  await expect(bob.getByRole('dialog', { name: /Richiesta di contatto/ })).toBeVisible();
  await bob.getByPlaceholder('Come chiamarlo (opzionale)').fill('Alice');
  await bob.getByRole('button', { name: /Aggiungi contatto/ }).click();

  // Both rosters populate.
  await expect(alice.locator('.crow .alias')).toHaveText(['Bob']);
  await expect(bob.locator('.crow .alias')).toHaveText(['Alice']);

  // Bob opens the conversation; Alice sends an encrypted message.
  await bob.locator('.crow').first().click();
  await bob.waitForSelector('.composer textarea');
  await alice.locator('.crow').first().click();
  await alice.waitForSelector('.composer textarea');

  const text = 'Ciao Bob, messaggio cifrato con MLS reale 🔐';
  await alice.locator('.composer textarea').fill(text);
  await alice.locator('.composer textarea').press('Enter');

  // Bob receives it decrypted.
  await expect(bob.locator('.bubble.in').first()).toContainText('MLS reale');

  // Both sides show the same safety number: no one is in the middle.
  await alice.getByTestId('safety-badge').click();
  const aliceNumber = await alice.getByTestId('safety-number').innerText();
  await bob.getByTestId('safety-badge').click();
  const bobNumber = await bob.getByTestId('safety-number').innerText();
  expect(aliceNumber.replace(/\s/g, '')).toMatch(/^\d{60}$/);
  expect(aliceNumber).toBe(bobNumber);

  expect(errors).toEqual([]);
});
