import { expect, test } from '@playwright/test';

// Needs the admin login of the running app: PHISHGUARD_USER (default "admin") and
// PHISHGUARD_PASSWORD. CI generates both; locally, skipped unless you set them.
const user = process.env.PHISHGUARD_USER ?? 'admin';
const password = process.env.PHISHGUARD_PASSWORD;

test.skip(!password, 'set PHISHGUARD_PASSWORD to the admin password of the running app');

test.beforeEach(async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('User name').fill(user);
  await page.getByLabel('Password').fill(password!);
  await page.getByRole('button', { name: 'Log in' }).click();
  await expect(page).not.toHaveURL(/\/login/);
});

test('the dashboard loads after login without console errors', async ({ page }) => {
  const problems: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') problems.push(m.text()); });
  await page.goto('/');
  await expect(page.locator('#root')).not.toBeEmpty();
  expect(problems).toEqual([]);
});

test('Quick Scan offers the screenshot upload on the SMS tab only', async ({ page }) => {
  await page.goto('/scan');
  const screenshot = page.getByLabel('…or upload a screenshot of the SMS');
  const eml = page.getByLabel('…or upload an .eml file');
  await expect(eml).toBeVisible();
  await expect(screenshot).toBeHidden();
  await page.locator('label[for=kind-sms]').click();
  await expect(screenshot).toBeVisible();
  await expect(eml).toBeHidden();
  await expect(page.getByLabel('Sender (optional)')).toBeVisible();
});
