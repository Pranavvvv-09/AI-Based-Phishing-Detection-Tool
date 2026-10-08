import { expect, test } from '@playwright/test';

// Start the app first:  python -m phishguard.web   (or set PHISHGUARD_URL)
test('login page loads with the security headers and no console errors', async ({ page }) => {
  const problems: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') problems.push(m.text()); });
  const response = await page.goto('/login');
  expect(response?.status()).toBe(200);
  expect(response?.headers()['content-security-policy']).toContain("script-src 'self'");
  await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible();
  await expect(page.getByLabel('User name')).toBeVisible();
  expect(problems).toEqual([]);
});

test('the dashboard asks for a login first', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveURL(/\/login\?next=\/$/);
});
