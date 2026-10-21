import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

for (const width of [320, 375, 768, 1440]) {
  test(`real analysis and accessible layout at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/');
    await expect(page.locator('#status')).toContainText('Ready to check');
    await page.getByLabel('URL to check').fill('https://example.com/' + 'a'.repeat(250));
    await page.getByRole('button', { name: 'Check URL', exact: true }).click();
    await expect(page.locator('#result')).toBeVisible();
    await expect(page.locator('#status')).toContainText('Check complete');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const findings = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(findings.violations).toEqual([]);
    if (width === 375 || width === 1440) await page.screenshot({ path: `test-results/linkguard-${width}.png`, fullPage: true });
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download this result (JSON)' }).click();
    expect((await downloadPromise).suggestedFilename()).toBe('url-analysis.json');
    await page.getByRole('button', { name: 'Clear', exact: true }).click();
    await expect(page.locator('#result')).toBeHidden();
    await expect(page.getByLabel('URL to check')).toBeFocused();
  });
}

test('API failure and retry remove stale results', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('URL to check').fill('https://example.com');
  await page.route('**/api/predict', route => route.fulfill({ status: 429, contentType: 'application/json', headers: { 'Retry-After': '60' }, body: '{"error":"Too many requests"}' }));
  await page.getByRole('button', { name: 'Check URL', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('60 seconds');
  await expect(page.locator('#result')).toBeHidden();
  await expect(page.getByRole('button', { name: 'Check URL', exact: true })).toBeEnabled();
  await page.unroute('**/api/predict');
  await page.getByRole('button', { name: 'Check URL', exact: true }).click();
  await expect(page.locator('#result')).toBeVisible();
  await expect(page.getByRole('alert')).toBeHidden();
});

test('clearing an in-flight check prevents a stale result', async ({ page }) => {
  await page.goto('/');
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  await page.route('**/api/predict', async route => {
    await pending;
    await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Model unavailable"}' }).catch(() => {});
  });
  await page.getByLabel('URL to check').fill('https://example.com');
  await page.getByRole('button', { name: 'Check URL', exact: true }).click();
  await expect(page.locator('#check-form')).toHaveAttribute('aria-busy', 'true');
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  release();
  await expect(page.locator('#status')).toHaveText('Ready for a new check.');
  await expect(page.locator('#result')).toBeHidden();
  await expect(page.getByRole('alert')).toBeHidden();
});

test('untrusted URL text renders without executing markup', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('URL to check').fill('https://example.com/<svg/onload=alert(1)>');
  await page.getByRole('button', { name: 'Check URL', exact: true }).click();
  await expect(page.locator('#result')).toBeVisible();
  await expect(page.locator('#analyzed-url svg')).toHaveCount(0);
  await expect(page.locator('#analyzed-url')).toContainText('<svg');
});
