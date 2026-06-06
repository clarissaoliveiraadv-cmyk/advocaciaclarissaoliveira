import { chromium } from "playwright";

const CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";

async function main() {
  const previstoId = process.argv[2];
  const recebidoId = process.argv[3];

  // Login uma vez e capturar cookies
  const b1 = await chromium.launch({ executablePath: CHROME });
  const p1 = await b1.newPage();
  await p1.goto("http://localhost:3000/login", { waitUntil: "networkidle" });
  await p1.locator('input[name="email"]').fill("clarissaoliveira.adv@gmail.com");
  await p1.locator('input[name="senha"]').fill("trocar-em-producao");
  await p1.locator('button[type="submit"]').click();
  await p1.waitForURL(/dashboard|recebiveis/, { timeout: 15000 });
  const cookies = await p1.context().cookies();
  await b1.close();

  for (const [name, url] of [
    ["11-receber-previsto", `http://localhost:3000/recebiveis/${previstoId}/receber`],
    ["12-distribuicao-confirmada", `http://localhost:3000/recebiveis/${recebidoId}/receber`],
  ] as const) {
    const browser = await chromium.launch({ executablePath: CHROME });
    const context = await browser.newContext({ viewport: { width: 1400, height: 1100 } });
    await context.addCookies(cookies);
    const page = await context.newPage();
    await page.goto(url, { waitUntil: "networkidle" });
    await page.screenshot({ path: `/tmp/${name}.png`, fullPage: true });
    console.warn(`✓ /tmp/${name}.png`);
    await browser.close();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
