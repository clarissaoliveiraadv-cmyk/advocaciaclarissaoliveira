import { chromium, type Page } from "playwright";

async function shot(name: string, url: string, after?: (page: Page) => Promise<void>) {
  const browser = await chromium.launch({
    executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
  });
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  await page.goto(url, { waitUntil: "networkidle" });
  if (after) await after(page);
  await page.screenshot({ path: `/tmp/${name}.png`, fullPage: true });
  console.warn(`✓ /tmp/${name}.png`);
  await browser.close();
}

async function main() {
  // Login
  await shot("01-login", "http://localhost:3000/login");

  // Logged-in
  await shot("02-dashboard", "http://localhost:3000/login", async (page) => {
    await page.locator('input[name="email"]').fill("clarissaoliveira.adv@gmail.com");
    await page.locator('input[name="senha"]').fill("trocar-em-producao");
    await page.locator('button[type="submit"]').click();
    await page.waitForURL(/dashboard|recebiveis|movimento|clientes/, { timeout: 15000 });
    await page.waitForLoadState("networkidle");
  });

  const cookies = await (async () => {
    const b = await chromium.launch({
      executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    });
    const p = await b.newPage();
    await p.goto("http://localhost:3000/login", { waitUntil: "networkidle" });
    await p.locator('input[name="email"]').fill("clarissaoliveira.adv@gmail.com");
    await p.locator('input[name="senha"]').fill("trocar-em-producao");
    await p.locator('button[type="submit"]').click();
    await p.waitForURL(/dashboard|recebiveis/, { timeout: 15000 });
    const ck = await p.context().cookies();
    await b.close();
    return ck;
  })();

  for (const [name, url] of [
    ["03-clientes", "http://localhost:3000/clientes"],
    ["04-processos", "http://localhost:3000/processos"],
    ["05-cadastros", "http://localhost:3000/cadastros"],
    ["06-cadastros-contas", "http://localhost:3000/cadastros/contas"],
    ["07-cadastros-categorias", "http://localhost:3000/cadastros/categorias"],
    ["08-cadastros-parceiros", "http://localhost:3000/cadastros/parceiros"],
    ["09-movimento", "http://localhost:3000/movimento"],
    ["10-recebiveis", "http://localhost:3000/recebiveis"],
  ] as const) {
    const browser = await chromium.launch({
      executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    });
    const context = await browser.newContext({ viewport: { width: 1400, height: 900 } });
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
