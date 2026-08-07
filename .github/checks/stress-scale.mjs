/**
 * Стресс масштабом: что делает страница, когда инструментов становится много.
 *
 * Фикстура — семь строк, боевой снимок — триста двадцать пять. Ни то, ни другое не
 * говорит, где предел. Здесь снимок раздувается до 300, 1000 и 3000 строк, и каждый раз
 * замеряется то, что читатель чувствует: сколько идёт от пароля до первой строки,
 * сколько занимает переключение фильтра и сортировка, и не разъезжаются ли итоги.
 *
 * Запуск: node stress-scale.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer";
import { decryptEnvelope, encryptEnvelope } from "./lib/envelope.mjs";
import { startSite } from "./lib/site-server.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = path.resolve(HERE, "..", "..");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let checks = 0;
const failures = [];
const check = (ok, message) => { checks += 1; if (!ok) failures.push(message); };

const envelope = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "portfolio.fixture.enc"), "utf8"));
const password = fs.readFileSync(path.join(HERE, "fixtures", "PASSWORD.txt"), "utf8").trim();
const base = await decryptEnvelope(envelope, password);

/** Копия снимка на `count` строк: те же формы данных, разные инструменты. */
function inflate(count) {
  const source = (base.rows || []).filter((row) => row.conid);
  const rows = [];
  for (let i = 0; i < count; i += 1) {
    const model = source[i % source.length];
    rows.push({
      ...model,
      conid: `s${i}`,
      rowId: `s${i}:${model.direction || "LONG"}`,
      symbol: `SY${i}`,
      instrument: `Синтетический инструмент ${i}`,
    });
  }
  // Итоги обязаны остаться суммой строк, иначе страница честно скажет о расхождении и
  // проверка поймает собственную фикстуру, а не код.
  const fields = ["marketValueUsd", "openBasisUsd", "unrealizedPnlUsd", "realizedPnlUsd",
    "dividendsNetUsd", "totalResultUsd", "commissionsUsd", "exposureUsd",
    "investedCapitalUsd", "derivativeNotionalUsd", "transactionTaxesUsd",
    "instrumentFeesUsd", "dividendsGrossUsd", "withholdingTaxUsd", "fxRealizedPnlUsd"];
  const totals = { ...(base.totals || {}) };
  for (const field of fields) {
    if (!(field in totals)) continue;
    totals[field] = String(rows.reduce((acc, row) => acc + (Number(row[field]) || 0), 0));
  }
  return { ...base, rows, totals };
}

const site = await startSite(SITE_ROOT);
const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });

console.log("  %s  %s  %s  %s  %s".replace(/%s/g, "%s"),
  "строк".padEnd(7), "снимок".padEnd(9), "до первой строки".padEnd(17),
  "фильтр".padEnd(9), "сортировка");

for (const count of [300, 1000, 3000]) {
  const payload = inflate(count);
  const blob = await encryptEnvelope(envelope, payload, password);
  site.serve(blob);
  const bytes = Buffer.byteLength(JSON.stringify(blob));

  const page = await browser.newPage();
  const errors = [];
  page.on("console", (m) => {
    if (m.type() === "error" && !/Content-Security-Policy/i.test(m.text())) errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(`uncaught: ${e.message}`));
  try {
    await page.setViewport({ width: 1440, height: 1000 });
    await page.goto(site.origin, { waitUntil: "networkidle0" });
    await page.waitForSelector("#unlockButton:not([disabled])", { timeout: 30000 });
    await page.type("#passwordInput", password);

    const started = Date.now();
    await page.click("#unlockButton");
    await page.waitForFunction(
      () => document.querySelectorAll("#portfolioBody tr.data-row").length > 0,
      { timeout: 60000 },
    );
    const unlockMs = Date.now() - started;
    await sleep(500);

    // Переключение фильтра: то, что читатель делает чаще всего.
    const filterStart = Date.now();
    await page.evaluate(() => {
      const boxes = [...document.querySelectorAll("#currencyScopeOptions input[type=checkbox]")];
      boxes.forEach((box, index) => { box.checked = index === 0; });
      boxes[0]?.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await page.waitForFunction(() => true);
    await sleep(60);
    const filterMs = Date.now() - filterStart;

    const sortStart = Date.now();
    await page.evaluate(() => document.querySelector("#instrumentsTable thead th button")?.click());
    await sleep(60);
    const sortMs = Date.now() - sortStart;

    await page.click("#resetFilters");
    await sleep(300);

    const view = await page.evaluate(() => {
      const money = (text) => {
        const cleaned = String(text || "").replace(/[−–—]/g, "-").replace(/[^\d,\-]/g, "").replace(",", ".");
        const value = Number(cleaned);
        return Number.isFinite(value) ? value : null;
      };
      const rows = [...document.querySelectorAll("#portfolioBody tr.data-row")];
      return {
        rendered: rows.length,
        totalCell: rows.reduce((acc, tr) => acc + (money(tr.querySelector("td.is-total")?.textContent) || 0), 0),
        kpiTotal: money([...document.querySelectorAll("#kpiGrid .kpi-card")]
          .find((card) => card.querySelector("span")?.textContent?.includes("Итог по инструментам"))
          ?.querySelector("strong")?.textContent),
        context: document.getElementById("kpiContext")?.textContent?.trim() || "",
      };
    });

    console.log("  %s  %s  %s  %s  %s",
      String(count).padEnd(7), `${(bytes / 1048576).toFixed(2)} МБ`.padEnd(9),
      `${unlockMs} мс`.padEnd(17), `${filterMs} мс`.padEnd(9), `${sortMs} мс`);

    check(view.rendered === count, `${count}: нарисовано ${view.rendered} строк`);
    // Допуск растёт со строками, и это не поблажка. Карточка складывает значения полной
    // точности, а сюда читаются НАПЕЧАТАННЫЕ — каждое округлено до копейки, и на тысяче
    // строк расхождение до пяти долларов ожидаемо ровно потому, что карточка ТОЧНЕЕ.
    // Постоянный допуск в пять копеек объявлял бы отказом верную арифметику; на трёх
    // тысячах строк наблюдалось 0.34 при теоретическом пределе в 15.
    const roundingBudget = Math.max(0.05, count * 0.005);
    check(Math.abs(view.totalCell - view.kpiTotal) <= roundingBudget,
      `${count}: карточка итога ${view.kpiTotal} против суммы напечатанных строк `
      + `${view.totalCell.toFixed(2)}, разрыв больше бюджета округления ${roundingBudget}`);
    check(!errors.length, `${count}: в консоли ${errors.length} — ${errors[0]?.slice(0, 120) || ""}`);
    check(unlockMs < 30000, `${count}: от пароля до первой строки ${unlockMs} мс`);
    check(filterMs < 8000, `${count}: переключение фильтра ${filterMs} мс`);
  } finally {
    await page.close();
  }
}

console.log(`\n${checks} проверок, отказов: ${failures.length}`);
for (const line of failures) console.log("  FAIL", line);

await browser.close();
await site.close();
process.exit(failures.length ? 1 : 0);
