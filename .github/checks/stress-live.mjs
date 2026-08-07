/**
 * Стресс живого слоя: сколько котировок пришло, какие они и что страница про это говорит.
 *
 * Вопрос, на который отвечает файл: как ведёт себя страница, когда живых цен нет, есть
 * на одну позицию, есть на все, есть на инструменты, которых в портфеле нет вовсе, или
 * есть, но испорченные. Живой слой не обязателен по устройству — страница обязана
 * оставаться той же самой без него, — и каждый из этих случаев проверяется на одном и
 * том же: числа на экране не превращаются в NaN, в консоли пусто, а подпись говорит
 * правду о том, действует пересчёт или нет.
 *
 * Запуск: node stress-live.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer";
import { decryptEnvelope, encryptEnvelope, encryptLiveQuotes, liveQuotesKey } from "./lib/envelope.mjs";
import { startSite } from "./lib/site-server.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = path.resolve(HERE, "..", "..");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let checks = 0;
const failures = [];
const check = (ok, message) => { checks += 1; if (!ok) failures.push(message); };

const envelope = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "portfolio.fixture.enc"), "utf8"));
const password = fs.readFileSync(path.join(HERE, "fixtures", "PASSWORD.txt"), "utf8").trim();
const payload = await decryptEnvelope(envelope, password);
const rows = (payload.rows || []).filter((row) => row.conid);
const openRows = rows.filter((row) => Math.abs(Number(row.quantity) || 0) > 1e-8);

const site = await startSite(SITE_ROOT);
const key = liveQuotesKey();
const withLayer = {
  ...payload,
  liveQuotes: {
    schemaVersion: 1, url: `${site.origin}/data/quotes.enc`,
    algorithm: "AES-GCM", aad: "temp-zero-inode-839:quotes:v1",
    key: Buffer.from(key).toString("base64"),
  },
};
site.serve(await encryptEnvelope(envelope, withLayer, password));

const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });

const quote = (price, extra = {}) => ({
  price: String(price), currency: "USD", type: "LAST",
  marketTime: new Date().toISOString(), fetchedAt: new Date().toISOString(),
  source: "yahoo-batch", freshness: "fresh", delayedByMinutes: 0,
  providerSymbol: "X", ...extra,
});

const snapshot = (quotes, { generatedAt = null, overlay = true, basedOn = null } = {}) => ({
  schemaVersion: 1,
  generatedAt: generatedAt || new Date().toISOString(),
  quotes,
  overlay: overlay
    ? { schemaVersion: 1, basedOn: { generatedAt: basedOn || payload.generatedAt }, rows: {}, totals: {} }
    : null,
  alerts: { rules: [], state: {}, writeUrl: `${site.origin}/alerts-sink` },
});

/** Один сценарий: подать живой слой, открыть страницу, прочитать что вышло. */
async function scenario(name, live, inspect = null) {
  const page = await browser.newPage();
  const errors = [];
  page.on("console", (m) => {
    if (m.type() === "error" && !/Content-Security-Policy/i.test(m.text())) errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(`uncaught: ${e.message}`));
  try {
    site.serveLiveQuotes(await encryptLiveQuotes(live, key));
    await page.setViewport({ width: 1440, height: 1000 });
    await page.goto(site.origin, { waitUntil: "networkidle0" });
    await page.waitForSelector("#unlockButton:not([disabled])", { timeout: 20000 });
    await page.type("#passwordInput", password);
    await page.click("#unlockButton");
    await page.waitForFunction(
      () => document.querySelectorAll("#portfolioBody tr.data-row").length > 0,
      { timeout: 20000 },
    );
    await sleep(1400);

    const seen = await page.evaluate(() => {
      const note = document.getElementById("liveQuotesNote");
      const body = document.getElementById("dashboardView")?.innerText || "";
      return {
        note: note && !note.hidden ? note.textContent.trim() : "",
        noteClass: note?.className || "",
        rows: document.querySelectorAll("#portfolioBody tr.data-row").length,
        context: document.getElementById("kpiContext")?.textContent?.trim() || "",
        kpis: [...document.querySelectorAll("#kpiGrid .kpi-card strong")].map((n) => n.textContent.trim()),
        // Ни одно из этих слов не имеет права оказаться на экране ни в одном состоянии.
        junk: ["NaN", "undefined", "Infinity", "[object Object]"].filter((word) => body.includes(word)),
      };
    });

    check(seen.rows > 0, `${name}: таблица опустела`);
    check(!seen.junk.length, `${name}: на экране ${seen.junk.join(", ")}`);
    check(!errors.length, `${name}: в консоли ${errors.length} — ${errors[0]?.slice(0, 120) || ""}`);
    check(!seen.kpis.some((text) => /NaN|undefined/.test(text)),
      `${name}: карточка итогов показывает «${seen.kpis.find((t) => /NaN|undefined/.test(t))}»`);
    if (inspect) inspect(seen, name);
    console.log(`  ${name.padEnd(42)} строк ${String(seen.rows).padStart(2)} · «${seen.note.slice(0, 78)}»`);
    return seen;
  } finally {
    await page.close();
  }
}

console.log(`фикстура: ${rows.length} инструментов, из них открытых ${openRows.length}\n`);

/* 1. Живого слоя нет вовсе: пустой набор котировок. */
await scenario("нет ни одной котировки", snapshot({}), (seen, name) => {
  check(/живые цены: 0/.test(seen.note) || /устарели|недоступны/.test(seen.note),
    `${name}: подпись «${seen.note}» не говорит, что живых цен нет`);
});

/* 2. Одна котировка на одну открытую позицию. */
await scenario("одна котировка", snapshot({ [String(openRows[0].conid)]: quote(123.45) }),
  (seen, name) => check(/живые цены: 1/.test(seen.note), `${name}: подпись «${seen.note}»`));

/* 3. Котировки на все открытые позиции. */
await scenario("котировки на все открытые",
  snapshot(Object.fromEntries(openRows.map((row, i) => [String(row.conid), quote(100 + i)]))),
  (seen, name) => check(new RegExp(`живые цены: ${openRows.length}`).test(seen.note),
    `${name}: подпись «${seen.note}» против ${openRows.length} открытых`));

/* 4. Триста котировок на инструменты, которых в портфеле нет. Страница обязана их
      игнорировать, а не рисовать и не спотыкаться. */
await scenario("300 чужих котировок",
  snapshot(Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`zz${i}`, quote(50 + i)]))),
  (seen, name) => check(/живые цены: 300/.test(seen.note), `${name}: подпись «${seen.note}»`));

/* 5. Испорченные значения: null, отрицательная цена, нечисло, гигантское число. */
await scenario("испорченные котировки", snapshot({
  [String(openRows[0].conid)]: quote(null),
  [String(openRows[1]?.conid || "zz")]: quote("не число"),
  [String(openRows[2]?.conid || "zz2")]: quote(-42),
  [String(rows[0].conid)]: quote("1e308"),
}));

/* 6. Снимок старше предела: живой слой обязан быть отброшен. */
await scenario("снимок старше четырёх минут",
  snapshot({ [String(openRows[0].conid)]: quote(200) },
    { generatedAt: new Date(Date.now() - 30 * 60 * 1000).toISOString() }),
  (seen, name) => check(/устарели/.test(seen.note) && /live-note-off/.test(seen.noteClass),
    `${name}: подпись «${seen.note}», класс «${seen.noteClass}»`));

/* 7. Перекрытие от другого поколения снимка: деньги обязаны остаться снимковыми. */
await scenario("перекрытие от другого снимка",
  snapshot({ [String(openRows[0].conid)]: quote(200) }, { basedOn: "1999-01-01T00:00:00Z" }),
  (seen, name) => check(/деньги из снимка/.test(seen.note) || /устарели/.test(seen.note),
    `${name}: подпись «${seen.note}» обещает пересчёт по чужому перекрытию`));

/* 8. Перекрытия нет вообще (null) — слой есть, пересчёта нет. */
await scenario("живые цены без перекрытия",
  snapshot({ [String(openRows[0].conid)]: quote(200) }, { overlay: false }),
  (seen, name) => check(/деньги из снимка/.test(seen.note),
    `${name}: подпись «${seen.note}»`));

/* 9. Задержка биржи и выведенная цена — обе обязаны быть названы отдельно. */
await scenario("задержка и выведенная цена", snapshot({
  [String(openRows[0].conid)]: quote(150, { delayedByMinutes: 15, freshness: "delayed" }),
  [String(openRows[1]?.conid || "zz")]: quote(160, { derivedFrom: "US" }),
}), (seen, name) => {
  check(/задержк/i.test(seen.note), `${name}: задержка не названа — «${seen.note}»`);
  check(/выведен/i.test(seen.note), `${name}: выведенная цена не названа — «${seen.note}»`);
});

/* 10. Полсотни правил уведомлений: панель и фильтр обязаны выдержать. */
const manyRules = {
  rules: rows.slice(0, 7).flatMap((row, i) => ([
    { id: `b${i}`, conid: String(row.conid), kind: "BUY_BELOW", price: "1" },
    { id: `s${i}`, conid: String(row.conid), kind: "SELL_ABOVE", price: "99999" },
    { id: `d${i}`, conid: String(row.conid), kind: "DATE", date: "2030-01-01" },
  ])),
  state: {},
  writeUrl: `${site.origin}/alerts-sink`,
};
await scenario("21 правило уведомлений",
  { ...snapshot({ [String(openRows[0].conid)]: quote(120) }), alerts: manyRules });

console.log(`\n${checks} проверок, отказов: ${failures.length}`);
for (const line of failures) console.log("  FAIL", line);

await browser.close();
await site.close();
process.exit(failures.length ? 1 : 0);
