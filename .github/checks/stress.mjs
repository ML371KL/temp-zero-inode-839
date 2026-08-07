/**
 * Боевой стресс страницы: матрица срезов, живой слой в разных состояниях, крайние случаи.
 *
 * Не заменяет `frontend-checks.mjs` — тот стережёт отдельные обещания и живёт в CI. Этот
 * гоняет комбинации: каждый фильтр по каждому значению, пары, тройки, вкладки, поиск,
 * сортировки — и в КАЖДОЙ проверяет одно и то же тождество, которое не имеет права
 * сломаться ни в одном срезе: карточки итогов равны сумме видимых строк, счётчик в
 * заголовке равен числу видимых строк, и в консоли пусто.
 *
 * Запуск: node stress.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer";
import { decryptEnvelope, encryptEnvelope, encryptLiveQuotes, liveQuotesKey } from "./lib/envelope.mjs";
import { startSite } from "./lib/site-server.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = path.resolve(HERE, "..", "..");
const SETTLE = 260;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const FILTERS = ["assetScope", "alertScope", "directionScope", "currencyScope", "resultScope", "periodScope"];
const TABS = ["all", "open", "closed", "review"];

let checks = 0;
const failures = [];
const fail = (message) => { failures.push(message); };
const check = (ok, message) => { checks += 1; if (!ok) fail(message); };

/** Число из того, что напечатала страница: ru-RU, неразрывные пробелы, запятая. */
function parseMoney(text) {
  if (!text) return null;
  const cleaned = String(text).replace(/[−–—]/g, "-").replace(/[^\d,\-]/g, "").replace(",", ".");
  if (!cleaned || cleaned === "-") return null;
  const value = Number(cleaned);
  return Number.isFinite(value) ? value : null;
}

const envelope = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "portfolio.fixture.enc"), "utf8"));
const password = fs.readFileSync(path.join(HERE, "fixtures", "PASSWORD.txt"), "utf8").trim();
const payload = await decryptEnvelope(envelope, password);
const quarantined = new Set(
  (payload.quarantine?.fxInstruments || []).map((item) => String(item.conid)),
);

const site = await startSite(SITE_ROOT);
site.serve(envelope);
const browser = await puppeteer.launch({
  headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const page = await browser.newPage();
// На этой машине политику безопасности переписывает антивирус: он дописывает в неё свои
// хосты, и парсер браузера жалуется на директивы, которых в файле нет вовсе (`child-src`
// у нас не объявлен). Это шум среды, а не дефект страницы — и чтобы «шум среды» не стал
// удобной отговоркой, ниже политика из файла сверяется с той, что видит браузер: если они
// совпали, жалобы настоящие и считаются отказом. Всё, что не про CSP, — отказ всегда.
const CSP_NOISE = /Content-Security-Policy/i;
const consoleErrors = [];
const cspNoise = [];
page.on("console", (message) => {
  if (message.type() !== "error") return;
  (CSP_NOISE.test(message.text()) ? cspNoise : consoleErrors).push(message.text());
});
page.on("pageerror", (error) => consoleErrors.push(`uncaught: ${error.message}`));

await page.setViewport({ width: 1440, height: 1000 });
await page.goto(site.origin, { waitUntil: "networkidle0" });
await page.waitForSelector("#unlockButton:not([disabled])", { timeout: 20000 });
await page.type("#passwordInput", password);
await page.click("#unlockButton");
await page.waitForFunction(
  () => document.querySelectorAll("#portfolioBody tr.data-row").length > 0,
  { timeout: 20000 },
);
await sleep(600);

/* ------------------------------------------------------------------ операции --- */

const optionsOf = (id) => page.$$eval(`#${id}Options input[type=checkbox]`, (b) => b.map((x) => x.value));

async function pick(id, values) {
  await page.evaluate((filterId, picked) => {
    const boxes = [...document.querySelectorAll(`#${filterId}Options input[type=checkbox]`)];
    for (const box of boxes) box.checked = picked.includes(box.value);
    boxes[0]?.dispatchEvent(new Event("change", { bubbles: true }));
  }, id, values);
  await sleep(SETTLE);
}

async function resetAll() {
  await page.click("#resetFilters");
  await sleep(SETTLE);
}

async function setTab(tab) {
  await page.evaluate((name) => {
    document.querySelector(`#quickTabs button[data-tab="${name}"]`)?.click();
  }, tab);
  await sleep(SETTLE);
}

async function setSearch(text) {
  await page.evaluate((value) => {
    const input = document.getElementById("searchInput");
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, text);
  await sleep(500);   // поиск с задержкой
}

/** Всё, что нужно для тождества, одним чтением DOM. */
function readView(quarantineList) {
  return page.evaluate((quarantine) => {
    const money = (text) => {
      if (!text) return null;
      const cleaned = String(text).replace(/[−–—]/g, "-").replace(/[^\d,\-]/g, "").replace(",", ".");
      if (!cleaned || cleaned === "-") return null;
      const value = Number(cleaned);
      return Number.isFinite(value) ? value : null;
    };
    const rows = [...document.querySelectorAll("#portfolioBody tr.data-row")];
    const visible = rows.map((tr) => {
      const cells = [...tr.querySelectorAll("td")];
      return {
        key: tr.dataset.rowKey || "",
        conid: (tr.dataset.rowKey || "").split(":")[0],
        unrealized: money(cells[9]?.textContent),
        realized: money(cells[10]?.textContent),
        dividends: money(cells[11]?.textContent),
        total: money(tr.querySelector("td.is-total")?.textContent),
      };
    });
    const counted = visible.filter((row) => !quarantine.includes(row.conid));
    const kpis = Object.fromEntries([...document.querySelectorAll("#kpiGrid .kpi-card")].map((card) => [
      card.querySelector("span")?.textContent?.trim() || "",
      money(card.querySelector("strong")?.textContent),
    ]));
    return {
      visible, counted, kpis,
      context: document.getElementById("kpiContext")?.textContent?.trim() || "",
      heading: document.getElementById("resultCount")?.textContent?.trim()
        || document.querySelector("#instrumentsPanel .panel-heading p")?.textContent?.trim() || "",
      resetDisabled: document.getElementById("resetFilters")?.disabled ?? null,
    };
  }, quarantineList);
}

const CENT = 0.02;
const sum = (list, field) => list.reduce((acc, row) => acc + (row[field] || 0), 0);

/** Тождество, которое обязано держаться в ЛЮБОМ срезе. */
async function assertConsistent(label, { period = false } = {}) {
  const view = await readView([...quarantined]);
  const pairs = [
    ["Реализованный P&L", "realized"],
    ["Чистые дивиденды", "dividends"],
    ["Итог по инструментам", "total"],
  ];
  if (!period) pairs.push(["Нереализованный P&L", "unrealized"]);
  for (const [card, field] of pairs) {
    const shown = view.kpis[card];
    const expected = sum(view.counted, field);
    check(shown === null || Math.abs(shown - expected) <= CENT,
      `${label}: карточка «${card}» ${shown} против суммы строк ${expected.toFixed(2)}`);
  }
  const claimed = Number((view.context.match(/^(\d+)\s+из\s+(\d+)/) || [])[1]);
  check(Number.isFinite(claimed) && claimed === view.visible.length,
    `${label}: строка итогов заявляет ${claimed}, а строк на экране ${view.visible.length}`);
  return view;
}

/* ---------------------------------------------------------------- сценарии --- */

console.log(`фикстура: ${payload.rows.length} строк, на карантине ${quarantined.size}`);

const options = {};
for (const id of FILTERS) options[id] = await optionsOf(id);
console.log("варианты фильтров:", Object.entries(options).map(([k, v]) => `${k}=${v.length}`).join(" "));

await resetAll();
const base = await assertConsistent("исходный вид");
console.log(`исходный вид: ${base.visible.length} строк, итог ${base.kpis["Итог по инструментам"]}`);
check(base.resetDisabled === true, "кнопка «Сбросить» активна там, где ничего не выбрано");

/* 1. Каждый фильтр по каждому отдельному значению. */
let cases = 0;
for (const id of FILTERS) {
  for (const value of options[id]) {
    await resetAll();
    await pick(id, [value]);
    await assertConsistent(`${id}=${value}`, { period: id === "periodScope" });
    cases += 1;
  }
}
console.log(`одиночные срезы: ${cases}`);

/* 2. Пары фильтров. Пересечение обязано быть подмножеством каждой половины. */
let pairs = 0;
for (let i = 0; i < FILTERS.length; i += 1) {
  for (let j = i + 1; j < FILTERS.length; j += 1) {
    const [a, b] = [FILTERS[i], FILTERS[j]];
    if (!options[a].length || !options[b].length) continue;
    const [va, vb] = [options[a][0], options[b][0]];
    await resetAll();
    await pick(a, [va]);
    const onlyA = (await readView([...quarantined])).visible.map((row) => row.key);
    await resetAll();
    await pick(b, [vb]);
    const onlyB = (await readView([...quarantined])).visible.map((row) => row.key);
    await resetAll();
    await pick(a, [va]);
    await pick(b, [vb]);
    const both = await assertConsistent(`${a}=${va} + ${b}=${vb}`,
      { period: a === "periodScope" || b === "periodScope" });
    const keys = both.visible.map((row) => row.key);
    const setA = new Set(onlyA);
    const setB = new Set(onlyB);
    check(keys.every((key) => setA.has(key) && setB.has(key)),
      `${a}+${b}: пересечение содержит строку, которой нет в одной из половин`);
    const expected = onlyA.filter((key) => setB.has(key));
    check(keys.length === expected.length,
      `${a}+${b}: строк ${keys.length}, а пересечение половин даёт ${expected.length}`);
    pairs += 1;
  }
}
console.log(`пары фильтров: ${pairs}`);

/* 3. Вкладки × фильтр. */
let tabCases = 0;
for (const tab of TABS) {
  await resetAll();
  await setTab(tab);
  await assertConsistent(`вкладка ${tab}`);
  for (const id of ["assetScope", "currencyScope"]) {
    if (!options[id].length) continue;
    await pick(id, [options[id][0]]);
    await assertConsistent(`вкладка ${tab} + ${id}`);
    await pick(id, options[id]);
    tabCases += 1;
  }
}
await setTab("all");
console.log(`вкладки: ${tabCases}`);

/* 4. Поиск вместе с фильтрами и поиск, не находящий ничего. */
await resetAll();
const someSymbol = base.visible[0]?.key.split(":")[0] || "";
await setSearch(someSymbol);
await assertConsistent("поиск по conid");
await setSearch("нетакогоникогда");
const empty = await readView([...quarantined]);
check(empty.visible.length === 0, "поиск без совпадений оставил строки на экране");
check(/^0\s+из/.test(empty.context), `поиск без совпадений: строка итогов «${empty.context}»`);
for (const [card, value] of Object.entries(empty.kpis)) {
  check(value === null || value === 0, `пустой срез: карточка «${card}» показывает ${value}`);
}
await setSearch("");
await resetAll();

/* 5. Множественный выбор: объединение внутри одного фильтра. */
for (const id of FILTERS) {
  if (options[id].length < 2) continue;
  await resetAll();
  await pick(id, [options[id][0]]);
  const first = (await readView([...quarantined])).visible.map((row) => row.key);
  await pick(id, [options[id][1]]);
  const second = (await readView([...quarantined])).visible.map((row) => row.key);
  await pick(id, [options[id][0], options[id][1]]);
  const union = (await assertConsistent(`${id}: два значения`, { period: id === "periodScope" }))
    .visible.map((row) => row.key);
  const expected = new Set([...first, ...second]);
  check(union.length === expected.size,
    `${id}: два значения дали ${union.length} строк, объединение по одному — ${expected.size}`);
}
console.log("объединения внутри фильтра: проверены");

/* 6. Сортировка не меняет состав среза. */
await resetAll();
await pick("assetScope", [options.assetScope[0]]);
const beforeSort = (await readView([...quarantined])).visible.map((row) => row.key).sort();
const headers = await page.$$eval("#instrumentsTable thead th button", (nodes) => nodes.length);
for (let i = 0; i < Math.min(headers, 6); i += 1) {
  await page.evaluate((index) => {
    document.querySelectorAll("#instrumentsTable thead th button")[index]?.click();
  }, i);
  await sleep(SETTLE);
  const afterSort = (await readView([...quarantined])).visible.map((row) => row.key).sort();
  check(afterSort.join(",") === beforeSort.join(","),
    `сортировка по колонке ${i} изменила состав среза`);
}
await resetAll();
console.log(`сортировки: ${Math.min(headers, 6)}`);

/* 7. Сброс возвращает ровно исходный вид. */
await pick("assetScope", [options.assetScope[0]]);
await pick("currencyScope", [options.currencyScope[0]]);
await setTab("open");
await setSearch("a");
await setSearch("");
await resetAll();
const restored = await readView([...quarantined]);
check(restored.visible.length === base.visible.length,
  `сброс вернул ${restored.visible.length} строк вместо ${base.visible.length}`);
check(restored.kpis["Итог по инструментам"] === base.kpis["Итог по инструментам"],
  "сброс вернул другой итог");
check(restored.resetDisabled === true, "после сброса кнопка «Сбросить» осталась активной");

const servedCsp = await page.$eval('meta[http-equiv="Content-Security-Policy"]',
  (node) => node.getAttribute("content")).catch(() => "");
const fileCsp = (fs.readFileSync(path.join(SITE_ROOT, "index.html"), "utf8")
  .match(/Content-Security-Policy"\s+content="([^"]+)"/) || [])[1] || "";
const rewritten = servedCsp !== fileCsp;
console.log(`\nконсольных ошибок: ${consoleErrors.length}`
  + (cspNoise.length
    ? ` (+${cspNoise.length} про CSP — ${rewritten ? "политику переписала среда" : "ПОЛИТИКА СВОЯ"})`
    : ""));
for (const line of consoleErrors.slice(0, 5)) console.log("  ·", line.slice(0, 160));
check(consoleErrors.length === 0, `в консоли ${consoleErrors.length} ошибок`);
check(rewritten || cspNoise.length === 0,
  `парсер жалуется на НАШУ политику: ${(cspNoise[0] || "").slice(0, 140)}`);
check(fileCsp.includes("form-action 'none'") && fileCsp.split(";").length >= 8,
  `политика в файле неполна: ${fileCsp.slice(0, 120)}`);

console.log(`\n${checks} проверок, отказов: ${failures.length}`);
for (const line of failures.slice(0, 25)) console.log("  FAIL", line);

await browser.close();
await site.close();
process.exit(failures.length ? 1 : 0);
