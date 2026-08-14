/**
 * Headless browser checks for the published dashboard.
 *
 * They exist because everything this page does that matters happens after the payload
 * is decrypted, in the browser, and none of it is reachable from the private
 * repository's Python test suite. Locking has to actually remove the plaintext from
 * the DOM; narrowing the asset-class scope has to move the header, the buildup and the
 * table together or the page contradicts itself; a payload from a newer pipeline and a
 * broken response from the server both have to end in a sentence rather than in a
 * stack trace; and a string in the payload must never become markup.
 *
 * Every assertion is stated against the fixture's own decrypted payload rather than
 * against numbers typed into this file, so regenerating the fixture does not silently
 * turn the checks into assertions about nothing.
 *
 * Run: `npm ci && npx puppeteer browsers install chrome && node frontend-checks.mjs`
 * from `.github/checks`. Nothing here reads a path outside the repository except the
 * browser itself; `CHECKS_CHROME_PATH` overrides which browser is used when the
 * machine already has one.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer";

import {
  decryptEnvelope,
  encryptEnvelope,
  encryptLiveQuotes,
  liveQuotesKey,
} from "./lib/envelope.mjs";
import { startSite } from "./lib/site-server.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = path.resolve(HERE, "..", "..");
const FIXTURE_DIR = path.join(HERE, "fixtures");
const FIXTURE_FILE = path.join(FIXTURE_DIR, "portfolio.fixture.enc");
const PASSWORD_FILE = path.join(FIXTURE_DIR, "PASSWORD.txt");

// PBKDF2 at the pipeline's 600 000 iterations is roughly a second of a CI runner's CPU,
// and the first navigation also compiles a 177 KB module. Both are well inside this;
// it is here so a genuine hang fails the job instead of hitting the workflow's own
// six-hour ceiling.
const UNLOCK_TIMEOUT_MS = 60_000;
// The scope filter, the chart redraw after a resize and the search debounce are all
// driven by listeners rather than by anything a promise can be attached to.
const SETTLE_MS = 450;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Console noise the machine running the checks is responsible for, not the page.
 *
 * Empty on a CI runner and expected to stay that way. It exists because a developer
 * machine can have a security suite that rewrites responses on the way to the browser
 * — the one this was written against injects its own hosts into the page's
 * Content-Security-Policy, mangling `form-action 'none'` into `form-action 'none'
 * child-src …` and drawing two parser errors that have nothing to do with the code.
 * `detectEnvironmentNoise` only ever adds to this after proving the page the browser
 * received is not the page in the repository, so a real CSP mistake still fails.
 */
let environmentAllowances = [];
const goto = (page, origin) =>
  // `domcontentloaded` rather than `networkidle0`: every scenario below states its own
  // readiness condition — an enabled unlock button, a drawn table, a message in the
  // form — and waiting for the network to go quiet on top of that only added a way for
  // a scenario that deliberately breaks the payload request to time out instead of
  // being checked.
  page.goto(`${origin}/`, { waitUntil: "domcontentloaded", timeout: 30_000 });

/* ------------------------------------------------------------------ report --- */

class Report {
  constructor() {
    this.results = [];
  }

  record(name, failures, note = "") {
    this.results.push({ name, failures, note });
    const mark = failures.length ? "FAIL" : "ok  ";
    process.stdout.write(`${mark}  ${name}${note ? ` — ${note}` : ""}\n`);
    for (const failure of failures) process.stdout.write(`      · ${failure}\n`);
  }

  get failed() {
    return this.results.filter((item) => item.failures.length);
  }

  summarize() {
    const total = this.results.length;
    const failed = this.failed.length;
    process.stdout.write(
      `\n${total - failed}/${total} checks passed`
      + (failed ? `; failing: ${this.failed.map((item) => item.name).join(", ")}` : "")
      + "\n",
    );
    return failed === 0;
  }
}

/* -------------------------------------------------------------- page setup --- */

/**
 * A page in its own browser context, watching for anything the console reports.
 *
 * Its own context per scenario because the page remembers the asset-class scope in
 * localStorage and can remember a decryption key in IndexedDB: a scenario that
 * inherited either would be testing the previous scenario's leftovers.
 */
async function openPage(browser, { viewport = { width: 1280, height: 900 } } = {}) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.setViewport(viewport);
  const consoleErrors = [];
  const pageErrors = [];
  // Only `error`. Chrome files its own advice — "password forms should have a username
  // field", deprecation notices — as `verbose` and `warning`, and failing on those
  // would make the checks a running commentary on the browser rather than on the page.
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => pageErrors.push(`${error.name}: ${error.message}`));
  return {
    page,
    consoleErrors,
    pageErrors,
    async close() {
      await context.close();
    },
  };
}

/**
 * Console noise that is a failure everywhere except in the scenario that caused it.
 *
 * `allow` holds the patterns a deliberately broken scenario is entitled to produce —
 * the browser logs a failed request for the payload as a console error, and refusing
 * to allow that would mean no scenario could ever serve a 500. Nothing else is
 * forgiven, and an uncaught exception is never forgiven: `pageerror` means a render
 * path threw, which is the failure mode all of this exists to catch.
 */
function consoleFailures(session, allow = []) {
  const failures = [];
  const forgiven = [...allow, ...environmentAllowances];
  for (const text of session.consoleErrors) {
    if (forgiven.some((pattern) => pattern.test(text))) continue;
    failures.push(`console error: ${text}`);
  }
  for (const text of session.pageErrors) failures.push(`uncaught: ${text}`);
  return failures;
}

/**
 * Prove the browser got the page the repository holds — and say so when it did not.
 *
 * The comparison is the Content-Security-Policy, because that is the one line of
 * index.html an interfering proxy has a reason to rewrite and the one whose rewrite is
 * noisy: Chrome reports the mangled policy as two console errors on every page load,
 * which would fail every check for a reason that exists only on that machine. Proving
 * the tampering before forgiving the noise is what keeps this from being a blanket
 * exemption for CSP problems the page really does have.
 */
async function detectEnvironmentNoise(browser, origin, report) {
  const session = await openPage(browser);
  try {
    await goto(session.page, origin);
    const served = await session.page.evaluate(
      () => document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content ?? "",
    );
    const onDisk = readFileSync(path.join(SITE_ROOT, "index.html"), "utf8")
      .match(/http-equiv="Content-Security-Policy"\s+content="([^"]*)"/)?.[1] ?? "";
    if (!onDisk) {
      report.record("index.html declares a Content-Security-Policy", [
        "no Content-Security-Policy meta tag found in index.html",
      ]);
      return;
    }
    if (served === onDisk) {
      report.record("the browser receives the page the repository holds", []);
      return;
    }
    environmentAllowances = [/Content-Security-Policy/i];
    report.record(
      "the browser receives the page the repository holds",
      [],
      "NOTE: something on this machine rewrote the page's Content-Security-Policy in "
      + "flight, so CSP parser errors are ignored for this run. This cannot happen on a "
      + `runner. Served policy: ${served.slice(0, 160)}…`,
    );
  } finally {
    await session.close();
  }
}

async function unlock(page, password) {
  await page.waitForSelector("#unlockButton:not([disabled])", { timeout: UNLOCK_TIMEOUT_MS });
  await page.type("#passwordInput", password);
  await page.click("#unlockButton");
  await page.waitForFunction(
    () => !document.getElementById("dashboardView").hidden,
    { timeout: UNLOCK_TIMEOUT_MS },
  );
  await page.waitForFunction(
    () => document.querySelectorAll("#portfolioBody tr.data-row").length > 0,
    { timeout: UNLOCK_TIMEOUT_MS },
  );
}

/* ----------------------------------------------------------------- parsing --- */

/**
 * Read a number back out of what the page printed.
 *
 * The page formats in ru-RU: a non-breaking space groups the thousands, a comma is the
 * decimal separator and the currency symbol trails. Stripping everything that is not a
 * digit, a comma or a sign is enough, and is deliberately blind to which currency
 * symbol was used — the checks compare magnitudes across blocks, not formatting.
 */
function parseMoney(text) {
  if (text === null || text === undefined) return null;
  const cleaned = String(text)
    .replace(/[−–—]/g, "-")
    .replace(/[^\d,\-]/g, "")
    .replace(",", ".");
  if (!/\d/.test(cleaned)) return null;
  const value = Number(cleaned);
  return Number.isFinite(value) ? value : null;
}

const numberOf = (value) => {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};

const close = (left, right, tolerance = 0.02) =>
  left !== null && right !== null && Math.abs(left - right) <= tolerance;

/* ------------------------------------------------- check 1: lock leaves nothing --- */

/**
 * Everything a reader could get at without a debugger.
 *
 * Four sources, and each of them earns its place. `outerHTML` is the markup, but it is
 * not enough on its own: it serialises U+00A0 back to `&nbsp;`, so an amount the page
 * printed as "25 751,19 $" appears in it as `25&nbsp;751,19&nbsp;$` and no amount of
 * whitespace-stripping will find "25751" in that — a leak of every money figure on the
 * page hid behind exactly this while the check reported green. `textContent` is the
 * same text with the entities resolved, and unlike `innerText` it reads hidden
 * subtrees, which is the whole point when locking works by hiding a container.
 * Attribute values carry the tooltips and titles, and `value` carries what was typed
 * into a field, neither of which appears in either of the first two.
 */
function domSnapshotScript() {
  const html = document.documentElement.outerHTML;
  const text = document.documentElement.textContent;
  const attributes = [];
  for (const element of document.querySelectorAll("*")) {
    for (const attribute of element.attributes) attributes.push(attribute.value);
  }
  const values = Array.from(document.querySelectorAll("input, textarea, select"))
    .map((node) => `${node.value}`);
  return [html, text, attributes.join("\n"), values.join("\n")].join("\n");
}

// ru-RU groups thousands with U+00A0, and some builds use U+202F or U+2009.
// Removing every kind of space is what lets "25 751,19 $" be searched for as "25751".
const squash = (text) => text.replace(/[\s\u00A0\u202F\u2009]/g, "");

/**
 * The strings and magnitudes that only exist because the payload was decrypted.
 *
 * Deliberately derived from the payload rather than from a list of element ids: the
 * incident this check is for was plaintext surviving in a node nobody had thought to
 * clear, and a check that only looks where the code already looks would have missed it
 * exactly as the code did. Anything already present on the locked page before the
 * first unlock is dropped — that is page furniture, not portfolio.
 */
function secretsOf(payload) {
  const words = new Set();
  const numbers = new Set();

  const addWord = (value) => {
    const text = String(value ?? "").trim();
    if (text.length >= 3) words.add(text);
  };
  const addNumber = (value) => {
    const parsed = numberOf(value);
    if (parsed === null) return;
    // Both roundings of the integer part, because the page prints two decimals and the
    // digits before the comma are the truncation — except when the cents carry, and
    // then they are the rounding. Keeping only one of the two let a leak of −3 103,80
    // through: rounded it is 3104, and 3104 appears nowhere on the page.
    for (const magnitude of [Math.trunc(Math.abs(parsed)), Math.round(Math.abs(parsed))]) {
      // Under a thousand the digits are too short to be evidence of anything: "150" is
      // a share count and also the width of something in a stylesheet.
      if (magnitude >= 1000) numbers.add(String(magnitude));
    }
  };

  for (const row of payload.rows || []) {
    addWord(row.symbol);
    addWord(row.instrument);
    addWord(row.conid);
    addWord(row.assetClass);
    addWord(row.exchange);
    if (row.currency !== payload.baseCurrency) addWord(row.currency);
    for (const historic of row.symbolHistory || []) addWord(historic);
    for (const field of [
      "marketValueUsd", "totalResultUsd", "realizedPnlUsd", "unrealizedPnlUsd",
      "dividendsNetUsd", "openBasisUsd", "quantity",
    ]) addNumber(row[field]);
  }
  for (const block of [payload.totals, payload.accountIdentity, payload.performance,
    payload.allocation, payload.accountCash]) {
    for (const value of Object.values(block || {})) addNumber(value);
  }
  addNumber(payload.cash?.endingCash);
  for (const item of payload.quarantine?.fxInstruments || []) addWord(item.symbol);

  return { words: [...words], numbers: [...numbers] };
}

async function checkLockLeavesNothing(ctx) {
  const session = await openPage(ctx.browser);
  const failures = [];
  try {
    const { page } = session;
    await goto(page, ctx.site.origin);
    const baseline = await page.evaluate(domSnapshotScript);
    const baselineSquashed = squash(baseline);

    await unlock(page, ctx.password);

    // Fill in every corner the payload can reach before locking. Each of these was a
    // real leak at some point: an expanded card, a chart tooltip left showing a symbol
    // and an amount, and the search box holding what was typed into it.
    await page.click("#portfolioBody tr.data-row");
    await page.type("#searchInput", String(ctx.payload.rows[0].symbol).slice(0, 4));
    await sleep(SETTLE_MS);
    const tipTarget = await page.$("[data-tip-title]");
    if (tipTarget) {
      await tipTarget.hover();
      await sleep(120);
    }
    const tooltipFilled = await page.$eval("#chartTooltip", (node) => node.innerHTML.length > 0);

    await page.click("#lockButton");
    await page.waitForFunction(
      () => document.getElementById("dashboardView").hidden,
      { timeout: 10_000 },
    );
    await sleep(120);

    const locked = await page.evaluate(domSnapshotScript);
    const lockedSquashed = squash(locked);
    const { words, numbers } = secretsOf(ctx.payload);

    for (const word of words) {
      if (baseline.includes(word)) continue;
      if (locked.includes(word)) failures.push(`"${word}" still readable in the locked page`);
    }
    for (const digits of numbers) {
      if (baselineSquashed.includes(digits)) continue;
      if (lockedSquashed.includes(digits)) {
        failures.push(`the amount ${digits} still readable in the locked page`);
      }
    }
    if (!tooltipFilled) {
      failures.push("no chart tooltip was filled before locking, so the check never saw one");
    }
    failures.push(...consoleFailures(session));
    ctx.report.record(
      "lock removes every trace of the payload from the DOM",
      failures,
      `${words.length} names, ${numbers.length} amounts`,
    );
  } finally {
    await session.close();
  }
}

/* --------------------------------------------- check 2: the scope agrees with itself --- */

async function readScopeState(page) {
  return page.evaluate(() => {
    const cell = (row, selector) => row.querySelector(selector)?.textContent?.trim() ?? "";
    const buildup = {};
    for (const row of document.querySelectorAll("#buildupTable tr")) {
      const label = cell(row, "th[scope=row]");
      if (label) buildup[label] = cell(row, "td");
    }
    return {
      resultCount: document.getElementById("resultCount")?.textContent?.trim() ?? "",
      kpiContext: document.getElementById("kpiContext")?.textContent?.trim() ?? "",
      tableRows: document.querySelectorAll("#portfolioBody tr.data-row").length,
      groupCounts: [...document.querySelectorAll("#portfolioBody tr.group-row b")]
        .map((node) => Number(node.textContent.trim())),
      heroFigure: document.querySelector("#heroPanel .hero-figure")?.textContent?.trim() ?? "",
      heroEyebrow: document.querySelector("#heroPanel .eyebrow")?.textContent?.trim() ?? "",
      heroPositions: [...document.querySelectorAll("#heroPanel .hero-facts div")]
        .map((node) => node.textContent.trim())
        .find((text) => text.includes("Позиции")) ?? "",
      buildup,
    };
  });
}

async function selectClasses(page, classes) {
  await page.evaluate((picked) => {
    const boxes = [...document.querySelectorAll("#assetScopeOptions input[type=checkbox]")];
    for (const box of boxes) box.checked = picked.includes(box.value);
    // One bubbling event: the page listens on the container, not on each box.
    boxes[0].dispatchEvent(new Event("change", { bubbles: true }));
  }, classes);
  await sleep(SETTLE_MS);
}

/**
 * The scope filter is not only a function, it is a control someone has to reach.
 *
 * `selectClasses` above sets `checked` and dispatches the event, which proves the
 * filtering logic and nothing about whether a person can operate it. A one-line CSS
 * change made the row a scrollport at every width, and the menu — absolutely
 * positioned inside it — was clipped away on every desktop: open, invisible,
 * unclickable, and every existing check still green. So this one uses the mouse.
 */
async function checkScopeReachable(ctx) {
  const session = await openPage(ctx.browser);
  const failures = [];
  try {
    await goto(session.page, ctx.site.origin);
    await unlock(session.page, ctx.password);
    for (const width of [1920, 1440, 1280, 1024, 900, 830, 800, 761, 760, 420]) {
      await session.page.setViewport({ width, height: 900 });
      await sleep(SETTLE_MS);
      const opened = await session.page.evaluate(() => {
        const details = document.getElementById("assetScope")
          || document.querySelector(".scope-filter");
        if (!details) return { ok: false, why: "нет элемента среза" };
        details.open = true;
        return { ok: true };
      });
      if (!opened.ok) { failures.push(`${width}px: ${opened.why}`); continue; }
      await sleep(SETTLE_MS);
      // The page may be scrolled to bring the menu into view — a reader would do that
      // — but the *row* may not. `scrollIntoView` would scroll whichever box clips the
      // checkbox, which on a broken layout is the filter row itself: the first version
      // of this check did exactly that, reached into the 36px slit one option at a
      // time, and passed on the regression it was written to catch.
      const before = await session.page.evaluate(() => {
        const box = document.querySelector("#assetScopeOptions input[type=checkbox]");
        if (!box) return null;
        const rect = box.getBoundingClientRect();
        if (rect.top < 0 || rect.bottom > window.innerHeight) {
          window.scrollBy(0, rect.top - window.innerHeight / 2);
        }
        const after = box.getBoundingClientRect();
        return {
          checked: box.checked,
          x: after.left + after.width / 2,
          y: after.top + after.height / 2,
          onScreen: after.top >= 0 && after.bottom <= window.innerHeight
            && after.left >= 0 && after.right <= window.innerWidth,
        };
      });
      if (!before) { failures.push(`${width}px: нет чекбокса среза`); continue; }
      if (!before.onScreen) {
        failures.push(`${width}px: чекбокс среза не выводится на экран даже прокруткой страницы`);
        continue;
      }
      await session.page.mouse.click(before.x, before.y);
      await sleep(SETTLE_MS);
      const flipped = await session.page.evaluate((was) => {
        const box = document.querySelector("#assetScopeOptions input[type=checkbox]");
        return box ? box.checked !== was : false;
      }, before.checked);
      if (!flipped) {
        failures.push(`${width}px: клик по чекбоксу среза ничего не изменил`);
      }
    }
  } finally {
    // The one scenario that was not collecting these, while the README said every
    // scenario does. It is also the scenario that most needs them: ten widths, ten
    // menu interactions and ten chart redraws, so a handler that throws on one
    // breakpoint shows up here and nowhere else — and a thrown handler still leaves
    // the menu clickable, which is all the assertions above look at.
    failures.push(...consoleFailures(session));
    await session.close();
  }
  ctx.report.record(
    "the asset-class menu can actually be clicked at every width",
    failures,
    failures.length ? "" : "10 widths",
  );
}

/**
 * The three deliverables of this wave that nothing else here touches.
 *
 * Forgetting the device must lock even when the key store refuses, because that is the
 * half of the action that protects anything. Locking during a failing refresh must not
 * write into the cleared screen. And the tabs must answer the keyboard, since a
 * tablist that only responds to a mouse tells a screen reader nothing. Each of these
 * was fixed in this wave and each would have regressed unseen.
 */
async function checkFrontendGuarantees(ctx) {
  const session = await openPage(ctx.browser);
  const failures = [];
  try {
    const { page } = session;

    // 1. Forget-device with a key store that rejects.
    await goto(page, ctx.site.origin);
    await page.evaluate(() => {
      const open = indexedDB.open.bind(indexedDB);
      indexedDB.open = (...args) => {
        const request = open(...args);
        setTimeout(() => {
          const error = new Error("denied by the probe");
          Object.defineProperty(request, "error", { value: error, configurable: true });
          request.onerror?.({ target: request });
        }, 0);
        return request;
      };
    });
    await unlock(page, ctx.password);
    await page.click("#forgetDevice");
    await sleep(SETTLE_MS);
    const afterForget = await page.evaluate(() => ({
      locked: document.getElementById("dashboardView")?.hidden !== false,
      // `textContent`, for the reason spelled out above `readableText`: `innerText`
      // does not read hidden subtrees, and locking works by hiding `#dashboardView`.
      // So the residue loop below, written to catch a ticker left behind, could never
      // see one — it was asserting against a string that is empty by construction.
      body: document.documentElement.textContent,
    }));
    if (!afterForget.locked) {
      failures.push("«Забыть устройство» при отказе хранилища не заблокировало экран");
    }
    for (const row of (ctx.payload.rows || []).slice(0, 12)) {
      const symbol = String(row.symbol || "");
      if (symbol && afterForget.body.includes(symbol)) {
        failures.push(`после «Забыть устройство» в DOM остался тикер ${symbol}`);
        break;
      }
    }

    // 2. Locking during a refresh that is going to fail.
    await goto(page, ctx.site.origin);
    await unlock(page, ctx.password);
    await page.evaluate(() => {
      window.fetch = () => new Promise((_, reject) => {
        setTimeout(() => reject(new Error("probe: network down")), 900);
      });
    });
    await page.click("#refreshButton");
    await sleep(150);
    await page.evaluate(() => document.getElementById("lockButton").click());
    await sleep(1600);
    const afterRace = await page.evaluate(() => ({
      locked: document.getElementById("dashboardView")?.hidden !== false,
      feedback: document.getElementById("refreshFeedback")?.textContent || "",
      label: document.getElementById("refreshButtonLabel")?.textContent || "",
    }));
    if (!afterRace.locked) failures.push("блокировка во время падающего обновления не удержалась");
    if (afterRace.feedback.trim()) {
      failures.push(`падающее обновление написало в заблокированный экран: «${afterRace.feedback}»`);
    }
    if (afterRace.label.trim() && afterRace.label.trim() !== "Обновить") {
      failures.push(`метка кнопки обновления после блокировки: «${afterRace.label}»`);
    }

    // 3. The tabs answer the keyboard and say which one is chosen.
    await goto(page, ctx.site.origin);
    await unlock(page, ctx.password);
    const tabs = await page.evaluate(() => {
      const buttons = [...document.querySelectorAll("#quickTabs button")];
      return {
        count: buttons.length,
        roles: buttons.map((b) => b.getAttribute("role")),
        selected: buttons.filter((b) => b.getAttribute("aria-selected") === "true").length,
        tabindexes: buttons.map((b) => b.getAttribute("tabindex")),
      };
    });
    if (tabs.count < 2) failures.push("вкладок меньше двух — проверять нечего");
    if (tabs.roles.some((role) => role !== "tab")) failures.push("не у всех вкладок role=tab");
    if (tabs.selected !== 1) failures.push(`aria-selected=true у ${tabs.selected} вкладок вместо одной`);
    if (tabs.tabindexes.filter((t) => t === "0").length !== 1) {
      failures.push("roving tabindex не выставлен: не ровно одна вкладка достижима табуляцией");
    }
    // Which tab we start on has to be recorded, because both assertions below used to
    // hold when ArrowRight did nothing at all: focus stayed on the tab it was put on,
    // which is a tab and is the selected one. A keyboard test that passes on a page
    // with no key handler tests nothing. What it has to say is that focus *moved*, and
    // moved to the next tab in the list rather than anywhere.
    const startIndex = await page.evaluate(() => {
      const buttons = [...document.querySelectorAll("#quickTabs button")];
      const start = document.querySelector("#quickTabs button[tabindex='0']");
      start.focus();
      return buttons.indexOf(start);
    });
    await page.keyboard.press("ArrowRight");
    await sleep(SETTLE_MS);
    const moved = await page.evaluate(() => {
      const buttons = [...document.querySelectorAll("#quickTabs button")];
      const active = document.activeElement;
      return {
        index: buttons.indexOf(active),
        count: buttons.length,
        selectedIsFocused: active?.getAttribute("aria-selected") === "true",
        selectedCount: buttons.filter(
          (b) => b.getAttribute("aria-selected") === "true"
        ).length,
        rovingOnFocused: active?.getAttribute("tabindex") === "0",
      };
    });
    const expected = (startIndex + 1) % moved.count;
    if (moved.index !== expected) {
      failures.push(
        `стрелка вправо: фокус на вкладке ${moved.index} вместо ${expected}` +
          ` (стартовали с ${startIndex})`
      );
    }
    if (!moved.selectedIsFocused) failures.push("после стрелки выбранная вкладка не совпадает с фокусом");
    if (moved.selectedCount !== 1) {
      failures.push(`после стрелки aria-selected=true у ${moved.selectedCount} вкладок вместо одной`);
    }
    // The roving tabindex has to travel with the focus, or a second Tab press leaves
    // the tablist entirely from a tab the user never chose.
    if (!moved.rovingOnFocused) failures.push("после стрелки tabindex=0 остался не на сфокусированной вкладке");
  } finally {
    failures.push(...consoleFailures(session));
    await session.close();
  }
  ctx.report.record(
    "forget-device, the lock/refresh race and the tab keyboard all hold",
    failures,
    failures.length ? "" : "3 guarantees",
  );
}

async function checkScopeConsistency(ctx) {
  const session = await openPage(ctx.browser);
  const failures = [];
  try {
    const { page } = session;
    await goto(page, ctx.site.origin);
    await unlock(page, ctx.password);

    const rows = ctx.payload.rows || [];
    const quarantined = new Set(
      (ctx.payload.quarantine?.fxInstruments || []).map((item) => String(item.conid)),
    );
    const universe = [...new Set(rows.map((row) => String(row.assetClass || "—")))].sort();
    const offered = await page.$$eval(
      "#assetScopeOptions input[type=checkbox]",
      (boxes) => boxes.map((box) => box.value).sort(),
    );
    if (offered.join(",") !== universe.join(",")) {
      failures.push(`the filter offers [${offered}] but the payload holds [${universe}]`);
    }

    for (const assetClass of universe) {
      await selectClasses(page, [assetClass]);
      const view = await readScopeState(page);
      const listed = rows.filter((row) => String(row.assetClass || "—") === assetClass);
      // The table keeps quarantined rows and flags them; the summaries must not add
      // them up. Both halves of that rule are asserted, because getting either one
      // wrong is what makes the blocks disagree.
      const trusted = listed.filter((row) => !quarantined.has(String(row.conid)));
      const instrumentResult = trusted.reduce(
        (sum, row) => sum + (numberOf(row.totalResultUsd) || 0), 0);

      if (view.tableRows !== listed.length) {
        failures.push(
          `${assetClass}: the table draws ${view.tableRows} rows, the payload has ${listed.length}`);
      }
      const expectedCount = `${listed.length} из ${rows.length}`;
      if (view.resultCount !== expectedCount) {
        failures.push(`${assetClass}: the counter says "${view.resultCount}", expected "${expectedCount}"`);
      }
      const grouped = view.groupCounts.reduce((sum, value) => sum + value, 0);
      if (view.groupCounts.length && grouped !== listed.length) {
        failures.push(`${assetClass}: the group bands count ${grouped} rows, the table lists ${listed.length}`);
      }
      // Read as "the two numbers in the card", not by matching the Russian around them:
      // `\w` in a JavaScript regular expression is ASCII, so anything spelled out here
      // would fail on a word ending in Cyrillic and report a missing card instead.
      const positions = view.heroPositions.match(/\d+/g) || [];
      if (positions.length !== 2) {
        failures.push(
          `${assetClass}: the header does not state how many positions are listed `
          + `— "${view.heroPositions}"`);
      } else if (Number(positions[0]) + Number(positions[1]) !== listed.length) {
        failures.push(
          `${assetClass}: the header counts ${positions[0]}+${positions[1]} positions, `
          + `the table lists ${listed.length}`);
      }

      const buildupTotal = parseMoney(view.buildup["Итог по инструментам"]);
      if (buildupTotal === null) {
        failures.push(`${assetClass}: the buildup has no instrument total to compare`);
      } else if (!close(buildupTotal, instrumentResult, 0.02)) {
        failures.push(
          `${assetClass}: the buildup totals ${buildupTotal} over the rows it kept, `
          + `the payload's own rows total ${instrumentResult.toFixed(2)}`);
      }
      // With money in quarantine the account cannot be split by class, so a narrowed
      // header prints exactly the instrument total the buildup ends on. When it can be
      // split the header is an account figure and this comparison does not apply.
      const heroFigure = parseMoney(view.heroFigure);
      if (quarantined.size && universe.length > 1 && !close(heroFigure, instrumentResult, 0.02)) {
        failures.push(
          `${assetClass}: the header shows ${heroFigure} while the same rows total `
          + `${instrumentResult.toFixed(2)}`);
      }
      if (universe.length > 1 && !view.heroEyebrow.includes("·")) {
        failures.push(`${assetClass}: the header does not say which classes it is describing`);
      }
      if (!view.kpiContext) {
        failures.push(`${assetClass}: the KPI heading does not name the selection`);
      }
    }

    // Back to everything: the counter has to return to the full row count, and the
    // buildup total has to be the payload's own trusted total again.
    await selectClasses(page, universe);
    const whole = await readScopeState(page);
    if (whole.tableRows !== rows.length) {
      failures.push(`all classes: the table draws ${whole.tableRows} rows of ${rows.length}`);
    }
    const wholeTotal = parseMoney(whole.buildup["Итог по инструментам"]);
    if (!close(wholeTotal, numberOf(ctx.payload.totals?.totalResultUsd), 0.02)) {
      failures.push(
        `all classes: the buildup totals ${wholeTotal}, the payload says `
        + `${ctx.payload.totals?.totalResultUsd}`);
    }

    failures.push(...consoleFailures(session));
    ctx.report.record(
      "the header, the buildup and the table describe the same rows in every scope",
      failures,
      `${universe.length} classes`,
    );
  } finally {
    await session.close();
  }
}

/* ---------------------------------------- check 3: unknown schema and broken responses --- */

async function checkSchemaAndFailures(ctx) {
  const failures = [];

  // (a) A payload from a pipeline newer than this page.
  {
    const session = await openPage(ctx.browser);
    try {
      const future = { ...ctx.payload, schemaVersion: 99 };
      ctx.site.serve(await encryptEnvelope(ctx.envelope, future, ctx.password));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      const warning = await session.page.evaluate(() => {
        const node = document.getElementById("schemaWarning");
        return { hidden: node.hidden, text: node.textContent.trim() };
      });
      if (warning.hidden) failures.push("schema 99: the page shows no warning at all");
      if (!warning.text.includes("99")) {
        failures.push(`schema 99: the warning does not name the version — "${warning.text}"`);
      }
      const drawn = await session.page.$$eval("#portfolioBody tr.data-row", (nodes) => nodes.length);
      if (drawn !== (ctx.payload.rows || []).length) {
        failures.push(`schema 99: ${drawn} rows drawn, expected ${(ctx.payload.rows || []).length}`);
      }
      failures.push(...consoleFailures(session).map((item) => `schema 99: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (b) The server is broken. Nothing is decrypted, so the only thing the page can do
  //     is say so and offer the retry — silently sitting on a disabled button is the
  //     failure being guarded against.
  const brokenResponses = [
    ["500", { body: "upstream on fire", status: 500, type: "text/plain" }],
    ["not JSON", { body: "<html>404 from a CDN</html>", status: 200, type: "text/html" }],
    ["truncated JSON", { body: '{"format":"ibkr-portfolio-aes-gcm","ver', status: 200 }],
  ];
  for (const [label, response] of brokenResponses) {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(response.body, response);
      await goto(session.page, ctx.site.origin);
      await session.page.waitForFunction(
        () => document.getElementById("unlockMessage").textContent.trim().length > 0
          && !document.getElementById("retryLoad").hidden,
        { timeout: 15_000 },
      ).catch(() => {});
      const view = await session.page.evaluate(() => ({
        message: document.getElementById("unlockMessage").textContent.trim(),
        retryOffered: !document.getElementById("retryLoad").hidden,
        dashboardHidden: document.getElementById("dashboardView").hidden,
      }));
      if (!view.message) failures.push(`${label}: the page says nothing`);
      if (!view.retryOffered) failures.push(`${label}: no way to retry the load`);
      if (!view.dashboardHidden) failures.push(`${label}: the dashboard opened anyway`);
      // A failed request for the payload is logged by the browser itself, and this
      // scenario is the one that asked for it.
      failures.push(...consoleFailures(session, [/portfolio\.enc/, /Failed to load resource/])
        .map((item) => `${label}: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (c) A well-formed envelope in a format this page does not know.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve({ ...ctx.envelope, version: 99 });
      await goto(session.page, ctx.site.origin);
      await session.page.waitForFunction(
        () => document.getElementById("unlockMessage").textContent.trim().length > 0,
        { timeout: 15_000 },
      ).catch(() => {});
      const message = await session.page.$eval("#unlockMessage", (node) => node.textContent.trim());
      if (!/формат/i.test(message)) {
        failures.push(`envelope version 99: expected a message about the format, got "${message}"`);
      }
      failures.push(...consoleFailures(session).map((item) => `envelope version 99: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (d) The right password against a ciphertext that has been tampered with. AES-GCM
  //     refuses to authenticate it, and the page has to report that as a failure to
  //     open rather than as an exception out of WebCrypto.
  {
    const session = await openPage(ctx.browser);
    try {
      const bytes = Buffer.from(ctx.envelope.ciphertext, "base64");
      bytes[Math.floor(bytes.length / 2)] ^= 0xff;
      ctx.site.serve({ ...ctx.envelope, ciphertext: bytes.toString("base64") });
      await goto(session.page, ctx.site.origin);
      await session.page.waitForSelector("#unlockButton:not([disabled])", { timeout: UNLOCK_TIMEOUT_MS });
      await session.page.type("#passwordInput", ctx.password);
      await session.page.click("#unlockButton");
      await session.page.waitForFunction(
        () => /не подошёл|повреждён/i.test(document.getElementById("unlockMessage").textContent),
        { timeout: UNLOCK_TIMEOUT_MS },
      ).catch(() => {});
      const view = await session.page.evaluate(() => ({
        message: document.getElementById("unlockMessage").textContent.trim(),
        dashboardHidden: document.getElementById("dashboardView").hidden,
      }));
      if (!/не подошёл|повреждён/i.test(view.message)) {
        failures.push(`tampered ciphertext: expected a decryption failure, got "${view.message}"`);
      }
      if (!view.dashboardHidden) failures.push("tampered ciphertext: the dashboard opened anyway");
      failures.push(...consoleFailures(session).map((item) => `tampered ciphertext: ${item}`));
    } finally {
      await session.close();
    }
  }

  ctx.site.serve(ctx.envelope);
  ctx.report.record("an unknown schema and a broken response are answered, not thrown", failures);
}

/* --------------------------------------------------------------- check 4: XSS --- */

const XSS_SENTINEL = "XSSPROBE7";
const XSS_PAYLOAD = `<img src=x onerror="window.__xssFired=(window.__xssFired||0)+1">`
  + `<svg onload="window.__xssFired=(window.__xssFired||0)+1"></svg>`
  + `"><script>window.__xssFired=(window.__xssFired||0)+1</script> ${XSS_SENTINEL}`;

/**
 * Poison the text fields of the payload, and only the text fields.
 *
 * Every amount in the payload is a *string* too — "68.40", not 68.4 — so a blanket
 * walk over string values would replace the numbers with markup and the page would
 * fail to draw for reasons that have nothing to do with escaping. The list is explicit
 * for that reason, and the check afterwards insists the poison actually reached the
 * DOM, so a field that stops being rendered turns into a failure instead of a
 * silently vacuous pass.
 */
function poison(payload) {
  const poisoned = structuredClone(payload);
  for (const row of poisoned.rows || []) {
    row.symbol = `${row.symbol} ${XSS_PAYLOAD}`;
    row.instrument = `${row.instrument} ${XSS_PAYLOAD}`;
    row.exchange = XSS_PAYLOAD;
    row.symbolHistory = [XSS_PAYLOAD];
    row.reviewReasons = [...(row.reviewReasons || []), XSS_PAYLOAD];
    if (row.currentPrice) row.currentPrice.type = XSS_PAYLOAD;
    for (const cycle of row.cycles || []) {
      for (const event of cycle.cashEvents || []) event.description = XSS_PAYLOAD;
    }
  }
  // A currency code that is not a currency code: `Intl.NumberFormat` throws on it and
  // the page falls back to printing the code itself, which is a second place the
  // string reaches the DOM and the only one that does not go through the table cell.
  if (poisoned.rows?.[0]) poisoned.rows[0].currency = XSS_PAYLOAD;
  for (const issue of poisoned.reconciliation?.issues || []) {
    issue.message = `${issue.message} ${XSS_PAYLOAD}`;
    if (Array.isArray(issue.symbols)) issue.symbols = [XSS_PAYLOAD];
  }
  for (const item of poisoned.quarantine?.fxInstruments || []) item.symbol = XSS_PAYLOAD;
  if (poisoned.cash) poisoned.cash.source = XSS_PAYLOAD;
  poisoned.globalReviewEvents = [
    ...(poisoned.globalReviewEvents || []),
    {
      kind: "REVIEW",
      eventId: "xss-probe",
      source: XSS_PAYLOAD,
      conid: "unknown",
      symbol: XSS_PAYLOAD,
      timestamp: poisoned.generatedAt,
      category: "XSS_PROBE",
      description: XSS_PAYLOAD,
      raw: {},
    },
  ];
  return poisoned;
}

/**
 * The live layer: one price per row, and the money beside it recomputed by the
 * server from that same price.
 *
 * What this has to hold, and each of these is a way the page could lie:
 *
 *  * **The price shown is the live one, and the money agrees with it.** Two prices
 *    in a row was the old design; one price with figures computed from a different
 *    one would be worse than either.
 *  * **An overlay belonging to another payload is refused.** It arrives every few
 *    seconds and the pipeline republishes every half hour, so the two crossing is
 *    routine, not exotic. Applying it anyway draws part of one run and part of
 *    another, with a total equal to neither.
 *  * **Nothing survives the lock**, including a fetch still in the air.
 *  * **An unreachable source costs nothing** — the bucket is a third party.
 *  * **A delayed price says so in words.** Toronto stamps a fifteen-minute-old
 *    price with the current time.
 */
async function checkLiveLayer(ctx) {
  const failures = [];
  const rows = (ctx.payload.rows || []).filter((row) => row.conid);
  const key = liveQuotesKey();
  const payloadWithLayer = {
    ...ctx.payload,
    liveQuotes: {
      schemaVersion: 1,
      url: `${ctx.site.origin}/data/quotes.enc`,
      algorithm: "AES-GCM",
      aad: "temp-zero-inode-839:quotes:v1",
      key: Buffer.from(key).toString("base64"),
    },
  };
  const target = rows[0];
  const LIVE_PRICE = "1234.5";
  const LIVE_VALUE = "987654.32";

  // Deliberately unlike anything in the fixture, so a cell showing either of these
  // cannot be one that simply kept the snapshot.
  const snapshot = ({ generatedAt = ctx.payload.generatedAt, quoteExtra = {} } = {}) => ({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    quotes: Object.fromEntries(rows.slice(0, 3).map((row) => [String(row.conid), {
      price: LIVE_PRICE, currency: row.currency || "USD", type: "LAST",
      marketTime: new Date().toISOString(), fetchedAt: new Date().toISOString(),
      source: "yahoo-batch", freshness: "fresh", delayedByMinutes: 0,
      providerSymbol: row.symbol || "X", ...quoteExtra,
    }])),
    overlay: {
      schemaVersion: 1,
      basedOn: { generatedAt, plaintextSha256: "x" },
      rows: { [target.rowId]: { marketValueUsd: LIVE_VALUE } },
      totals: {},
    },
  });

  const readPage = (page) => page.evaluate((rowId) => {
    const tr = document.querySelector(`tr.data-row[data-row-key="${rowId}"]`);
    const cells = [...(tr?.querySelectorAll("td") || [])].map((td) => td.textContent);
    return {
      cells: cells.join(" | "),
      note: document.getElementById("liveQuotesNote")?.textContent || "",
      rows: document.querySelectorAll("#portfolioBody tr.data-row").length,
    };
  }, target.rowId);

  // (a) In force: the live price is the price, and the money follows it.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, payloadWithLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot(), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await session.page.waitForFunction(
        (want) => document.body.textContent.includes(want),
        { timeout: 10_000 }, "1 234,5",
      ).catch(() => {});

      const seen = await readPage(session.page);
      if (!/1[\s ]?234[.,]5/.test(seen.cells)) {
        failures.push(`in force: the row does not show the live price — ${seen.cells.slice(0, 160)}`);
      }
      if (!/987[\s ]?654/.test(seen.cells)) {
        failures.push("in force: the row's money was not taken from the overlay");
      }
      if (!seen.note.includes("пересчитаны")) {
        failures.push(`in force: the note does not say the money was recomputed — "${seen.note}"`);
      }
      failures.push(...consoleFailures(session).map((item) => `in force: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (b) An overlay computed against a different payload.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, payloadWithLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(
        snapshot({ generatedAt: "1999-01-01T00:00:00Z" }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((resolve) => setTimeout(resolve, 1200));

      const seen = await readPage(session.page);
      if (/987[\s ]?654/.test(seen.cells)) {
        failures.push("stale overlay: money from another payload's run was applied");
      }
      if (/1[\s ]?234[.,]5/.test(seen.cells)) {
        failures.push("stale overlay: the live price was shown beside snapshot money");
      }
      if (!seen.note.includes("из снимка")) {
        failures.push(`stale overlay: the note does not say the money is the snapshot's — "${seen.note}"`);
      }
    } finally {
      await session.close();
    }
  }

  // (c) The lock, with a fetch still in the air.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, payloadWithLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot(), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((resolve) => setTimeout(resolve, 800));

      // Holding the response open puts the lock inside an unfinished fetch. Waiting
      // for the next scheduled tick instead means waiting a whole refresh interval,
      // and a shorter wait observes no tick at all — which is how the first version
      // of this check passed against code with every lock guard deleted.
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot(), key), { delayMs: 1200 });
      await session.page.evaluate(() => document.getElementById("refreshButton")?.click());
      await new Promise((resolve) => setTimeout(resolve, 200));
      await session.page.click("#lockButton");
      await new Promise((resolve) => setTimeout(resolve, 2500));

      const leaked = await session.page.evaluate(() => document.documentElement.innerHTML);
      if (/1[\s ]?234[.,]5|987[\s ]?654/.test(leaked)) {
        failures.push("lock: a live figure survives in the DOM");
      }
      failures.push(...consoleFailures(session).map((item) => `lock: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (d) The bucket is simply not there.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, payloadWithLayer, ctx.password));
      ctx.site.withdrawLiveQuotes();
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((resolve) => setTimeout(resolve, 800));
      const seen = await readPage(session.page);
      if (seen.rows !== (ctx.payload.rows || []).length) {
        failures.push(`offline: ${seen.rows} rows drawn, expected ${(ctx.payload.rows || []).length}`);
      }
      if (!seen.note.includes("недоступны") && !seen.note.includes("снимок")) {
        failures.push(`offline: the note does not say so — "${seen.note}"`);
      }
      const thrown = consoleFailures(session).filter((item) => /exception/i.test(item));
      failures.push(...thrown.map((item) => `offline: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (e) A delayed quote names its delay.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, payloadWithLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(
        snapshot({ quoteExtra: { delayedByMinutes: 15, freshness: "delayed" } }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((resolve) => setTimeout(resolve, 1200));
      const seen = await readPage(session.page);
      if (!seen.cells.includes("задержка 15")) {
        failures.push(`delayed: the row does not name the delay — ${seen.cells.slice(0, 160)}`);
      }
      if (!seen.note.includes("задержк")) {
        failures.push(`delayed: the note does not count them — "${seen.note}"`);
      }
    } finally {
      ctx.site.withdrawLiveQuotes();
      await session.close();
    }
  }

  ctx.report.record(
    "the live layer shows one price, with the money the server computed from it",
    failures,
    `${Math.min(3, rows.length)} instruments, 5 scenarios`,
  );
}

/**
 * The last-exit tile: the price the owner got out at, and how far the market has
 * moved since. It exists to answer "is it worth going back in", so the two things
 * that matter are that it reads the exit and not the entry, and that a short reads
 * its buy-back rather than the sale that opened it.
 */
async function checkLastExitTile(ctx) {
  const failures = [];
  const withExit = (ctx.payload.rows || []).filter((row) =>
    (row.cycles || []).some((cycle) =>
      (cycle.trades || []).some((trade) => String(trade.action).toUpperCase() === "EXIT")));

  if (!withExit.length) {
    ctx.report.record("the last-exit tile reads the exit, not the entry", [
      "the fixture has no closed cycle at all, so this check proves nothing",
    ]);
    return;
  }

  const session = await openPage(ctx.browser);
  try {
    ctx.site.serve(await encryptEnvelope(ctx.envelope, ctx.payload, ctx.password));
    await goto(session.page, ctx.site.origin);
    await unlock(session.page, ctx.password);

    for (const row of withExit.slice(0, 3)) {
      const exits = (row.cycles || []).flatMap((cycle) =>
        (cycle.trades || []).filter((t) => String(t.action).toUpperCase() === "EXIT"));
      const newest = exits.sort((a, b) =>
        String(a.timestamp).localeCompare(String(b.timestamp))).at(-1);
      const short = String(row.direction || "").toUpperCase() === "SHORT";

      await session.page.click(`tr.data-row[data-row-key="${row.rowId}"]`);
      const tile = await session.page.evaluate((rowId) => {
        const anchor = document.querySelector(`tr.data-row[data-row-key="${rowId}"]`);
        const detail = anchor?.nextElementSibling;
        const item = [...(detail?.querySelectorAll(".detail-item") || [])]
          .find((node) => /Последняя цена/.test(node.querySelector("span")?.textContent || ""));
        return item ? {
          label: item.querySelector("span").textContent,
          value: item.querySelector("strong").textContent,
          drift: item.querySelector(".exit-drift")?.textContent || "",
          tone: item.querySelector(".exit-drift")?.className || "",
          title: item.getAttribute("title") || "",
        } : null;
      }, row.rowId);
      await session.page.click(`tr.data-row[data-row-key="${row.rowId}"]`);

      if (!tile) { failures.push(`${row.symbol}: no last-exit tile at all`); continue; }
      // A short's exit is a buy; labelling it "продажи" would name the wrong trade.
      const expected = short ? "откупа" : "продажи";
      if (!tile.label.includes(expected)) {
        failures.push(`${row.symbol} (${short ? "short" : "long"}): tile says "${tile.label}", expected "${expected}"`);
      }
      // The digits of the newest exit price must be the ones on screen — this is what
      // separates reading the exit from reading averageExit or the entry.
      const digits = String(newest.price).replace(/[^0-9]/g, "").slice(0, 4);
      if (digits && !tile.value.replace(/[^0-9]/g, "").includes(digits)) {
        failures.push(`${row.symbol}: tile shows "${tile.value}", newest exit was ${newest.price}`);
      }
      if (tile.drift && !/^[+-]?[\d\s.,]+%$/.test(tile.drift.trim())) {
        failures.push(`${row.symbol}: drift "${tile.drift}" is not a signed percentage`);
      }
      if (tile.drift && !/positive|negative/.test(tile.tone) && !/^[+-]?0[.,]00/.test(tile.drift.trim())) {
        failures.push(`${row.symbol}: drift "${tile.drift}" carries no sign colour`);
      }
      if (!tile.title.includes("не результат")) {
        failures.push(`${row.symbol}: the tooltip does not say the percentage is price movement, not P&L`);
      }
    }
    failures.push(...consoleFailures(session).map((item) => `last-exit tile: ${item}`));
  } finally {
    await session.close();
  }

  ctx.report.record(
    "the last-exit tile reads the exit, not the entry",
    failures,
    `${Math.min(3, withExit.length)} instruments`,
  );
}

/**
 * The alert panel: the only input on a page of outputs, and the only control whose
 * effect happens on a machine the browser cannot see.
 *
 * What has to hold:
 *  * **A short is offered a buy-back, not a sale.** Naming the wrong trade in the
 *    control that sets the alert is the same failure as naming it in the message.
 *  * **A rule reaches the server and comes back.** The page draws what the server
 *    parsed, not what it believes it sent, so the round trip is the feature.
 *  * **A failed write is visible on the rule itself.** One that looks set and never
 *    arrived is worse than none at all.
 *  * **Nothing survives the lock** — a half-typed price is a position disclosed.
 */
async function checkAlertsPanel(ctx) {
  const failures = [];
  const rows = (ctx.payload.rows || []).filter((row) => row.conid);
  const short = rows.find((row) => String(row.direction).toUpperCase() === "SHORT");
  const long = rows.find((row) => String(row.direction).toUpperCase() !== "SHORT");
  const key = liveQuotesKey();
  const withLayer = {
    ...ctx.payload,
    liveQuotes: {
      schemaVersion: 1, url: `${ctx.site.origin}/data/quotes.enc`,
      algorithm: "AES-GCM", aad: "temp-zero-inode-839:quotes:v1",
      key: Buffer.from(key).toString("base64"),
    },
  };
  const snapshot = (alerts) => ({
    schemaVersion: 1, generatedAt: new Date().toISOString(),
    quotes: Object.fromEntries(rows.slice(0, 3).map((row) => [String(row.conid), {
      price: "100", currency: row.currency || "USD", type: "LAST",
      marketTime: new Date().toISOString(), fetchedAt: new Date().toISOString(),
      source: "yahoo-batch", freshness: "fresh", delayedByMinutes: 0,
      providerSymbol: row.symbol || "X",
    }])),
    overlay: { schemaVersion: 1, basedOn: { generatedAt: ctx.payload.generatedAt },
               rows: {}, totals: {} },
    alerts,
  });

  const open = async (page, row) => {
    await page.click(`tr.data-row[data-row-key="${row.rowId}"]`);
    await page.waitForSelector(".alerts-panel", { timeout: 5000 }).catch(() => {});
  };

  // (a) Labels follow the direction, and existing rules are drawn from the server.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot({
        rules: [{ id: "r1", conid: String(long.conid), kind: "SELL_ABOVE", price: "123.45" }],
        state: { r1: { armed: true } }, writeUrl: `${ctx.site.origin}/alerts-sink`,
      }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 900));

      await open(session.page, long);
      const seen = await session.page.evaluate(() => {
        const panel = document.querySelector(".alerts-panel");
        return panel ? {
          kinds: [...panel.querySelectorAll(".alerts-kind")].map((n) => n.textContent.trim()),
          chips: [...panel.querySelectorAll(".alert-chip-what")].map((n) => n.textContent.trim()),
          notes: [...panel.querySelectorAll(".alert-chip-note")].map((n) => n.textContent.trim()),
        } : null;
      });
      if (!seen) failures.push("long: no alert panel in the expanded row");
      else {
        if (!seen.kinds.includes("Продать")) {
          failures.push(`long: the panel offers ${JSON.stringify(seen.kinds)}, expected a sale`);
        }
        if (!seen.chips.some((text) => text.includes("123,45") || text.includes("123.45"))) {
          failures.push(`long: the server's rule is not drawn — ${JSON.stringify(seen.chips)}`);
        }
        // Раньше здесь стоял греп по слову «сервер». Он проходил одинаково и на
        // «правило проверяется», и на «сервер о нём не знает» — то есть ровно на тех
        // двух состояниях, ради различения которых эта заметка и существует, и ровно
        // так 6 августа девять часов выглядели рабочими чипы, не проверявшиеся ничем.
        if (!seen.notes.some((text) => /активен/i.test(text))) {
          failures.push(`long: a rule the server confirms does not read as active — ${JSON.stringify(seen.notes)}`);
        }
      }
      failures.push(...consoleFailures(session).map((item) => `panel: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (a2) Та же самая карточка, но сервер о правиле молчит: состояние пустое. Заметка
  // ОБЯЗАНА отличаться от рабочей. Это второй половина проверки выше и главная из
  // двух: «выглядит поставленным, но не проверяется» — единственный отказ этой
  // панели, который владелец не в состоянии заметить сам.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot({
        rules: [{ id: "r1", conid: String(long.conid), kind: "SELL_ABOVE", price: "123.45" }],
        state: {}, writeUrl: `${ctx.site.origin}/alerts-sink`,
      }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 900));

      await open(session.page, long);
      const notes = await session.page.$$eval(".alert-chip-note",
        (nodes) => nodes.map((n) => n.textContent.trim())).catch(() => []);
      if (!notes.length) {
        failures.push("unconfirmed: the rule is not drawn at all");
      } else if (notes.some((text) => /активен/i.test(text))) {
        failures.push(`unconfirmed: a rule the server says nothing about reads as active — ${JSON.stringify(notes)}`);
      }
      failures.push(...consoleFailures(session).map((item) => `unconfirmed: ${item}`));
    } finally {
      await session.close();
    }
  }

  // (b) A short is offered the buy-back.
  if (short) {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot({
        rules: [], state: {}, writeUrl: `${ctx.site.origin}/alerts-sink`,
      }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 900));
      await open(session.page, short);
      const kinds = await session.page.$$eval(".alerts-kind",
        (nodes) => nodes.map((n) => n.textContent.trim()));
      if (!kinds.includes("Откупить")) {
        failures.push(`short: the panel offers ${JSON.stringify(kinds)}, expected a buy-back`);
      }
      if (kinds.includes("Продать")) {
        failures.push("short: the panel offers a sale, which is not how a short is closed");
      }
    } finally {
      await session.close();
    }
  } else {
    failures.push("the fixture holds no short position, so the direction rule is untested");
  }

  // (c) A refused write is visible on the rule.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot({
        rules: [], state: {},
        // A URL that will answer 404 to the PUT: the sink does not exist.
        writeUrl: `${ctx.site.origin}/nope/alerts.enc`,
      }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 900));
      await open(session.page, long);
      await session.page.evaluate(() => {
        const panel = document.querySelector(".alerts-panel");
        panel.querySelector(".alerts-input").value = "42";
        panel.querySelector(".alerts-input").dispatchEvent(new Event("input", { bubbles: true }));
        panel.querySelector(".alerts-add").click();
      });
      await new Promise((r) => setTimeout(r, 1200));
      const feedback = await session.page.$eval(".alerts-feedback",
        (node) => node.textContent.trim()).catch(() => "");
      const chips = await session.page.$$eval(".alert-chip",
        (nodes) => nodes.length).catch(() => 0);
      if (!feedback) {
        failures.push("refused write: the panel says nothing about the failure");
      }
      if (chips) {
        failures.push("refused write: the rule stayed on screen as though it had been saved");
      }
    } finally {
      await session.close();
    }
  }

  // (d) The lock takes the panel and anything typed into it.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot({
        rules: [{ id: "r1", conid: String(long.conid), kind: "BUY_BELOW", price: "777.77" }],
        state: {}, writeUrl: `${ctx.site.origin}/alerts-sink`,
      }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 900));
      await open(session.page, long);
      await session.page.click("#lockButton");
      await new Promise((r) => setTimeout(r, 800));
      const left = await session.page.evaluate(() => ({
        panels: document.querySelectorAll(".alerts-panel").length,
        text: /777[.,]77/.test(document.documentElement.innerHTML),
      }));
      if (left.panels) failures.push("lock: the alert panel survives");
      if (left.text) failures.push("lock: an alert level survives in the DOM");
    } finally {
      ctx.site.withdrawLiveQuotes();
      await session.close();
    }
  }

  ctx.report.record(
    "the alert panel names the right trade, round-trips a rule and admits a failure",
    failures,
    "4 scenarios",
  );
}

/**
 * Что аудит нашёл непокрытым: успешная запись, наполненные итоги, протухший
 * снимок и сохранность ввода. Каждый из этих четырёх пробелов давал проверкам
 * зелёный свет на поведении, которое на боевой странице было бы отказом.
 */
async function checkAuditGaps(ctx) {
  const failures = [];
  const rows = (ctx.payload.rows || []).filter((row) => row.conid);
  const target = rows[0];
  const key = liveQuotesKey();
  const withLayer = {
    ...ctx.payload,
    liveQuotes: {
      schemaVersion: 1, url: `${ctx.site.origin}/data/quotes.enc`,
      algorithm: "AES-GCM", aad: "temp-zero-inode-839:quotes:v1",
      key: Buffer.from(key).toString("base64"),
    },
  };
  const snapshot = ({ generatedAt = ctx.payload.generatedAt, totals = {}, age = 0,
                      rules = [] } = {}) => ({
    schemaVersion: 1,
    generatedAt: new Date(Date.now() - age).toISOString(),
    quotes: Object.fromEntries(rows.slice(0, 3).map((row) => [String(row.conid), {
      price: "1234.5", currency: row.currency || "USD", type: "LAST",
      marketTime: new Date().toISOString(), fetchedAt: new Date().toISOString(),
      source: "yahoo-batch", freshness: "fresh", delayedByMinutes: 0,
      providerSymbol: row.symbol || "X",
    }])),
    overlay: { schemaVersion: 1, basedOn: { generatedAt }, rows: {}, totals },
    alerts: { rules, state: {}, writeUrl: `${ctx.site.origin}/data/alerts-sink` },
  });

  const openRow = async (page) => {
    await page.click(`tr.data-row[data-row-key="${target.rowId}"]`);
    await page.waitForSelector(".alerts-panel", { timeout: 5000 }).catch(() => {});
  };

  // (a) Записанное правило действительно уходит на сервер — и с той ценой.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.resetAlertPuts(200);
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot(), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 900));
      await openRow(session.page);
      await session.page.evaluate(() => {
        const panel = document.querySelector(".alerts-panel");
        const input = panel.querySelector(".alerts-input");
        input.value = "77,25";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        panel.querySelector(".alerts-add").click();
      });
      await new Promise((r) => setTimeout(r, 1500));

      const puts = ctx.site.alertPuts();
      if (!puts.length) failures.push("save: nothing was PUT at all");
      else {
        const envelope = JSON.parse(puts.at(-1).body);
        if (envelope.format !== "ibkr-alerts-aes-gcm") {
          failures.push(`save: wrong envelope format ${envelope.format}`);
        }
        // Расшифровываем то, что реально ушло: только это отличает «запись прошла»
        // от «записалось именно то, что ввели».
        const { webcrypto } = await import("node:crypto");
        const { gunzipSync } = await import("node:zlib");
        const raw = await webcrypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: Buffer.from(envelope.cipher.iv, "base64"),
            additionalData: new TextEncoder().encode("temp-zero-inode-839:alerts:v1"),
            tagLength: 128,
          },
          await webcrypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]),
          Buffer.from(envelope.ciphertext, "base64"),
        );
        const body = JSON.parse(gunzipSync(Buffer.from(raw)).toString("utf8"));
        const rule = (body.rules || [])[0];
        if (!rule) failures.push("save: the uploaded document holds no rule");
        else {
          // Запятая — привычный разделитель; она обязана доехать как 77.25.
          if (rule.price !== "77.25") {
            failures.push(`save: uploaded price is ${rule.price}, expected 77.25`);
          }
          if (String(rule.conid) !== String(target.conid)) {
            failures.push(`save: uploaded conid ${rule.conid}, expected ${target.conid}`);
          }
        }
      }
    } finally {
      await session.close();
    }
  }

  // (b) Итоги из перекрытия действительно попадают в шапку.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(
        snapshot({ totals: { marketValueUsd: "424242.42" } }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 1200));
      const shown = await session.page.evaluate(() => document.body.textContent);
      if (!/424[\s ]?242/.test(shown)) {
        failures.push("totals: the overlay's market value never reaches the page");
      }
    } finally {
      await session.close();
    }
  }

  // (c) Просроченный снимок не применяется.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(
        snapshot({ totals: { marketValueUsd: "555555.55" }, age: 60 * 60 * 1000 }), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 1200));
      const shown = await session.page.evaluate(() => document.body.textContent);
      if (/555[\s ]?555/.test(shown)) {
        failures.push("expiry: an hour-old snapshot was applied as live");
      }
      if (/1[\s ]?234[.,]5/.test(shown)) {
        failures.push("expiry: an hour-old price was drawn as the current one");
      }
    } finally {
      await session.close();
    }
  }

  // (d) Тик живого слоя не стирает недонабранную цену.
  {
    const session = await openPage(ctx.browser);
    try {
      ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
      ctx.site.serveLiveQuotes(await encryptLiveQuotes(snapshot(), key));
      await goto(session.page, ctx.site.origin);
      await unlock(session.page, ctx.password);
      await new Promise((r) => setTimeout(r, 900));
      await openRow(session.page);
      await session.page.focus(".alerts-input");
      await session.page.evaluate(() => {
        const input = document.querySelector(".alerts-panel .alerts-input");
        input.value = "9";
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
      // Тик приходит раз в двадцать секунд; вызываем перерисовку тем же путём.
      await session.page.evaluate(() => document.getElementById("refreshButton")?.click());
      await new Promise((r) => setTimeout(r, 1500));
      const state = await session.page.evaluate(() => {
        const input = document.querySelector(".alerts-panel .alerts-input");
        return { value: input?.value ?? null, focused: document.activeElement === input };
      });
      if (state.value !== "9") {
        failures.push(`typing: a half-typed price became "${state.value}" after a refresh`);
      }
      if (!state.focused) failures.push("typing: focus left the field on a refresh");
    } finally {
      ctx.site.withdrawLiveQuotes();
      ctx.site.resetAlertPuts(200);
      await session.close();
    }
  }

  ctx.report.record(
    "a saved rule really arrives, live totals reach the header, a stale snapshot does not, and typing survives",
    failures,
    "4 scenarios",
  );
}

/**
 * Ряд фильтров: постоянные подписи, множественный выбор, уведомления.
 *
 * Проверяется не «фильтр что-то фильтрует», а три обещания, которые легко нарушить
 * незаметно. Подпись фильтра ПОСТОЯННА — стоило ей начать показывать выбранное, как
 * она разрасталась до «Опционы + Акции и ETF» и тащила за собой соседние кнопки, ради
 * чего слоту держали фиксированную ширину; выбор виден каёмкой, а не текстом. Выбор
 * МНОЖЕСТВЕННЫЙ — и здесь мало увидеть два флажка: период не просто отбирает строки,
 * он пересчитывает под себя каждую цифру, поэтому два года обязаны давать в точности
 * объединение того, что дают эти годы по одному. И фильтр уведомлений отбирает по
 * слою, которого в строке payload нет вовсе.
 */
async function checkFilterRow(ctx) {
  const failures = [];
  const rows = (ctx.payload.rows || []).filter((row) => row.conid);
  const key = liveQuotesKey();
  const withLayer = {
    ...ctx.payload,
    liveQuotes: {
      schemaVersion: 1, url: `${ctx.site.origin}/data/quotes.enc`,
      algorithm: "AES-GCM", aad: "temp-zero-inode-839:quotes:v1",
      key: Buffer.from(key).toString("base64"),
    },
  };
  // Правила на два РАЗНЫХ инструмента и разного вида: иначе выбор «Продать» и выбор
  // «На дату» дали бы один и тот же ответ, и проверка прошла бы на сломанном отборе.
  const [sellRow, dateRow] = [rows[0], rows[1]];
  const alerts = {
    rules: [
      { id: "f-sell", conid: String(sellRow.conid), kind: "SELL_ABOVE", price: "999" },
      { id: "f-date", conid: String(dateRow.conid), kind: "DATE", date: "2030-01-01" },
    ],
    state: {},
    writeUrl: `${ctx.site.origin}/alerts-sink`,
  };
  const liveSnapshot = {
    schemaVersion: 1, generatedAt: new Date().toISOString(),
    quotes: {},
    overlay: { schemaVersion: 1, basedOn: { generatedAt: ctx.payload.generatedAt }, rows: {}, totals: {} },
    alerts,
  };

  const FILTERS = ["assetScope", "alertScope", "directionScope", "currencyScope", "resultScope", "periodScope"];
  const LABELS = ["Инструменты", "Уведомления", "Направление", "Валюта", "Результат", "Период"];

  const session = await openPage(ctx.browser);
  try {
    ctx.site.serve(await encryptEnvelope(ctx.envelope, withLayer, ctx.password));
    ctx.site.serveLiveQuotes(await encryptLiveQuotes(liveSnapshot, key));
    await goto(session.page, ctx.site.origin);
    await unlock(session.page, ctx.password);
    await sleep(900);

    const readLabels = () => session.page.$$eval(
      ".select-filters .scope-filter > summary > span",
      (nodes) => nodes.map((node) => node.textContent.trim()),
    );
    const readNarrowed = () => session.page.$$eval(
      ".select-filters .scope-filter > summary",
      (nodes) => nodes.map((node) => node.classList.contains("is-narrowed")),
    );
    const readRowKeys = () => session.page.$$eval(
      "tr.data-row",
      (nodes) => nodes.map((node) => node.dataset.rowKey).filter(Boolean),
    );
    const optionsOf = (id) => session.page.$$eval(
      `#${id}Options input[type=checkbox]`,
      (boxes) => boxes.map((box) => box.value),
    );
    const pick = async (id, values) => {
      await session.page.evaluate((filterId, picked) => {
        const boxes = [...document.querySelectorAll(`#${filterId}Options input[type=checkbox]`)];
        for (const box of boxes) box.checked = picked.includes(box.value);
        // Одно всплывающее событие: страница слушает контейнер, а не каждый флажок.
        boxes[0].dispatchEvent(new Event("change", { bubbles: true }));
      }, id, values);
      await sleep(SETTLE_MS);
    };
    const resetAll = async () => {
      await session.page.click("#resetFilters");
      await sleep(SETTLE_MS);
    };

    /* 1. Порядок и постоянство подписей. */
    const labelsBefore = await readLabels();
    if (labelsBefore.join("|") !== LABELS.join("|")) {
      failures.push(`подписи фильтров: [${labelsBefore}] вместо [${LABELS}]`);
    }
    const missing = [];
    for (const id of FILTERS) {
      if (!(await session.page.$(`#${id}`))) missing.push(id);
    }
    if (missing.length) failures.push(`нет фильтров: ${missing.join(", ")}`);

    /* 2. Выбор виден каёмкой и НЕ трогает подпись — у КАЖДОГО фильтра.
       Именно «у каждого»: первая редакция проверки смотрела только первый, а он
       единственный перерисовывает себя сам (его `after` трогает всю страницу).
       У остальных пяти каёмка не загоралась вовсе — сужение работало, а признака
       сужения на экране не было, и проверка это пропустила. */
    for (const [index, id] of FILTERS.entries()) {
      const options = await optionsOf(id);
      if (options.length < 2) {
        failures.push(`${id}: в фикстуре ${options.length} вариант(ов), сужение проверить нечем`);
        continue;
      }
      await pick(id, [options[0]]);
      const labelsAfter = await readLabels();
      if (labelsAfter.join("|") !== LABELS.join("|")) {
        failures.push(`${id}: подпись изменилась после выбора — [${labelsAfter}]`);
      }
      const narrowed = await readNarrowed();
      if (!narrowed[index]) failures.push(`${id}: сужение не подсвечено каёмкой`);
      if (narrowed.filter(Boolean).length !== 1) {
        failures.push(`${id}: подсветились и фильтры, в которых ничего не выбирали`);
      }
      // Кнопка «Выбрать все» показывается ровно при сужении: она и есть путь назад.
      const allVisible = await session.page.$eval(`#${id}All`, (node) => !node.hidden);
      if (!allVisible) failures.push(`${id}: при сужении не предложена кнопка «Выбрать все»`);
      await resetAll();
      if ((await readNarrowed()).some(Boolean)) failures.push(`${id}: сброс не снял подсветку`);
    }

    /* 3. Уведомления: слой, которого в строке payload нет. */
    const allKeys = await readRowKeys();
    await pick("alertScope", ["SELL_ABOVE"]);
    const sellKeys = await readRowKeys();
    if (sellKeys.length !== 1 || sellKeys[0] !== sellRow.rowId) {
      failures.push(`«Продать»: показаны [${sellKeys}], ожидалась одна строка ${sellRow.rowId}`);
    }
    await pick("alertScope", ["DATE"]);
    const dateKeys = await readRowKeys();
    if (dateKeys.length !== 1 || dateKeys[0] !== dateRow.rowId) {
      failures.push(`«На дату»: показаны [${dateKeys}], ожидалась одна строка ${dateRow.rowId}`);
    }
    // Два вида сразу — объединение, а не пересечение. Пересечение здесь пусто, и
    // ошибка выглядела бы как «фильтр работает, просто ничего не нашлось».
    await pick("alertScope", ["SELL_ABOVE", "DATE"]);
    const bothKeys = await readRowKeys();
    if (bothKeys.length !== 2) {
      failures.push(`два вида уведомлений дали ${bothKeys.length} строк вместо двух — выбор читается как пересечение`);
    }
    await resetAll();
    if ((await readRowKeys()).length !== allKeys.length) failures.push("сброс не вернул все строки");

    /* 4. Период: два года обязаны дать объединение того, что дают годы по одному. */
    const years = await optionsOf("periodScope");
    if (years.length < 2) {
      failures.push(`в фикстуре ${years.length} года — множественный период проверить нечем`);
    } else {
      const [first, second] = years;
      await pick("periodScope", [first]);
      const one = await readRowKeys();
      await pick("periodScope", [second]);
      const two = await readRowKeys();
      await pick("periodScope", [first, second]);
      const together = await readRowKeys();
      const union = [...new Set([...one, ...two])].sort();
      if (together.slice().sort().join(",") !== union.join(",")) {
        failures.push(
          `период ${first}+${second} дал [${together.sort()}], а объединение годов по одному — [${union}]`,
        );
      }
      const note = await session.page.$eval("#kpiContext", (node) => node.textContent.trim());
      if (!note.includes(first) || !note.includes(second)) {
        failures.push(`строка итогов не называет оба выбранных года: «${note}»`);
      }
      // Раскрытая карточка под периодом: что периодом не меняется, не меняется.
      // «Первая сделка» под выбранным 2024 годом показывала первую сделку 2024-го —
      // это ответ на другой вопрос, и отличить его от настоящего было нельзя.
      //
      // Проверка обязана бить по различию, а не по любой строке: у инструмента, вся
      // жизнь которого внутри выбранного года, спроецированная «первая сделка» равна
      // настоящей, и первая редакция этой проверки именно так и проходила мимо обеих
      // подсунутых ошибок. Поэтому строка выбирается та, чей первый год НЕ совпадает
      // с периодом, а если такой не нашлось — это отказ, а не тихий пропуск.
      const cardOf = async (rowKey) => {
        const open = async () => session.page.evaluate((key) => {
          const tr = document.querySelector(`tr.data-row[data-row-key="${key}"]`);
          if (tr) tr.click();
          return Boolean(tr);
        }, rowKey);
        if (!await open()) return null;
        await sleep(SETTLE_MS);
        const card = await session.page.evaluate(() => Object.fromEntries(
          [...document.querySelectorAll(".detail-row .detail-item")].map((node) => [
            node.querySelector("span")?.textContent?.trim() || "",
            node.querySelector("strong")?.textContent?.trim() || "",
          ]),
        ));
        await open();
        await sleep(150);
        return card;
      };

      await resetAll();
      const lifeCards = {};
      for (const rowKey of await readRowKeys()) {
        const card = await cardOf(rowKey);
        if (card && card["Первая сделка"]) lifeCards[rowKey] = card;
      }
      // Пара «год + инструмент», на которой различие вообще существует: инструмент
      // жил в этом году, но начался раньше. Перебираем годы, а не берём один наугад.
      let oldest = null;
      let target = null;
      for (const year of years) {
        await pick("periodScope", [year]);
        const underPeriod = await readRowKeys();
        const candidate = underPeriod.find((rowKey) => lifeCards[rowKey]
          && !lifeCards[rowKey]["Первая сделка"].includes(year));
        if (candidate) { oldest = year; target = candidate; break; }
      }
      if (!target) {
        failures.push("в фикстуре нет инструмента, который жил бы в году позже своего первого — карточку под периодом проверить нечем");
      } else {
        const scoped = await cardOf(target);
        const whole = lifeCards[target];
        for (const tile of ["Conid", "Биржа", "Первая сделка", "Себестоимость позиции, AVCO"]) {
          if (whole[tile] !== undefined && whole[tile] !== scoped[tile]) {
            failures.push(`«${tile}» изменилась под периодом ${oldest}: «${whole[tile]}» → «${scoped[tile]}»`);
          }
        }
        const flows = Object.keys(scoped).filter((name) => /^(Дивиденды|Комиссии|Прочие сборы)/.test(name));
        if (!flows.length) {
          failures.push(`у ${target} под периодом не осталось ни одной плитки-потока — проверка подписи не состоялась`);
        } else if (!flows.every((name) => name.includes(oldest))) {
          failures.push(`плитки-потоки под периодом не называют период: ${flows.join(", ")}`);
        }
      }
      await resetAll();
    }

    /* 5. Результат: прибыльные и убыточные вместе — это всё, кроме нуля. */
    await pick("resultScope", ["profit"]);
    const profitKeys = await readRowKeys();
    await pick("resultScope", ["loss"]);
    const lossKeys = await readRowKeys();
    await pick("resultScope", ["profit", "loss"]);
    const eitherKeys = await readRowKeys();
    if (eitherKeys.length !== new Set([...profitKeys, ...lossKeys]).size) {
      failures.push("«Прибыльные + Убыточные» не равно объединению того и другого");
    }
    if (profitKeys.some((keyId) => lossKeys.includes(keyId))) {
      failures.push("строка попала и в прибыльные, и в убыточные");
    }
    await resetAll();

    failures.push(...consoleFailures(session));
  } finally {
    await session.close();
  }
  ctx.report.record(
    "фильтры: подписи постоянны, выбор множественный, уведомления отбирают",
    failures,
    `${FILTERS.length} фильтров`,
  );
}

async function checkXss(ctx) {
  const session = await openPage(ctx.browser);
  const failures = [];
  try {
    const { page } = session;
    ctx.site.serve(await encryptEnvelope(ctx.envelope, poison(ctx.payload), ctx.password));
    await goto(page, ctx.site.origin);
    await unlock(page, ctx.password);
    // Expand a card and open the issues panel too: the poisoned fields that never
    // appear in the collapsed table live there.
    await page.click("#portfolioBody tr.data-row");
    await sleep(SETTLE_MS);

    const verdict = await page.evaluate((sentinel) => {
      const injectable = ["onerror", "onload", "onclick", "onmouseover", "onfocus"];
      const withHandlers = [];
      for (const element of document.querySelectorAll("*")) {
        for (const attribute of element.attributes) {
          if (injectable.includes(attribute.name.toLowerCase())) {
            withHandlers.push(`${element.tagName.toLowerCase()}[${attribute.name}]`);
          }
        }
      }
      return {
        fired: window.__xssFired ?? 0,
        images: document.querySelectorAll("img, iframe, object, embed").length,
        // Не число, а происхождение. Счёт ломался от любого честного файла —
        // theme-boot.js добавился, и проверка объявила его внедрением. Сторожить
        // надо не количество, а то, что ни один скрипт не пришёл со страницей:
        // внедрённый был бы инлайном или ссылался бы на чужой хост.
        scripts: [...document.querySelectorAll("script")].map(
          (element) => element.getAttribute("src") || "инлайн"),
        withHandlers,
        // The sentinel must be present as *text*: that is the proof the string reached
        // the page at all and was rendered rather than parsed.
        sentinelInText: (document.body.innerText.match(new RegExp(sentinel, "g")) || []).length,
        escapedMarkup: document.body.innerHTML.includes("&lt;img"),
      };
    }, XSS_SENTINEL);

    if (verdict.fired) failures.push(`injected handlers ran ${verdict.fired} time(s)`);
    if (verdict.images) failures.push(`${verdict.images} injected element(s) exist in the DOM`);
    const foreign = verdict.scripts.filter((src) => {
      if (src === "инлайн") return true;
      return /^[a-z]+:/i.test(src) && !src.startsWith(ctx.site.origin);
    });
    if (foreign.length) {
      failures.push(`скрипты не со своего origin: ${foreign.join(", ")}`);
    }
    if (verdict.withHandlers.length) {
      failures.push(`inline handlers present: ${verdict.withHandlers.slice(0, 5).join(", ")}`);
    }
    if (verdict.sentinelInText < 3) {
      failures.push(
        `the poison reached the page only ${verdict.sentinelInText} time(s) — `
        + "the check is not looking at what it thinks it is");
    }
    if (!verdict.escapedMarkup) {
      failures.push("no escaped markup anywhere: the injected tags were not rendered as text");
    }
    // The page's own Content-Security-Policy refuses inline script, so an injection
    // that did get through would be reported here rather than silently executed.
    failures.push(...consoleFailures(session));
    ctx.report.record(
      "payload strings are rendered as text and never as markup",
      failures,
      `${verdict.sentinelInText} sentinels rendered`,
    );
  } finally {
    ctx.site.serve(ctx.envelope);
    await session.close();
  }
}

/* --------------------------------------- check 5: SVG validity and no sideways scroll --- */

const WIDTHS = [320, 375, 414, 768, 1024, 1280, 1600, 1920];

/**
 * How much a clipping container may hide before it counts as broken layout.
 *
 * The page contains its own overflow: `.panel` is `overflow: hidden`, so a block that
 * is too wide never makes the document scroll sideways — it is silently cut off
 * instead, and the sideways-scroll test alone cannot see it. This second measurement
 * is what does, and the tolerance is why it is not zero. It was 48 px when these checks
 * were written, to forgive one known defect: `.select-filters` was 34 px wider than
 * `.portfolio-panel` at exactly 768 px — the desktop filter row one breakpoint above
 * where it starts scrolling — and clipped the edge of the "Сбросить" button. That row
 * now has its own scrollport at every width, so the line is back where it belongs: low
 * enough that a clipped control fails, high enough to ignore the couple of subpixels a
 * chart rounds off at 320 px. Anything structural — a chart or a panel drawn hundreds
 * of pixels too wide — was always far above it.
 */
const CLIP_TOLERANCE_PX = 6;

async function checkLayoutAndSvg(ctx) {
  const session = await openPage(ctx.browser, { viewport: { width: WIDTHS[0], height: 900 } });
  const failures = [];
  // Sub-tolerance clipping is printed rather than dropped: it is the only place these
  // small responsive defects are visible at all, and a check that quietly forgives
  // something should at least say what it forgave.
  const clippedNotes = new Set();
  let inspected = 0;
  try {
    const { page } = session;
    await goto(page, ctx.site.origin);
    await unlock(page, ctx.password);

    for (const width of WIDTHS) {
      await page.setViewport({ width, height: 900 });
      // The charts are drawn at a measured pixel width, not into a scaled viewBox, so
      // they redraw on a ResizeObserver after the layout settles. Reading before that
      // measures the previous width's chart.
      await sleep(SETTLE_MS);
      const view = await page.evaluate(() => {
        const problems = [];
        let counted = 0;
        for (const svg of document.querySelectorAll("svg")) {
          counted += 1;
          const viewBox = svg.getAttribute("viewBox");
          if (viewBox) {
            const parts = viewBox.trim().split(/[\s,]+/).map(Number);
            if (parts.length !== 4 || parts.some((part) => !Number.isFinite(part))) {
              problems.push(`viewBox="${viewBox}" is not four numbers`);
            } else if (parts[2] <= 0 || parts[3] <= 0) {
              problems.push(`viewBox="${viewBox}" has no area`);
            }
          }
          const box = svg.getBoundingClientRect();
          const drawn = svg.getClientRects().length > 0;
          if (drawn && (box.width <= 0 || box.height <= 0)) {
            problems.push(`a visible svg is ${box.width}×${box.height}`);
          }
          for (const element of [svg, ...svg.querySelectorAll("*")]) {
            for (const attribute of element.attributes) {
              if (/NaN|Infinity|undefined/.test(attribute.value)) {
                problems.push(
                  `${element.tagName.toLowerCase()}[${attribute.name}]="${attribute.value}"`);
              }
            }
            if (element.tagName.toLowerCase() === "path" && !element.getAttribute("d")) {
              problems.push("a <path> with no d");
            }
          }
        }
        // Blocks whose own content does not fit and which cut it off rather than
        // scroll. Two exclusions, both deliberate: an element inside a scrollport is
        // meant to extend past it — that is what the table's horizontal scroll is —
        // and `text-overflow: ellipsis` is truncation the page asked for, which is how
        // the instrument names and the row notes are meant to behave.
        // `getAttribute("class")` rather than `.className`: on an SVG element the
        // property is an SVGAnimatedString, and a failure naming
        // "rect.[object SVGAnimatedString]" tells the reader nothing.
        const name = (element) =>
          `${element.tagName.toLowerCase()}.${element.getAttribute("class") || "-"}`.slice(0, 60);
        const clipped = [];
        for (const element of document.querySelectorAll("body *")) {
          const style = getComputedStyle(element);
          if (!["hidden", "clip"].includes(style.overflowX)) continue;
          if (style.textOverflow === "ellipsis") continue;
          const hidden = element.scrollWidth - element.clientWidth;
          if (hidden <= 0 || element.clientWidth === 0) continue;
          let scrollable = false;
          for (let parent = element.parentElement; parent; parent = parent.parentElement) {
            if (["auto", "scroll"].includes(getComputedStyle(parent).overflowX)) {
              scrollable = true;
              break;
            }
          }
          if (scrollable) continue;
          clipped.push({ what: name(element), hidden });
        }
        return {
          problems: [...new Set(problems)],
          svgCount: counted,
          documentWidth: document.documentElement.scrollWidth,
          bodyWidth: document.body.scrollWidth,
          innerWidth: window.innerWidth,
          clipped,
          // Anything sticking out past the viewport, named, so a failure says which
          // element to look at instead of only that the page scrolls sideways.
          overflowing: [...document.querySelectorAll("body *")]
            .filter((node) => node.getBoundingClientRect().right > window.innerWidth + 1)
            .slice(0, 5)
            .map(name),
        };
      });
      inspected = Math.max(inspected, view.svgCount);
      // One pixel of slack: a fractional layout width rounds up to a scrollWidth one
      // larger than the viewport without anything actually being cut off.
      if (view.documentWidth > view.innerWidth + 1) {
        failures.push(
          `${width}px: the page scrolls sideways (${view.documentWidth} > ${view.innerWidth})`
          + (view.overflowing.length ? ` — ${view.overflowing.join(", ")}` : ""));
      }
      if (view.bodyWidth > view.innerWidth + 1) {
        failures.push(`${width}px: the body is ${view.bodyWidth} wide in a ${view.innerWidth} viewport`);
      }
      if (!view.svgCount) failures.push(`${width}px: no charts were drawn at all`);
      for (const problem of view.problems) failures.push(`${width}px: ${problem}`);
      for (const item of view.clipped) {
        const line = `${width}px: ${item.what} hides ${item.hidden}px of its own content`;
        if (item.hidden > CLIP_TOLERANCE_PX) failures.push(line);
        else clippedNotes.add(line);
      }
    }

    failures.push(...consoleFailures(session));
    for (const note of clippedNotes) {
      process.stdout.write(`      (tolerated, under ${CLIP_TOLERANCE_PX}px) ${note}\n`);
    }
    ctx.report.record(
      "charts are valid SVG and nothing scrolls sideways from 320 to 1920 px",
      failures,
      `${WIDTHS.length} widths, ${inspected} svg nodes`,
    );
  } finally {
    await session.close();
  }
}

/* -------------------------------------------------------------------- main --- */

/**
 * Вечерняя тёмная тема: с 20:00 до 07:00 по часам устройства.
 *
 * Проверяется в настоящем браузере с подменёнными часами, потому что всё, что здесь
 * важно, происходит до первой отрисовки и зависит от локального времени: `getHours()`
 * читает часовой пояс машины, и никакой разбор исходника этого не покажет.
 *
 * Два свойства, которые легко сломать и оба тихо. Первое: навязанная вечером тёмная
 * НЕ должна затирать постоянный выбор — иначе один вечер сделает её «последней темой»
 * навсегда, и правило съест само себя. Второе: граница ровно на 20:00 и 07:00, а не
 * «где-то вечером»; час до и час после проверяются отдельно, иначе сдвиг на единицу
 * прошёл бы незамеченным.
 */
async function checkEveningTheme(ctx) {
  const failures = [];

  /* Часы подменяются ДО загрузки страницы: тему ставит theme-boot.js из <head>. */
  async function openAt(hour, { stored = null, session: sessionStorageTheme = null } = {}) {
    const session = await openPage(ctx.browser);
    await session.page.evaluateOnNewDocument(
      (h, persisted, tonight) => {
        const Real = Date;
        const fixed = new Real(2026, 7, 14, h, 30, 0).getTime();
        function Fake(...args) {
          return args.length ? new Real(...args) : new Real(fixed);
        }
        Fake.now = () => fixed;
        Fake.parse = Real.parse;
        Fake.UTC = Real.UTC;
        Fake.prototype = Real.prototype;
        window.Date = Fake;
        try {
          if (persisted) window.localStorage.setItem("portfolio-ledger:theme", persisted);
          else window.localStorage.removeItem("portfolio-ledger:theme");
          if (tonight) {
            window.sessionStorage.setItem("portfolio-ledger:theme-tonight", tonight);
          } else {
            window.sessionStorage.removeItem("portfolio-ledger:theme-tonight");
          }
        } catch (error) { /* приватный режим здесь не проверяется */ }
      },
      hour, stored, sessionStorageTheme,
    );
    await goto(session.page, ctx.site.origin);
    return session;
  }

  async function readState(page) {
    return page.evaluate(() => ({
      applied: document.documentElement.getAttribute("data-theme"),
      persisted: window.localStorage.getItem("portfolio-ledger:theme"),
      tonight: window.sessionStorage.getItem("portfolio-ledger:theme-tonight"),
    }));
  }

  /* Границы: час внутри окна и час снаружи, с обеих сторон. */
  const cases = [
    { hour: 19, stored: "light", expect: "light", why: "за час до восьми вечера ещё день" },
    { hour: 20, stored: "light", expect: "dark", why: "ровно в 20:00 окно уже началось" },
    { hour: 23, stored: "light", expect: "dark", why: "поздний вечер" },
    { hour: 3, stored: "light", expect: "dark", why: "после полуночи окно не обрывается" },
    { hour: 6, stored: "light", expect: "dark", why: "последний час окна" },
    { hour: 7, stored: "light", expect: "light", why: "ровно в 07:00 окно закончилось" },
    { hour: 12, stored: "dark", expect: "dark", why: "днём действует свой выбор" },
    { hour: 12, stored: "light", expect: "light", why: "днём действует свой выбор" },
    { hour: 21, stored: null, expect: "dark", why: "вечером без выбора всё равно тёмная" },
  ];

  for (const item of cases) {
    const session = await openAt(item.hour, { stored: item.stored });
    try {
      const state = await readState(session.page);
      if (state.applied !== item.expect) {
        failures.push(
          `${item.hour}:30 при выборе ${item.stored ?? "«не выбрано»"} → `
          + `${state.applied ?? "системная"}, ожидалась ${item.expect} (${item.why})`,
        );
      }
      /* Главное: постоянный выбор не тронут ничем из этого. */
      if (state.persisted !== item.stored) {
        failures.push(
          `${item.hour}:30 затёр постоянный выбор: было ${item.stored ?? "пусто"}, `
          + `стало ${state.persisted ?? "пусто"}`,
        );
      }
      failures.push(...consoleFailures(session));
    } finally {
      await session.close();
    }
  }

  /* Переключение вечером: действует, но живёт только до закрытия вкладки. */
  {
    const session = await openAt(21, { stored: "dark" });
    try {
      await session.page.click("#themeButton");
      const state = await readState(session.page);
      if (state.applied !== "light") {
        failures.push(`вечером переключатель не сработал: ${state.applied}`);
      }
      if (state.tonight !== "light") {
        failures.push("вечерний выбор не запомнен на время вкладки");
      }
      if (state.persisted !== "dark") {
        failures.push(
          `вечерний выбор затёр постоянный: стало ${state.persisted ?? "пусто"}, `
          + "а наутро должно вернуться dark",
        );
      }
      failures.push(...consoleFailures(session));
    } finally {
      await session.close();
    }
  }

  /* Тот же вечерний выбор переживает перезагрузку страницы — это и есть «до конца визита». */
  {
    const session = await openAt(21, { stored: "dark", session: "light" });
    try {
      const state = await readState(session.page);
      if (state.applied !== "light") {
        failures.push(`вечерний выбор не пережил перезагрузку: ${state.applied}`);
      }
      failures.push(...consoleFailures(session));
    } finally {
      await session.close();
    }
  }

  /* Днём переключатель по-прежнему пишет в постоянную память. */
  {
    const session = await openAt(12, { stored: "dark" });
    try {
      await session.page.click("#themeButton");
      const state = await readState(session.page);
      if (state.applied !== "light" || state.persisted !== "light") {
        failures.push(
          `днём выбор не запомнился навсегда: применено ${state.applied}, `
          + `сохранено ${state.persisted ?? "пусто"}`,
        );
      }
      failures.push(...consoleFailures(session));
    } finally {
      await session.close();
    }
  }

  ctx.report.record(
    "тема: с 20:00 до 07:00 тёмная, постоянный выбор не затирается",
    failures,
    `${cases.length} часов + переключение`,
  );
}


async function main() {
  const envelope = JSON.parse(readFileSync(FIXTURE_FILE, "utf8"));
  const password = readFileSync(PASSWORD_FILE, "utf8").trim();
  const payload = await decryptEnvelope(envelope, password);

  const site = await startSite(SITE_ROOT);
  site.serve(envelope);
  const browser = await puppeteer.launch({
    headless: true,
    // The sandbox is unavailable inside most CI containers, and this browser only ever
    // visits a server this process started, on the loopback interface.
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
    executablePath: process.env.CHECKS_CHROME_PATH || undefined,
  });
  const report = new Report();
  const ctx = { browser, site, envelope, payload, password, report };

  process.stdout.write(
    `site: ${SITE_ROOT}\nfixture: ${payload.rows.length} rows, schema ${payload.schemaVersion}, `
    + `generated ${payload.generatedAt}\n\n`,
  );

  try {
    await detectEnvironmentNoise(browser, site.origin, report);
    await checkLockLeavesNothing(ctx);
    await checkScopeConsistency(ctx);
    await checkScopeReachable(ctx);
    await checkFrontendGuarantees(ctx);
    await checkSchemaAndFailures(ctx);
    await checkLiveLayer(ctx);
    await checkLastExitTile(ctx);
    await checkAlertsPanel(ctx);
    await checkFilterRow(ctx);
    await checkAuditGaps(ctx);
    await checkXss(ctx);
    await checkLayoutAndSvg(ctx);
    await checkEveningTheme(ctx);
  } finally {
    await browser.close();
    await site.close();
  }

  return report.summarize() ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(1);
  },
);
