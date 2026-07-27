"use strict";

import {
  areaChart,
  areaGeometry,
  bareAxisFormatter,
  chartTable,
  columnChart,
  compactUsd,
  compactUsdFixed,
  divergingBars,
  escapeHtml,
  rankedBars,
  rankedLayout,
  sharePercent,
  signedCompactUsd,
  splitMeter,
  stackedStrip,
  waterfall,
// Versioned like the <script> and <link> tags in index.html: without it a change to
// this module alone would keep being served from cache.
} from "./charts.js?v=20260727-9";

const SUPPORTED_SCHEMA_VERSIONS = [2, 3];
const SUPPORTED_ENVELOPE_VERSIONS = [1, 2];
// A saved key is a standing grant of access to the whole portfolio from this browser
// profile. It expires so that a device left behind stops being a key eventually.
const DEVICE_KEY_MAX_AGE_MS = 12 * 60 * 60 * 1000;
const SEARCH_DEBOUNCE_MS = 200;

const state = {
  envelope: null,
  payload: null,
  cryptoKey: null,
  activeTab: "all",
  expanded: new Set(),
  sortKey: null,
  sortDirection: null,
  refreshTimer: null,
  searchTimer: null,
  alertDrafts: new Map(),
  charts: new Map(),
  // The table is the default: it is the exact statement of what the number is made
  // of, and the chart is the illustration of it.
  buildupAsTable: true,
  timelineMode: "absolute",
  // Which asset classes the whole page is about. Empty means every class; the
  // selection is restored from localStorage on load.
  assetScope: new Set(),
};

/* ------------------------------------------------------------------ scope --- */

/*
 * The asset-class filter is not a table filter. Futures on this account were one leg
 * of an arbitrage whose other leg lived at a different broker, so their loss here is
 * real money that is answered for elsewhere; leaving them in makes every headline
 * figure describe a strategy rather than the trading. Narrowing the scope therefore
 * has to reach the summary blocks, not just the rows.
 *
 * What it cannot reach is the account. Interest, account fees, currency conversions
 * and the cash balance belong to no instrument, and net contributions were paid into
 * the account as a whole. So a narrowed page answers a different question — what the
 * chosen instruments did — and says so, instead of quietly relabelling the old one.
 */
const SCOPE_KEY = "portfolio-ledger:asset-scope";

function storedScope() {
  try {
    const raw = JSON.parse(window.localStorage.getItem(SCOPE_KEY) || "[]");
    return new Set(Array.isArray(raw) ? raw.map(String) : []);
  } catch {
    return new Set();
  }
}

function persistScope() {
  try {
    window.localStorage.setItem(SCOPE_KEY, JSON.stringify([...state.assetScope]));
  } catch {
    /* Private mode: the choice still holds for this session. */
  }
}

/** Classes present in the payload, in a stable order. */
function scopeUniverse() {
  return [...new Set((state.payload?.rows || []).map((row) => String(row.assetClass || "—")))]
    .sort((left, right) => left.localeCompare(right));
}

/**
 * Drop a remembered class the current payload does not have.
 *
 * Without this a scope saved when futures existed would survive into a payload
 * without them and read as a narrowing of nothing, or — if every remembered class
 * were gone — empty the page with no visible cause.
 */
function pruneScope() {
  const universe = new Set(scopeUniverse());
  for (const value of [...state.assetScope]) {
    if (!universe.has(value)) state.assetScope.delete(value);
  }
}

/** True when the selection actually leaves something out. */
function scopeNarrowed() {
  const universe = scopeUniverse();
  if (!state.assetScope.size) return false;
  return universe.some((value) => !state.assetScope.has(value));
}

function inScope(row) {
  if (!state.assetScope.size) return true;
  return state.assetScope.has(String(row.assetClass || "—"));
}

function scopedRows() {
  return (state.payload?.rows || []).filter(inScope);
}

function scopeLabel() {
  if (!scopeNarrowed()) return "Все классы";
  return [...state.assetScope]
    .sort((left, right) => left.localeCompare(right))
    .map((value) => ASSET_CLASS_LABELS[value] || value)
    .join(" + ");
}

/**
 * Money-weighted return of the account with the excluded classes carved out of it.
 *
 * Not the return of the chosen instruments on their own. Interest, account fees and
 * currency conversions are the account's, not any class's, and they kept accruing
 * whichever classes are ticked — so the question the card answers is "what did this
 * account do without those instruments", and the answer has to be an account figure.
 *
 * The excluded instruments are treated as somewhere else the money went: cash they
 * consumed is a withdrawal from what remains, cash they returned is a deposit, and
 * whatever of them is still open is taken out of the closing value. That is also
 * literally true here — the futures were one leg of an arbitrage settled at another
 * broker. With nothing excluded the flows reduce to contributions and closing value,
 * which is the account's own money-weighted return, and it comes back identical.
 *
 * `cashUsd` is used rather than price times quantity because only it is converted,
 * and at the rate of its own execution. Dividends are dated by payment, not ex-date:
 * this asks when the cash moved; the cumulative chart asks which position earned it.
 */
function carveOutFlows(payload, excluded, asOf) {
  const flows = [];
  let known = true;
  for (const flow of payload.cashFlows || []) {
    const amount = numberValue(flow.amountUsd);
    const time = timeValue(flow.timestamp);
    // A contribution is money put in, which is a negative flow to the holder.
    if (amount && time !== null) flows.push({ time, amount: -amount });
  }
  let excludedValue = 0;
  for (const row of excluded) {
    for (const cycle of row.cycles || []) {
      for (const trade of cycle.trades || []) {
        const amount = numberValue(trade.cashUsd);
        const time = timeValue(trade.timestamp);
        // A corporate action moves shares, not cash, and carries no `cashUsd` — there
        // is nothing to carve out and nothing is missing. An execution without one is
        // a different thing: a payload built before the field existed. Its flows would
        // silently go missing and the rate would come out wrong but confident, so say
        // it is unknown instead.
        if (amount === null && !trade.actionId) known = false;
        if (amount && time !== null) flows.push({ time, amount: -amount });
      }
      for (const event of cycle.cashEvents || []) {
        const amount = numberValue(event.amountUsd);
        const time = timeValue(event.timestamp);
        if (amount && time !== null) flows.push({ time, amount: -amount });
      }
    }
    if (isOpen(row)) {
      const value = numberValue(row.marketValueUsd);
      if (value === null) known = false;
      else excludedValue += value;
    }
  }
  const netAssetValue = numberValue(payload.accountIdentity?.netAssetValueUsd);
  if (netAssetValue === null || asOf === null) return { flows, known: false };
  flows.push({ time: asOf, amount: netAssetValue - excludedValue });
  return { flows, known };
}

/** Bisection, matching the pipeline: it cannot diverge, and a basis point is enough. */
function xirr(flows) {
  if (flows.length < 2) return null;
  if (!flows.some((flow) => flow.amount > 0)) return null;
  if (!flows.some((flow) => flow.amount < 0)) return null;
  const start = Math.min(...flows.map((flow) => flow.time));
  // 31 557 600 seconds is a Julian year, the same divisor the pipeline uses; 365
  // would put this a fraction of a basis point away from the account figure.
  const dated = flows.map((flow) => ({
    years: (flow.time - start) / 31_557_600_000,
    amount: flow.amount,
  }));
  const presentValue = (rate) =>
    dated.reduce((sum, item) => sum + item.amount / (1 + rate) ** item.years, 0);
  let low = -0.9999;
  let high = 10;
  const lowValue = presentValue(low);
  if (lowValue * presentValue(high) > 0) return null;
  for (let step = 0; step < 200; step += 1) {
    const middle = (low + high) / 2;
    const value = presentValue(middle);
    if (Math.abs(value) < 1e-9) return middle;
    if (lowValue * value <= 0) high = middle;
    else low = middle;
  }
  return (low + high) / 2;
}

/**
 * Everything the narrowed blocks need, computed once per scope rather than once per
 * caller. The hero, the buildup and the timeline each ask for it during one redraw,
 * and the money-weighted return is a two-hundred-step bisection over every execution
 * in the account: recomputing it three times made switching classes visibly slow.
 */
let scopeCache = null;

function scopeSummary(payload) {
  const key = `${payload.generatedAt}|${[...state.assetScope].sort().join(",")}`;
  if (scopeCache && scopeCache.key === key) return scopeCache.value;
  const all = payload.rows || [];
  const rows = all.filter(inScope);
  const excluded = all.filter((row) => !inScope(row));
  const sum = (field) => rows.reduce((total, row) => total + (numberValue(row[field]) || 0), 0);
  const instrumentResult = sum("totalResultUsd");
  const droppedResult = excluded.reduce(
    (total, row) => total + (numberValue(row.totalResultUsd) || 0), 0);

  // The headline is the account result less what was excluded, not the sum of what
  // was kept: broker interest was earned, account fees were paid and currencies were
  // converted no matter which classes are ticked, and dropping them would understate
  // the account by nearly twenty thousand dollars.
  const accountResult = numberValue(payload.accountIdentity?.accountResultUsd);
  const asOf = timeValue(payload.generatedAt);
  const { flows, known } = carveOutFlows(payload, excluded, asOf);
  const value = {
    rows,
    excluded,
    narrowed: scopeNarrowed(),
    label: scopeLabel(),
    instrumentResult,
    result: accountResult === null ? instrumentResult : accountResult - droppedResult,
    realized: sum("realizedPnlUsd"),
    unrealized: sum("unrealizedPnlUsd"),
    dividends: sum("dividendsNetUsd"),
    fees: sum("otherFeesUsd"),
    openCount: rows.filter(isOpen).length,
    moneyWeighted: known ? xirr(flows) : null,
  };
  scopeCache = { key, value };
  return value;
}

const byId = (id) => document.getElementById(id);
const unlockView = byId("unlockView");
const dashboardView = byId("dashboardView");
const unlockForm = byId("unlockForm");
const passwordInput = byId("passwordInput");
const unlockButton = byId("unlockButton");
const unlockMessage = byId("unlockMessage");
const rememberDevice = byId("rememberDevice");
const portfolioBody = byId("portfolioBody");

function bytesFromBase64(value) {
  const binary = atob(value);
  // A preallocated loop rather than Uint8Array.from with a callback: the callback
  // form was the single slowest step in unlocking, well ahead of key derivation.
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function inflate(bytes) {
  if (typeof DecompressionStream !== "function") {
    throw new Error("Этот браузер не умеет распаковывать gzip. Обновите браузер.");
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function keyId(envelope) {
  return `${envelope.kdf.salt}:${envelope.kdf.iterations}:${envelope.kdf.hash}`;
}

async function deriveKey(password, envelope) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: bytesFromBase64(envelope.kdf.salt),
      iterations: envelope.kdf.iterations,
      hash: envelope.kdf.hash,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function decryptEnvelope(envelope, key) {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytesFromBase64(envelope.cipher.iv),
      additionalData: bytesFromBase64(envelope.cipher.aad),
      tagLength: 128,
    },
    key,
    bytesFromBase64(envelope.ciphertext),
  );
  const body = String(envelope.compression || "none") === "gzip"
    ? await inflate(new Uint8Array(decrypted))
    : new Uint8Array(decrypted);
  return JSON.parse(new TextDecoder().decode(body));
}

function openKeyDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("portfolio-ledger-keys", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("keys", { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function withKeyStore(mode, operation) {
  const database = await openKeyDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction("keys", mode);
      const request = operation(transaction.objectStore("keys"));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    database.close();
  }
}

async function saveDeviceKey(envelope, key) {
  await withKeyStore("readwrite", (store) => store.put({
    id: keyId(envelope),
    key,
    savedAt: new Date().toISOString(),
  }));
}

async function loadDeviceKey(envelope) {
  const record = await withKeyStore("readonly", (store) => store.get(keyId(envelope)));
  if (!record?.key) {
    // A miss means the envelope's salt or iteration count changed, so every stored
    // key is now undecryptable dead weight. Leaving them would accumulate usable key
    // material for old payloads on the device, one per change, forever.
    await forgetDeviceKeys();
    return null;
  }
  const savedAt = Date.parse(record.savedAt || "");
  if (!Number.isFinite(savedAt) || Date.now() - savedAt > DEVICE_KEY_MAX_AGE_MS) {
    await forgetDeviceKeys();
    return null;
  }
  return record.key;
}

async function forgetDeviceKeys() {
  await withKeyStore("readwrite", (store) => store.clear());
}

async function loadEnvelope({ bypassCache = false } = {}) {
  // The initial load may come from the HTTP cache; an explicit refresh must not.
  const response = await fetch("data/portfolio.enc", {
    cache: bypassCache ? "reload" : "default",
  });
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error("Данные ещё не опубликованы. Сначала запустите workflow в приватном репозитории.");
    }
    throw new Error(`Не удалось загрузить зашифрованные данные (${response.status}).`);
  }
  const envelope = await response.json();
  if (envelope.format !== "ibkr-portfolio-aes-gcm"
    || !SUPPORTED_ENVELOPE_VERSIONS.includes(envelope.version)) {
    throw new Error("Неподдерживаемый формат зашифрованных данных.");
  }
  state.envelope = envelope;
  return envelope;
}

function numberValue(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  // Negative zero is arithmetically zero but prints as "-0,00 $", which reads as a
  // real charge of nothing and made a zero tax line look like a mistake.
  return Object.is(parsed, -0) ? 0 : parsed;
}

// Intl formatters are expensive to build and were being rebuilt thousands of times
// per render, which was the actual cause of the sluggish filtering.
const numberFormatters = new Map();
const moneyFormatters = new Map();

function numberFormatter(maximumFractionDigits, minimumFractionDigits = 0) {
  const key = `${maximumFractionDigits}:${minimumFractionDigits}`;
  if (!numberFormatters.has(key)) {
    numberFormatters.set(key, new Intl.NumberFormat("ru-RU", {
      maximumFractionDigits,
      minimumFractionDigits,
    }));
  }
  return numberFormatters.get(key);
}

function moneyFormatter(currency, showCode, digits = 2) {
  const key = `${currency}:${showCode}:${digits}`;
  if (!moneyFormatters.has(key)) {
    let formatter;
    try {
      formatter = new Intl.NumberFormat("ru-RU", {
        style: "currency",
        currency,
        currencyDisplay: showCode ? "code" : "narrowSymbol",
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      });
    } catch {
      formatter = null;
    }
    moneyFormatters.set(key, formatter);
  }
  return moneyFormatters.get(key);
}

function formatNumber(value, maximumFractionDigits = 4) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  return numberFormatter(maximumFractionDigits).format(parsed);
}

/**
 * Money is always shown with its currency spelled out unless it is the base currency.
 * A narrow symbol renders USD, CAD and AUD all as "$", which makes three different
 * amounts look like the same one.
 */
function formatMoney(value, currency = "USD", showCode = null, digits = 2) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  const code = String(currency || "USD").toUpperCase();
  const withCode = showCode === null ? code !== "USD" : showCode;
  const formatter = moneyFormatter(code, withCode, digits);
  if (!formatter) return `${formatNumber(parsed, digits)} ${code}`;
  return formatter.format(parsed);
}

/**
 * PXT's second cycle bought at 18.23, sold at 17.64 and still made money: the shares
 * paid 3999.04 CAD while they were held, and nothing on the card said so — the two
 * prices sat there implying a loss. Dividing the cycle's dividends by the quantity
 * bought puts the payout in the same unit as the prices beside it, so the sign of the
 * result stops reading as a contradiction.
 *
 * The divisor is the entry quantity rather than the exit quantity because an open
 * cycle has exited nothing — four of them would divide by zero — and because it is
 * the quantity the payout was actually earned on.
 *
 * Two decimals is not enough at this scale: per-share payouts here run from 0.0024 to
 * 46.58, and 52 of 170 fall below a tenth of a unit.
 */
function perShareDividend(cycle, currency) {
  const total = numberValue(cycle.dividendsNet);
  const quantity = numberValue(cycle.entryQuantityTotal);
  if (!total || !quantity) return null;
  const perShare = total / quantity;
  const magnitude = Math.abs(perShare);
  const digits = magnitude >= 1 ? 2 : magnitude >= 0.1 ? 3 : 4;
  return {
    text: formatMoney(perShare, currency, true, digits),
    total: formatMoney(total, currency, true),
  };
}

function formatUsd(value) {
  return formatMoney(value, "USD", false);
}

/**
 * Inside the table the five money columns already say USD in their headers, so the
 * symbol is dropped there and only there: repeated 253 times down five columns it
 * was pure noise competing with the digits it sat next to.
 */
function formatUsdCell(value) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  return numberFormatter(2, 2).format(parsed);
}

function formatSignedUsd(value) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  return parsed > 0 ? `+${formatUsd(parsed)}` : formatUsd(parsed);
}

/**
 * Commissions and transaction taxes are stored as signed costs, where a charge is
 * positive. Shown that way they read as income, so they are negated for display.
 */
function formatCost(value) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  return formatUsd(-parsed || 0);
}

function formatPercent(value, digits = 2, minimumDigits = 0) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  return `${numberFormatter(digits, minimumDigits).format(parsed * 100)} %`;
}

const dateFormatters = new Map();

function dateFormatter(includeTime, timeZone) {
  const key = `${includeTime}:${timeZone || "local"}`;
  if (!dateFormatters.has(key)) {
    dateFormatters.set(key, new Intl.DateTimeFormat("ru-RU", {
      year: "numeric",
      month: "short",
      day: "2-digit",
      ...(includeTime ? { hour: "2-digit", minute: "2-digit" } : {}),
      ...(timeZone ? { timeZone } : {}),
    }));
  }
  return dateFormatters.get(key);
}

const ZONED = /(?:Z|[+-]\d{2}:?\d{2})$/;

/**
 * Real instants are shown in the viewer's own timezone.
 *
 * Flex trade times are the exception: they carry no offset because they are wall-clock
 * in the report's configured timezone. Those are printed exactly as reported, since
 * converting a time whose zone is unknown would move it by an arbitrary amount.
 */
function formatDate(value, includeTime = false) {
  if (!value) return "—";
  const text = String(value);
  if (!ZONED.test(text)) {
    // No offset: render the wall clock as the broker stated it.
    const naive = new Date(`${text}Z`);
    if (Number.isNaN(naive.getTime())) return escapeHtml(text);
    return dateFormatter(includeTime, "UTC").format(naive);
  }
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return escapeHtml(text);
  return dateFormatter(includeTime, undefined).format(parsed);
}

const shortDateFormatters = new Map();

function shortDateFormatter(pattern, timeZone) {
  const key = `${pattern}:${timeZone || "local"}`;
  if (!shortDateFormatters.has(key)) {
    shortDateFormatters.set(key, new Intl.DateTimeFormat("ru-RU", {
      day: "2-digit",
      month: "2-digit",
      ...(pattern === "date" ? { year: "2-digit" } : { hour: "2-digit", minute: "2-digit" }),
      ...(timeZone ? { timeZone } : {}),
    }));
  }
  return shortDateFormatters.get(key);
}

/**
 * The compact form used inside table cells, where "09 окт. 2023 г." spent a third
 * of the column on the word "г." and pushed the rest of the cycle out of view.
 * The timezone rule is the same one `formatDate` follows.
 */
function formatDateShort(value, pattern = "date") {
  if (!value) return "—";
  const text = String(value);
  const zoned = ZONED.test(text);
  const parsed = new Date(zoned ? text : `${text}Z`);
  if (Number.isNaN(parsed.getTime())) return escapeHtml(text);
  return shortDateFormatter(pattern, zoned ? undefined : "UTC").format(parsed);
}

/** Milliseconds for a payload timestamp, zoned or naive, or null. */
function timeValue(value) {
  if (!value) return null;
  const text = String(value);
  const parsed = Date.parse(ZONED.test(text) ? text : `${text}Z`);
  return Number.isFinite(parsed) ? parsed : null;
}

function pnlClass(value) {
  const parsed = numberValue(value);
  if (parsed === null || parsed === 0) return "muted-value";
  return parsed > 0 ? "positive" : "negative";
}

/* ------------------------------------------------------------------ theme --- */

const THEME_KEY = "portfolio-ledger:theme";

function storedTheme() {
  try {
    return window.localStorage.getItem(THEME_KEY);
  } catch {
    return null;
  }
}

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "light" || theme === "dark") {
    root.setAttribute("data-theme", theme);
  } else {
    root.removeAttribute("data-theme");
  }
  const dark = theme === "dark" || (theme !== "light"
    && window.matchMedia("(prefers-color-scheme: dark)").matches);
  byId("themeIcon").textContent = dark ? "☾" : "☀";
  byId("themeLabel").textContent = dark ? "Тёмная" : "Светлая";
  document.querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", dark ? "#070e17" : "#f2f5f8");
  return dark;
}

applyTheme(storedTheme());

byId("themeButton").addEventListener("click", () => {
  const next = applyTheme(storedTheme()) ? "light" : "dark";
  try {
    window.localStorage.setItem(THEME_KEY, next);
  } catch {
    /* private mode: the choice simply does not persist */
  }
  applyTheme(next);
  if (state.payload) renderCharts();
});

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (!storedTheme()) applyTheme(null);
});

/* ------------------------------------------------------------- collapsing --- */

// The instrument table is the block the owner actually works in; everything above it
// is context that can be folded away to a single strip. The choice is remembered,
// because having to re-fold six panels on every visit is worse than not having the
// control at all.
const COLLAPSE_KEY = "portfolio-ledger:collapsed";
const COLLAPSIBLE = ["hero", "buildup", "timeline", "allocation", "extremes", "account", "issues"];

function collapsedSet() {
  try {
    const stored = JSON.parse(window.localStorage.getItem(COLLAPSE_KEY) || "[]");
    return new Set(Array.isArray(stored) ? stored.filter((key) => COLLAPSIBLE.includes(key)) : []);
  } catch {
    return new Set();
  }
}

function storeCollapsed(keys) {
  try {
    window.localStorage.setItem(COLLAPSE_KEY, JSON.stringify([...keys]));
  } catch {
    /* private mode: the choice simply does not persist */
  }
}

function applyCollapsed() {
  const collapsed = collapsedSet();
  for (const key of COLLAPSIBLE) {
    const section = document.querySelector(`[data-collapse="${key}"]`);
    if (!section) continue;
    const isCollapsed = collapsed.has(key);
    section.classList.toggle("is-collapsed", isCollapsed);
    const button = section.querySelector(`[data-collapse-for="${key}"]`);
    if (button) {
      button.setAttribute("aria-expanded", String(!isCollapsed));
      button.firstElementChild.textContent = isCollapsed ? "+" : "−";
      button.title = isCollapsed ? "Развернуть блок" : "Свернуть блок";
    }
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-collapse-for]");
  if (!button) return;
  const key = button.dataset.collapseFor;
  const collapsed = collapsedSet();
  if (collapsed.has(key)) collapsed.delete(key);
  else collapsed.add(key);
  storeCollapsed(collapsed);
  applyCollapsed();
  alignHeroSide();
  // A chart drawn inside a hidden panel measured zero and fell back to 320 px, so
  // whatever was just revealed has to be redrawn at its real width.
  if (state.payload && !collapsed.has(key)) renderCharts();
});

/* --------------------------------------------------------------- totals ----- */

const AGGREGATE_FIELDS = [
  "marketValueUsd",
  "openBasisUsd",
  "unrealizedPnlUsd",
  "realizedPnlUsd",
  "dividendsNetUsd",
  "otherFeesUsd",
  "totalResultUsd",
];

function aggregateRows(rows) {
  const totals = Object.fromEntries(AGGREGATE_FIELDS.map((field) => [field, 0]));
  let partial = false;

  for (const row of rows) {
    for (const field of AGGREGATE_FIELDS) {
      const value = numberValue(row[field]);
      if (value !== null) totals[field] += value;
    }
    if (isOpen(row) && [row.marketValueUsd, row.openBasisUsd, row.unrealizedPnlUsd]
      .some((value) => numberValue(value) === null)) {
      partial = true;
    }
  }
  return { totals, partial };
}

function filterContext(rows) {
  const total = state.payload?.rows?.length || 0;
  const tabLabels = { open: "Открытые", closed: "Закрытые", review: "Требуют проверки" };
  const parts = [];
  if (tabLabels[state.activeTab]) parts.push(tabLabels[state.activeTab]);
  const search = byId("searchInput").value.trim();
  if (search) parts.push(`поиск «${search}»`);
  for (const id of ["directionFilter", "currencyFilter", "profitFilter", "yearFilter"]) {
    const select = byId(id);
    if (select.value) parts.push(select.selectedOptions[0]?.textContent || select.value);
  }
  if (scopeNarrowed()) parts.unshift(scopeLabel());
  return `${rows.length} из ${total}${parts.length ? ` · ${parts.join(" · ")}` : " · все инструменты"}`;
}

function isFiltered(rows) {
  // A year can leave the row count untouched while changing every figure in them, so
  // the count alone cannot decide whether these totals are comparable to the payload's.
  if (byId("yearFilter").value) return true;
  return rows.length !== (state.payload?.rows?.length || 0);
}

function renderKpis(payload, rows) {
  const { totals, partial } = aggregateRows(rows);
  // Under a year the three position cards have nothing to add up: the rows carry no
  // market value, basis or unrealised, because those describe today and belong to no
  // year. Zero would read as "worth nothing" rather than "does not apply".
  const year = byId("yearFilter").value;
  const position = (value, note) => (year ? [null, "не относится к году"] : [value, note]);
  const cards = [
    ["Рыночная стоимость", ...position(totals.marketValueUsd, "Открытые позиции")],
    ["Себестоимость, AVCO", ...position(totals.openBasisUsd, "По курсам на дату покупки")],
    ["Нереализованный P&L", ...position(totals.unrealizedPnlUsd, "Текущий")],
    ["Реализованный P&L", totals.realizedPnlUsd, year ? `Закрыто в ${year}` : "Закрытые объёмы"],
    ["Чистые дивиденды", totals.dividendsNetUsd, year ? `Получено в ${year}` : "После налогов"],
    ["Итог по инструментам", totals.totalResultUsd,
      year ? `За ${year}, без нереализованного` : "Без процентов и валютных конверсий"],
  ];
  byId("kpiContext").textContent = filterContext(rows);
  byId("kpiGrid").innerHTML = cards.map(([label, value, note]) => `
    <article class="kpi-card">
      <span>${escapeHtml(label)}</span>
      <strong class="${label.includes("P&L") || label.includes("Итог") ? pnlClass(value) : ""}">${formatUsd(value)}</strong>
      ${(note || partial) ? `<small>${escapeHtml(note)}${partial ? `${note ? " · " : ""}не хватает цен или курсов` : ""}</small>` : ""}
    </article>
  `).join("");
  renderTotalsCheck(payload, rows, totals);
}

/**
 * The cards deliberately reflect the active filter. That makes them impossible to
 * compare against the payload totals unless nothing is filtered out — which is
 * exactly when a mismatch would mean the frontend and the pipeline disagree.
 */
function renderTotalsCheck(payload, rows, totals) {
  const banner = byId("totalsCheck");
  if (isFiltered(rows)) {
    banner.hidden = true;
    return;
  }
  const published = payload.totals || {};
  const drifted = AGGREGATE_FIELDS
    .map((field) => {
      const mine = totals[field];
      const theirs = numberValue(published[field]);
      if (theirs === null) return null;
      return Math.abs(mine - theirs) > 0.01 ? { field, mine, theirs } : null;
    })
    .filter(Boolean);
  banner.hidden = drifted.length === 0;
  if (drifted.length) {
    banner.innerHTML = drifted.map((item) => `
      <div class="issue-item error">
        <span class="severity">ERROR</span>
        <span class="issue-type">${escapeHtml(item.field)}</span>
        <span class="issue-message">Сумма по строкам ${formatUsd(item.mine)} не совпадает с опубликованным итогом ${formatUsd(item.theirs)}</span>
      </div>
    `).join("");
  }
}

/* ------------------------------------------------------------------- hero --- */

const IDENTITY_LABELS = {
  BALANCED: ["ok", "Итог сходится со счётом"],
  REVIEW: ["warning", "Итог почти сходится со счётом"],
  MISMATCH: ["error", "Итог не сходится со счётом"],
  INCOMPLETE: ["warning", "Итог проверить нельзя: не хватает данных"],
  UNAVAILABLE: ["warning", "Итог проверить нельзя: нет отчёта по кэшу"],
  // A payload published before the account blocks existed at all. Saying "нет отчёта
  // по кэшу" here would send the owner to fix the Flex query, when what is actually
  // stale is the snapshot.
  NO_ACCOUNT_BLOCK: ["warning", "Данные счёта в этом снимке отсутствуют"],
};

const IDENTITY_HINTS = {
  BALANCED: "разница укладывается в переоценку валютных остатков",
  NO_ACCOUNT_BLOCK: "снимок опубликован до этой версии учёта — запустите синхронизацию",
  UNAVAILABLE: "в Activity Flex нет секции Cash Report",
};

/**
 * One number leads the page: what the account has earned since the first deposit.
 * Everything beside it exists to say what that number is made of and how much of
 * it can be trusted.
 */
function renderHero(payload) {
  const identity = payload.accountIdentity || {};
  const performance = payload.performance || {};
  const allocation = payload.allocation || {};
  const status = payload.status || {};
  const rows = payload.rows || [];

  const scope = scopeSummary(payload);
  const result = numberValue(identity.accountResultUsd);
  const fallback = result === null ? numberValue(payload.totals?.totalResultUsd) : null;
  // Narrowed, the headline is what the chosen instruments made. It cannot be the
  // account result: that one includes interest, account fees and the currency
  // conversions, none of which belong to an asset class.
  const headline = scope.narrowed ? scope.result : (result === null ? fallback : result);
  const contributions = numberValue(identity.netContributionsUsd);
  const returnOnMoney = contributions ? headline / Math.abs(contributions) : null;
  const identityStatus = payload.accountIdentity ? identity.status : "NO_ACCOUNT_BLOCK";
  const [tone, identityLabel] = IDENTITY_LABELS[identityStatus] || IDENTITY_LABELS.UNAVAILABLE;

  // An older snapshot carries `cash` but none of the account blocks. Reading the
  // balance from `cash` as well means the page shows what it has instead of a dash.
  const marketValue = numberValue(identity.marketValueUsd)
    ?? numberValue(payload.totals?.marketValueUsd) ?? 0;
  const cash = numberValue(identity.endingCashUsd)
    ?? (payload.cash?.available ? numberValue(payload.cash.endingCash) : null);
  const netAssetValue = numberValue(identity.netAssetValueUsd)
    ?? (cash === null ? null : marketValue + cash);
  // With no cash report and nothing open there is no split to show, and a meter of
  // one empty segment claims a composition the payload does not have.
  const hasComposition = cash !== null || marketValue !== 0;
  // Cash keeps slot 1 and instruments slot 2 here and in the asset-class strip, so
  // the same thing is the same colour in both charts.
  const meterSegments = cash === null
    ? [{ label: "Позиции", value: marketValue, slot: 2, display: formatUsd(marketValue) }]
    : [
      { label: "Позиции", value: Math.max(0, marketValue), slot: 2, display: formatUsd(marketValue) },
      { label: "Кэш", value: Math.max(0, cash), slot: 1, display: formatUsd(cash) },
    ];

  const openCount = scope.narrowed
    ? scope.openCount
    : Number(status.openPositionCount || rows.filter(isOpen).length);
  // A dash says nothing about why. Where a figure is missing because the snapshot
  // never carried it, the tile says which section of the report would supply it.
  const missingHint = payload.accountIdentity
    ? "нет событий Deposits/Withdrawals в Activity Flex"
    : "нет в этом снимке — нужна свежая синхронизация";
  // Narrowing changes two values and nothing else. The row keeps its four cards, its
  // labels and its one-line shape: an explanation added under one card and not the
  // others knocks the row out of line, and the plate beside it already says what the
  // page is showing.
  const returnRate = scope.narrowed ? scope.moneyWeighted : performance.moneyWeightedReturn;
  const facts = [
    ["Внесено минус выведено", formatUsd(identity.netContributionsUsd), "",
      contributions === null ? missingHint : ""],
    ["Сейчас на счёте", formatUsd(netAssetValue), "",
      netAssetValue === null ? (payload.accountIdentity ? "нет секции Cash Report" : missingHint) : ""],
    ["Годовая доходность, XIRR", formatPercent(returnRate), pnlClass(returnRate),
      numberValue(returnRate) === null && !scope.narrowed ? missingHint : ""],
    ["Открытых позиций", `${openCount} из ${scope.narrowed ? scope.rows.length : rows.length}`, "", ""],
  ];

  byId("heroPanel").innerHTML = `
    <button class="collapse-toggle hero-collapse" type="button" data-collapse-for="hero"
      aria-label="Свернуть или развернуть блок"><span aria-hidden="true">−</span></button>
    <div class="hero-main">
      <p class="eyebrow">${scope.narrowed
        ? `Заработано за всё время · ${escapeHtml(scope.label)}`
        : "Заработано за всё время"}</p>
      <p class="hero-figure ${pnlClass(headline)}">${formatSignedUsd(headline)}</p>
      <p class="hero-sub">
        ${returnOnMoney === null ? "" : `<span class="hero-badge ${pnlClass(returnOnMoney)}">${escapeHtml(returnOnMoney > 0 ? "+" : "")}${formatPercent(returnOnMoney, 1, 1)} к внесённым деньгам</span>`}
        ${performance.firstFundingAt ? `<span class="hero-note">с ${formatDate(performance.firstFundingAt)}</span>` : ""}
      </p>
      <div class="hero-facts">
        ${facts.map(([label, value, valueTone, hint]) => `
          <div${hint ? ` title="${escapeHtml(hint)}"` : ""}><span>${escapeHtml(label)}</span><strong class="${valueTone}">${value}</strong>${hint ? `<small>${escapeHtml(hint)}</small>` : ""}</div>
        `).join("")}
      </div>
    </div>
    <div class="hero-side">
      ${hasComposition ? `<div class="hero-meter">
        <div class="hero-meter-head">
          <span>Из чего состоит счёт</span>
          <strong>${formatUsd(netAssetValue)}</strong>
        </div>
        <div id="heroMeter" class="chart-host chart-host-strip" data-chart="meter"></div>
        <div class="legend">
          ${meterSegments.map((segment, index) => `
            <span class="legend-item">
              <i class="legend-swatch series-${segment.slot}"></i>
              ${escapeHtml(segment.label)}
              <b>${segment.display}</b>
              ${index === 1 && allocation.cashShare != null ? `<em>${formatPercent(allocation.cashShare, 0)}</em>` : ""}
            </span>
          `).join("")}
        </div>
      </div>` : ""}
      <div class="hero-check tone-${tone}">
        <span class="hero-check-dot" aria-hidden="true"></span>
        <span>
          <strong>${escapeHtml(identityLabel)}</strong>
          <small>${identity.differenceUsd == null
            ? escapeHtml(IDENTITY_HINTS[identityStatus] || "сверка со счётом недоступна")
            : `расхождение ${formatUsd(identity.differenceUsd)} при допуске ${formatUsd(identity.toleranceUsd)}`}</small>
        </span>
      </div>
    </div>
  `;
  state.charts.set("meter", { segments: meterSegments });
}

/* ---------------------------------------------------------------- derived --- */

/**
 * What the lifetime result is made of, in the order the pipeline itself composes it:
 * instruments first, then everything that never belonged to a position.
 */
function buildupItems(payload) {
  const scope = scopeSummary(payload);
  // Account-level components stay whatever the filter is: interest accrued, fees were
  // charged and currencies were converted regardless of which classes are ticked.
  const accountCash = payload.accountCash || {};
  // Narrowed, every component is re-summed over the chosen rows. Reading them from
  // `totals` would print account-wide numbers under a heading that promises a subset.
  const totals = scope.narrowed
    ? {
      realizedPnlUsd: scope.realized,
      unrealizedPnlUsd: scope.unrealized,
      dividendsNetUsd: scope.dividends,
      dividendsGrossUsd: scope.rows.reduce(
        (sum, row) => sum + (numberValue(row.dividendsGrossUsd) || 0), 0),
      withholdingTaxUsd: scope.rows.reduce(
        (sum, row) => sum + (numberValue(row.withholdingTaxUsd) || 0), 0),
      instrumentFeesUsd: scope.fees,
      commissionsUsd: scope.rows.reduce(
        (sum, row) => sum + (numberValue(row.commissionsUsd) || 0), 0),
      fxRealizedPnlUsd: scope.rows.reduce(
        (sum, row) => sum + (numberValue(row.fxRealizedPnlUsd) || 0), 0),
    }
    : (payload.totals || {});
  const commissions = numberValue(totals.commissionsUsd);
  const fxRealized = numberValue(totals.fxRealizedPnlUsd);
  const items = [
    {
      label: "Реализованный P&L",
      value: numberValue(totals.realizedPnlUsd) || 0,
      note: [
        commissions ? `комиссии уже вычтены: ${formatCost(commissions)}` : null,
        fxRealized ? `валютная часть ${formatSignedUsd(fxRealized)}` : null,
      ].filter(Boolean).join(" · "),
    },
    {
      label: "Нереализованный P&L",
      value: numberValue(totals.unrealizedPnlUsd) || 0,
      note: "по последним известным ценам",
    },
    {
      label: "Дивиденды net",
      value: numberValue(totals.dividendsNetUsd) || 0,
      note: `gross ${formatUsd(totals.dividendsGrossUsd)} · налог ${formatUsd(totals.withholdingTaxUsd)}`,
    },
  ];
  const instrumentFees = numberValue(totals.instrumentFeesUsd);
  if (instrumentFees) {
    items.push({ label: "Сборы по инструментам", value: instrumentFees, note: "" });
  }
  items.push({
    label: "Итог по инструментам",
    kind: "total",
    note: scope.narrowed
      ? `сумма строк выбранных классов: ${scope.label}`
      : "сумма всех строк таблицы",
  });

  const extras = [
    ["Проценты брокера", accountCash.interestUsd, "начислены на остаток"],
    ["Сборы по счёту", accountCash.accountFeesUsd, "подписки и обслуживание"],
    ["Валютные конверсии", accountCash.currencyResultUsd, "результат обмена валют"],
    ["Прочий кэш", accountCash.otherCashUsd, ""],
    ["Неклассифицированный кэш", accountCash.unclassifiedCashUsd,
      `${Number(accountCash.unclassifiedCashCount || 0)} событий`],
  ];
  let hasAccountLevel = false;
  for (const [label, raw, note] of extras) {
    const value = numberValue(raw);
    if (value) {
      items.push({ label, value, note });
      hasAccountLevel = true;
    }
  }
  // The second total only means something once something has been added after the
  // first one. With no account-level components it repeats the line above it
  // verbatim, and a table that states the same number twice reads like an error.
  if (hasAccountLevel) {
    // Everything above is booked at the rates of the day it happened. The account is
    // worth what it is worth today, and foreign cash that was never converted sits
    // between the two. Leaving it out ended the table 333 dollars away from the
    // headline with nothing to say why.
    const residual = numberValue(payload.accountIdentity?.differenceUsd);
    if (residual) {
      items.push({
        label: "Переоценка валютных остатков",
        value: residual,
        note: "непереведённые остатки в AUD, CAD, GBP и JPY стоят сегодня иначе, чем в день, когда попали на счёт",
      });
    }
    items.push({
      label: residual ? "Заработано за всё время" : "Итог по счёту",
      kind: "total",
      note: residual
        ? "то же число, что в шапке"
        : "инструменты плюс то, что не принадлежит ни одной позиции",
    });
  }
  return items;
}

/**
 * Realised money on the date it was actually realised: a closed cycle's P&L at the
 * moment it closed, a dividend on the day it was earned. Unrealised P&L is
 * deliberately absent — it has no date, and pinning it to today would draw a jump
 * that never happened.
 */
function realisedTimeline(payload) {
  const buckets = new Map();
  let dated = 0;
  let undated = 0;

  const add = (time, amount) => {
    if (!amount) return;
    if (time === null) {
      undated += amount;
      return;
    }
    const date = new Date(time);
    const key = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1);
    buckets.set(key, (buckets.get(key) || 0) + amount);
    dated += amount;
  };

  for (const row of scopedRows()) {
    for (const cycle of row.cycles || []) {
      // Each sale is dated by the day it happened. Hanging a cycle's whole result on
      // the day it finally closed moved real money between calendar years — a position
      // sold down across 2023, 2024 and 2025 counted entirely in 2025, and the yearly
      // columns were out by tens of thousands even though the total was right.
      const dated = (cycle.trades || []).filter((trade) => trade.realizedUsd != null);
      if (dated.length) {
        for (const trade of dated) {
          add(timeValue(trade.timestamp), numberValue(trade.realizedUsd) || 0);
        }
      } else {
        // A snapshot published before executions carried their own result.
        const realized = numberValue(cycle.realizedPnlUsd) || 0;
        if (realized) {
          const exits = (cycle.trades || []).filter((trade) => trade.action === "EXIT");
          const at = cycle.closedAt || exits[exits.length - 1]?.timestamp || cycle.openedAt;
          add(timeValue(at), realized);
        }
      }
      for (const event of cycle.cashEvents || []) {
        if (!["DIVIDEND", "WITHHOLDING_TAX", "FEE"].includes(String(event.category || ""))) continue;
        add(timeValue(event.exDate || event.timestamp), numberValue(event.amountUsd) || 0);
      }
    }
  }

  // Interest, account fees and the result of each currency conversion are dated, so
  // they belong on a line that claims to be cumulative. They are not attributable to
  // an asset class, so they stay whatever the scope is — the same rule the
  // composition block follows. Unrealised P&L is the one thing that cannot be here:
  // it would need the market value of every position on every past day.
  for (const flow of payload.accountCashFlows || []) {
    add(timeValue(flow.timestamp), numberValue(flow.amountUsd) || 0);
  }

  const months = [...buckets.entries()].sort((left, right) => left[0] - right[0]);
  const points = [];
  let cumulative = 0;
  for (const [time, amount] of months) {
    cumulative += amount;
    points.push({ time, value: cumulative, delta: amount });
  }
  if (points.length) {
    // Start the line at zero one month before the first realisation, so the first
    // month reads as a step up from nothing rather than as the baseline.
    const first = new Date(points[0].time);
    points.unshift({
      time: Date.UTC(first.getUTCFullYear(), first.getUTCMonth() - 1, 1),
      value: 0,
      delta: 0,
    });
  }

  const years = new Map();
  for (const [time, amount] of months) {
    const year = new Date(time).getUTCFullYear();
    years.set(year, (years.get(year) || 0) + amount);
  }

  /*
   * The percent view is the same curve against one fixed base: everything the account
   * was ever given, net of what was taken out.
   *
   * Dividing by the money contributed *by that date* was tried first and is what a
   * money-weighted return would do, but it puts a small denominator under the earliest
   * months: a few hundred dollars of result on the first deposit is a double-digit
   * percentage, so the ratio opened with a spike the dollars did not have and the two
   * modes disagreed about the shape of the same history. One base keeps the shape
   * identical and leaves the axis the only thing that changes.
   */
  const flows = (payload.cashFlows || [])
    .map((flow) => ({ time: timeValue(flow.timestamp), amount: numberValue(flow.amountUsd) || 0 }))
    .filter((flow) => flow.time !== null);
  const contributed = flows.reduce((sum, flow) => sum + flow.amount, 0);
  const share = (value) => (contributed > 0 ? value / contributed : null);

  // The self-check has to be summed over the same rows the line was built from, or
  // a narrowed page reports its own filter as missing data.
  const scoped = scopedRows();
  const sumRows = (key) =>
    scoped.reduce((total, row) => total + (numberValue(row[key]) || 0), 0);
  const expected = sumRows("realizedPnlUsd")
    + sumRows("dividendsNetUsd")
    + sumRows("otherFeesUsd")
    + (payload.accountCashFlows || [])
      .reduce((total, flow) => total + (numberValue(flow.amountUsd) || 0), 0);
  const yearList = [...years.entries()].sort((left, right) => left[0] - right[0]);
  return {
    points,
    percentPoints: contributed > 0
      ? points.map((point) => ({ time: point.time, value: share(point.value), delta: share(point.delta) }))
      : [],
    percentAvailable: contributed > 0 && points.length >= 2,
    percentBase: contributed > 0 ? contributed : null,
    years: yearList.map(([year, value]) => ({ label: String(year), value })),
    percentYears: contributed > 0
      ? yearList.map(([year, value]) => ({ label: String(year), value: share(value) }))
      : [],
    dated,
    undated,
    expected,
  };
}

const ASSET_CLASS_LABELS = {
  STK: "Акции и ETF",
  OPT: "Опционы",
  FUT: "Фьючерсы",
  FOP: "Опционы на фьючерсы",
  BOND: "Облигации",
  FUND: "Фонды",
  WAR: "Варранты",
  CFD: "CFD",
  CASH: "Валюта",
};

// Colour follows the entity, never its size: a class keeps its slot when the mix
// changes, so a reader who learned "опционы оранжевые" stays right.
const ASSET_CLASS_SLOTS = { CASH: 1, STK: 2, OPT: 3, FUT: 4, BOND: 5, FUND: 6, FOP: 7, WAR: 8, CFD: 8 };

function allocationModel(payload) {
  const open = (payload.rows || []).filter((row) => isOpen(row)
    && numberValue(row.marketValueUsd) !== null);
  const exposure = open.reduce((sum, row) => sum + Math.abs(numberValue(row.marketValueUsd)), 0);
  const cash = numberValue(payload.allocation?.cashUsd);
  // The signed market value, so positions and cash add up to the account total the
  // way they do in the hero meter. Exposure counts a short twice over and belongs
  // to the risk question, not to "where is the money".
  const invested = numberValue(payload.allocation?.investedUsd)
    ?? open.reduce((sum, row) => sum + numberValue(row.marketValueUsd), 0);
  const base = numberValue(payload.allocation?.netAssetValueUsd) || (invested + (cash || 0));

  const byClass = new Map();
  for (const row of open) {
    const key = String(row.assetClass || "—");
    byClass.set(key, (byClass.get(key) || 0) + Math.abs(numberValue(row.marketValueUsd)));
  }
  const segments = [];
  if (cash !== null && cash > 0) {
    segments.push({ label: "Кэш", value: cash, slot: 1, display: formatUsd(cash) });
  }
  for (const [key, value] of [...byClass.entries()].sort((left, right) => right[1] - left[1])) {
    segments.push({
      label: ASSET_CLASS_LABELS[key] || key,
      value,
      slot: ASSET_CLASS_SLOTS[key] || 8,
      display: formatUsd(value),
    });
  }

  const ranked = open
    .map((row) => ({
      label: row.symbol || row.conid,
      value: Math.abs(numberValue(row.marketValueUsd)),
      note: row.instrument,
      share: base ? Math.abs(numberValue(row.marketValueUsd)) / base : null,
    }))
    .sort((left, right) => right.value - left.value);
  const shown = ranked.slice(0, 12);
  const rest = ranked.slice(12);
  if (rest.length) {
    const value = rest.reduce((sum, item) => sum + item.value, 0);
    shown.push({
      label: `Ещё ${rest.length}`,
      value,
      note: "остальные открытые позиции",
      share: base ? value / base : null,
      muted: true,
    });
  }
  return {
    segments,
    bars: shown.map((item) => ({
      label: item.label,
      value: item.value,
      muted: item.muted,
      note: item.note,
      display: `${compactUsdFixed(item.value)} · ${item.share === null ? "—" : percentLabel(item.share)}`,
    })),
    invested,
    exposure,
    base,
  };
}

function extremeRows(payload) {
  const scored = scopedRows()
    .map((row) => ({
      label: row.symbol || row.conid,
      // Shown in front of the ticker where the card is wide enough for it.
      secondary: row.instrument && row.instrument !== row.symbol ? row.instrument : "",
      value: numberValue(row.totalResultUsd),
      note: row.instrument,
    }))
    .filter((item) => item.value !== null && item.value !== 0)
    .sort((left, right) => right.value - left.value);
  if (scored.length <= 14) return scored;
  return [...scored.slice(0, 7), ...scored.slice(-7)];
}

/* ----------------------------------------------------------------- charts --- */

/**
 * The floor only exists so a container that is currently hidden does not produce a
 * zero-width chart; it must stay below the narrowest real card, or a phone gets a
 * chart wider than the card it sits in.
 */
function hostWidth(host) {
  // Floor below the narrowest real host (about 196 px on a 320 px phone) so the
  // minimum never becomes the thing that overflows the container.
  return Math.max(180, Math.floor(host.getBoundingClientRect().width) || 180);
}

/**
 * A host inside a collapsed panel, or behind the chart/table toggle, has no box.
 * Drawing into it bakes in the fallback width, and the ResizeObserver will not
 * correct that later: it ignores zero widths, so going hidden and back reads as
 * "unchanged" and no redraw is scheduled. So hidden hosts are simply skipped and
 * redrawn by whoever reveals them.
 */
function visibleHost(id) {
  const host = byId(id);
  if (!host) return null;
  return host.getBoundingClientRect().width > 0 ? host : null;
}

// Percent labels keep one decimal whether or not the value has one: a column reading
// "+20 %" next to "+5,7 %" looks like a different measure, not a rounder number.
const fixedPercentFormatter = new Intl.NumberFormat("ru-RU", {
  minimumFractionDigits: 1,
  maximumFractionDigits: 1,
});

function percentLabel(value, { signed = false } = {}) {
  if (!Number.isFinite(value)) return "—";
  const sign = signed && value > 0 ? "+" : "";
  return `${sign}${fixedPercentFormatter.format(value * 100)} %`;
}

/** The subtitle has to say what the percentages are a percentage of. */
function updateTimelineNote() {
  const timeline = state.charts.get("timeline");
  const percent = state.timelineMode === "percent" && timeline?.percentAvailable;
  byId("timelineNote").textContent = percent
    ? `Тот же результат в процентах от внесённых денег — от ${formatUsd(timeline.percentBase)} за всё время.`
    : (state.timelineCoverage || "");
}

function renderCharts() {
  const payload = state.payload;
  if (!payload) return;

  const items = buildupItems(payload);
  const timeline = state.charts.get("timeline");
  const allocation = state.charts.get("allocation");
  const extremes = state.charts.get("extremes");

  // Every panel's visibility is settled before anything is measured. Unhiding one
  // panel of a two-column row changes the width of the other, so a chart drawn
  // between the two calls was sized for a layout that no longer existed and
  // overflowed its card.
  byId("buildupPanel").hidden = items.length < 2;
  byId("timelinePanel").hidden = !timeline || timeline.points.length < 2;
  byId("allocationPanel").hidden = !allocation || !allocation.bars.length;
  byId("extremesPanel").hidden = !extremes || extremes.length < 2;

  const meter = state.charts.get("meter");
  const meterHost = visibleHost("heroMeter");
  if (meter && meterHost) {
    meterHost.innerHTML = splitMeter(meter.segments, hostWidth(meterHost), { height: 20 });
  }

  const buildupHost = visibleHost("buildupChart");
  if (buildupHost) buildupHost.innerHTML = waterfall(items, hostWidth(buildupHost));

  const timelineHost = visibleHost("timelineChart");
  if (timelineHost && timeline && timeline.points.length >= 2) {
    const percent = state.timelineMode === "percent" && timeline.percentAvailable;
    const series = percent ? timeline.percentPoints : timeline.points;
    const width = hostWidth(timelineHost);
    const format = percent ? (value) => sharePercent(value) : undefined;
    // In dollars the ticks carried the unit too — "400 тыс. $" against "40 %" — and
    // the axis gutter alone made the plot narrower in one mode than the other. Bare
    // ticks: the endpoint still prints the value in full, with its unit.
    const axisFormat = percent ? undefined : bareAxisFormatter;
    const chartOptions = { height: 224, format, axisFormat };
    timelineHost.innerHTML = areaChart(series, width, {
      ...chartOptions,
      label: percent
        ? "Реализованный результат к внесённым деньгам"
        : "Реализованный результат нарастающим итогом",
    });
    state.charts.set("timelineGeometry", areaGeometry(series, width, chartOptions));
    state.charts.set("timelineSeries", { points: series, percent });
    // The columns read in the same unit as the line above them: switching one and
    // leaving the other showing dollars invites reading the two together.
    const yearHost = visibleHost("yearChart");
    const years = percent ? timeline.percentYears : timeline.years;
    if (yearHost) yearHost.innerHTML = columnChart(years, hostWidth(yearHost), {
      label: percent ? "Результат года в процентах от внесённого" : "Результат по годам",
      format: percent ? (value) => percentLabel(value, { signed: true }) : undefined,
    });
  }

  const stripHost = visibleHost("classStrip");
  if (stripHost && allocation && allocation.bars.length) {
    // The strip is drawn between the same two edges as the bars beneath it: the whole
    // card then has one left edge and one right edge instead of a full-width rule over
    // an indented list.
    const stripWidth = hostWidth(stripHost);
    const columns = rankedLayout(allocation.bars, stripWidth);
    stripHost.innerHTML = `${stackedStrip(allocation.segments, stripWidth, {
      height: 20,
      left: columns.plotLeft,
      span: columns.plotWidth,
      label: "Состав счёта по классам активов",
    })}
      <div class="legend">
        ${allocation.segments.map((segment) => `
          <span class="legend-item"><i class="legend-swatch series-${segment.slot}"></i>${escapeHtml(segment.label)}<b>${segment.display}</b></span>
        `).join("")}
      </div>`;
    stripHost.querySelector(".legend").style.paddingLeft = `${columns.plotLeft}px`;
    const allocationHost = visibleHost("allocationChart");
    if (allocationHost) allocationHost.innerHTML = rankedBars(allocation.bars, hostWidth(allocationHost), {
      label: "Открытые позиции по рыночной стоимости",
    });
  }

  const extremesHost = visibleHost("extremesChart");
  if (extremesHost && extremes && extremes.length >= 2) {
    extremesHost.innerHTML = divergingBars(extremes, hostWidth(extremesHost), {
      label: "Итог по инструментам: лучшие и худшие",
    });
  }
}

function prepareCharts(payload) {
  const timeline = realisedTimeline(payload);
  state.charts.set("timeline", timeline);
  state.charts.set("allocation", allocationModel(payload));
  state.charts.set("extremes", extremeRows(payload));

  const drift = timeline.expected - timeline.dated;
  const covered = Math.abs(timeline.expected) > 1
    ? Math.abs(drift) / Math.abs(timeline.expected) < 0.001
    : true;
  state.timelineCoverage = covered
    // The dividend is bucketed by ex-date, which is what `realisedTimeline` reads and
    // which position earned it; the payment can land weeks later and in another year.
    // Sales are dated individually, not at the close of the cycle they belong to, and
    // the account-level items are on the line too — everything except the unrealised.
    ? "Продажи, дивиденды по отсечке, проценты брокера, сборы и FX-конверсии — по своим датам. Нереализованный P&L не входит."
    : `Закрытые сделки и дивиденды по датам. ${formatUsd(drift)} без даты в график не попали.`;
  updateTimelineNote();

  // The percent view divides by dated funding. Offering the button when there is
  // nothing to divide by would just produce an empty plot.
  const percentButton = byId("timelineMode").querySelector('button[data-mode="percent"]');
  percentButton.disabled = !timeline.percentAvailable;
  percentButton.title = timeline.percentAvailable
    ? "Тот же результат в процентах от внесённых денег"
    : "Недоступно: в снимке нет внесений (Deposits/Withdrawals)";
  if (!timeline.percentAvailable && state.timelineMode === "percent") {
    state.timelineMode = "absolute";
    byId("timelineMode").querySelectorAll("button")
      .forEach((item) => item.classList.toggle("active", item.dataset.mode === "absolute"));
  }

  const allocation = state.charts.get("allocation");
  byId("allocationNote").textContent = allocation.base
    ? `Открытые позиции на ${formatUsd(allocation.invested)} — это ${sharePercent(allocation.invested / allocation.base)} счёта`
    : "Открытые позиции по рыночной стоимости";

  byId("buildupTable").innerHTML = chartTable(
    buildupItems(payload).map((item, index, all) => {
      let cumulative = 0;
      for (let cursor = 0; cursor <= index; cursor += 1) {
        if (all[cursor].kind !== "total") cumulative += all[cursor].value;
      }
      const value = item.kind === "total" ? cumulative : item.value;
      return {
        label: item.label,
        value: formatUsd(value),
        tone: item.kind === "total" ? "" : pnlClass(value),
        kind: item.kind,
      };
    }),
    { head: ["Составляющая", "Сумма, USD"] },
  );
}

byId("timelineMode").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-mode]");
  if (!button || button.disabled) return;
  state.timelineMode = button.dataset.mode;
  byId("timelineMode").querySelectorAll("button")
    .forEach((item) => item.classList.toggle("active", item === button));
  updateTimelineNote();
  renderCharts();
});

byId("buildupTableToggle").addEventListener("click", (event) => {
  state.buildupAsTable = !state.buildupAsTable;
  byId("buildupTable").hidden = !state.buildupAsTable;
  byId("buildupChart").hidden = state.buildupAsTable;
  event.currentTarget.setAttribute("aria-expanded", String(state.buildupAsTable));
  event.currentTarget.textContent = state.buildupAsTable ? "Графиком" : "Таблицей";
  // Explicitly, not through the ResizeObserver: the observer ignores zero widths, so
  // a host that was hidden at the same width it had before reads as unchanged and
  // would keep whatever narrow SVG was last written into it.
  if (!state.buildupAsTable) renderCharts();
});

/* Tooltips: an enhancement over marks that already carry their value in a <title>
   and in a direct label, never the only way to read a number. */
const tooltip = byId("chartTooltip");

function showTooltip(target, event) {
  tooltip.innerHTML = `
    <strong>${escapeHtml(target.dataset.tipTitle || "")}</strong>
    <span>${escapeHtml(target.dataset.tipValue || "")}</span>
    ${target.dataset.tipNote ? `<small>${escapeHtml(target.dataset.tipNote)}</small>` : ""}
  `;
  tooltip.hidden = false;
  const box = tooltip.getBoundingClientRect();
  const x = Math.min(Math.max(8, event.clientX + 14), window.innerWidth - box.width - 8);
  const y = Math.max(8, event.clientY - box.height - 12);
  tooltip.style.transform = `translate(${Math.round(x)}px, ${Math.round(y)}px)`;
}

document.addEventListener("mousemove", (event) => {
  // The cumulative chart has no per-point marks to carry `data-tip-title`; it resolves
  // the nearest point itself in its own listener. That listener runs first as the event
  // bubbles, so without this guard the generic one would immediately hide the tooltip
  // it had just filled in, and the crosshair would follow the line with nothing to read.
  if (event.target.closest?.("#timelineChart")) return;
  const target = event.target.closest?.("[data-tip-title]");
  if (!target) {
    tooltip.hidden = true;
    return;
  }
  showTooltip(target, event);
});

document.addEventListener("focusin", (event) => {
  const target = event.target.closest?.("[data-tip-title]");
  if (!target) return;
  const box = target.getBoundingClientRect();
  showTooltip(target, { clientX: box.left + box.width / 2, clientY: box.top + box.height });
});

document.addEventListener("focusout", () => { tooltip.hidden = true; });
document.addEventListener("scroll", () => { tooltip.hidden = true; }, true);

// The area chart has no per-point marks, so the nearest point is resolved from the
// pointer position across the whole plot rather than from a hit target per month.
byId("timelineChart").addEventListener("mousemove", (event) => {
  const geometry = state.charts.get("timelineGeometry");
  const series = state.charts.get("timelineSeries");
  const svg = event.currentTarget.querySelector("svg");
  if (!geometry || !series?.points?.length || !svg) return;
  const box = svg.getBoundingClientRect();
  const time = geometry.fromX(event.clientX - box.left);
  let nearest = series.points[0];
  for (const point of series.points) {
    if (Math.abs(point.time - time) < Math.abs(nearest.time - time)) nearest = point;
  }
  const crosshair = svg.querySelector(".chart-crosshair");
  const line = svg.querySelector(".chart-crosshair-line");
  const dot = svg.querySelector(".chart-crosshair-dot");
  const cx = geometry.toX(nearest.time);
  const cy = geometry.toY(nearest.value);
  crosshair.removeAttribute("hidden");
  line.setAttribute("x1", cx);
  line.setAttribute("x2", cx);
  dot.setAttribute("cx", cx);
  dot.setAttribute("cy", cy);
  const month = new Date(nearest.time);
  showTooltip({
    dataset: {
      tipTitle: `${monthLabel(month)}`,
      tipValue: series.percent
        ? `${percentLabel(nearest.value, { signed: true })} от внесённого`
        : `Накоплено ${formatUsd(nearest.value)}`,
      tipNote: nearest.delta
        ? `за месяц ${series.percent
          ? percentLabel(nearest.delta, { signed: true })
          : formatSignedUsd(nearest.delta)}`
        : "",
    },
  }, event);
});

byId("timelineChart").addEventListener("mouseleave", (event) => {
  event.currentTarget.querySelector(".chart-crosshair")?.setAttribute("hidden", "");
  tooltip.hidden = true;
});

const monthFormatter = new Intl.DateTimeFormat("ru-RU", { month: "long", year: "numeric", timeZone: "UTC" });

function monthLabel(date) {
  return monthFormatter.format(date);
}

let resizeTimer = null;
window.addEventListener("resize", () => {
  if (!state.payload) return;
  if (resizeTimer) window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(() => {
    resizeTimer = null;
    renderCharts();
    syncStickyOffsets();
    alignHeroSide();
  }, 160);
});

/* ---------------------------------------------------------------- account --- */

/**
 * The instrument rows cannot answer "did the account really make this much": broker
 * interest, account fees and currency conversions never belong to a position. This
 * panel publishes the closing identity and everything the rows leave out.
 */
function renderAccountPanel(payload) {
  const identity = payload.accountIdentity;
  const accountCash = payload.accountCash || {};
  const performance = payload.performance || {};
  const panel = byId("accountPanel");
  if (!identity) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  const [tone, label] = IDENTITY_LABELS[identity.status] || IDENTITY_LABELS.UNAVAILABLE;
  const notCounted = [
    ["Проценты брокера", accountCash.interestUsd],
    ["Сборы по счёту", accountCash.accountFeesUsd],
    ["Результат FX-конверсий", accountCash.currencyResultUsd],
    ["Прочий кэш", accountCash.otherCashUsd],
    ["Неклассифицированный кэш", accountCash.unclassifiedCashUsd],
  ].filter(([, value]) => numberValue(value) !== null && numberValue(value) !== 0);

  // Two ways of arriving at the same number, printed side by side. They are the
  // whole point of the panel, so they get the equation layout rather than a grid
  // of equal-weight boxes where the reader has to find them.
  const bridge = `
    <div class="bridge">
      <div class="bridge-line">
        <span class="bridge-term"><small>Стоимость активов</small><b>${formatUsd(identity.marketValueUsd)}</b></span>
        <span class="bridge-op" aria-hidden="true">+</span>
        <span class="bridge-term"><small>Кэш</small><b>${formatUsd(identity.endingCashUsd)}</b></span>
        <span class="bridge-op" aria-hidden="true">−</span>
        <span class="bridge-term"><small>Внесено минус выведено</small><b>${formatUsd(identity.netContributionsUsd)}</b></span>
        <span class="bridge-op" aria-hidden="true">=</span>
        <span class="bridge-term is-result"><small>Заработано за всё время</small><b class="${pnlClass(identity.accountResultUsd)}">${formatUsd(identity.accountResultUsd)}</b></span>
      </div>
      <div class="bridge-line is-secondary">
        <span class="bridge-term"><small>Собрано из компонентов</small><b class="${pnlClass(identity.reportedResultUsd)}">${formatUsd(identity.reportedResultUsd)}</b></span>
        <span class="bridge-op" aria-hidden="true">→</span>
        <span class="bridge-term"><small>Расхождение</small><b>${formatUsd(identity.differenceUsd)}</b></span>
        <span class="bridge-op" aria-hidden="true">/</span>
        <span class="bridge-term"><small>Допуск</small><b>${formatUsd(identity.toleranceUsd)}</b></span>
      </div>
    </div>
  `;

  byId("accountIdentity").innerHTML = `
    <div class="identity-headline ${tone}">
      <span class="identity-dot" aria-hidden="true"></span>
      <strong>${escapeHtml(label)}</strong>
      <span>${escapeHtml(IDENTITY_HINTS[identity.status]
        || "разницу стоит объяснить, прежде чем доверять итогу")}</span>
    </div>
    ${bridge}
    <div class="identity-grid">
      <div${numberValue(performance.currencyCommissionsUsd)
        ? ` title="${escapeHtml(`В том числе ${formatCost(performance.currencyCommissionsUsd)} за валютные конверсии`)}"`
        : ""}><span>Комиссии за всё время</span><strong class="negative">${formatCost(performance.commissionsUsd)}</strong></div>
      <div><span>Налоги со сделок</span><strong class="negative">${formatCost(performance.transactionTaxesUsd)}</strong></div>
      <div><span>Доля кэша</span><strong>${formatPercent(payload.allocation?.cashShare)}</strong></div>
      <div><span>Номинал деривативов</span><strong>${formatUsd(payload.allocation?.derivativeNotionalUsd)}</strong></div>
      <div><span>Вложенный капитал</span><strong>${formatUsd(payload.allocation?.investedCapitalUsd)}</strong></div>
      <div><span>Первое внесение</span><strong>${formatDate(performance.firstFundingAt)}</strong></div>
    </div>
    ${notCounted.length ? `
      <div class="not-counted">
        <strong>Не входит в итог по инструментам</strong>
        ${notCounted.map(([name, value]) => `<span><small>${escapeHtml(name)}</small><b class="${pnlClass(value)}">${formatUsd(value)}</b></span>`).join("")}
      </div>` : ""}
  `;
}

/* ----------------------------------------------------------------- status --- */

// Two clocks, because they fail independently. The pipeline can be dead while the
// last statement it fetched is recent, and the pipeline can be running fine while
// IBKR keeps returning an old statement.
const RUN_AGE_WARNING_HOURS = 26;
const RUN_AGE_ERROR_HOURS = 72;
// Generous, because the statement period always ends the day before it is generated
// and no run happens on Sunday or Monday. Anything tighter is amber every weekend,
// which teaches the owner to ignore the light.
const DATA_AGE_WARNING_HOURS = 96;
const DATA_AGE_ERROR_HOURS = 168;

function hoursSince(value) {
  const parsed = timeValue(value);
  if (parsed === null) return null;
  return (Date.now() - parsed) / 3_600_000;
}

/**
 * One line, one light. The previous bar printed four timestamps and a coverage
 * sentence, which is a lot of reading to answer the only question that matters at a
 * glance: is what I am looking at current?
 */
function renderStatus(payload) {
  const status = payload.status || {};
  const level = String(status.level || "WARNING").toUpperCase();
  // The date of the data itself, not of the run that processed it.
  const dataAsOf = payload.cash?.asOf || status.activityReconciledAt;
  const dataAge = hoursSince(dataAsOf);
  const runAge = hoursSince(payload.generatedAt);

  let tone = "ok";
  let headline = "Данные IBKR актуальны";
  if (level === "ERROR") {
    tone = "error";
    headline = "Расхождения в учёте — данные под вопросом";
  } else if (runAge !== null && runAge > RUN_AGE_ERROR_HOURS) {
    tone = "error";
    headline = "Дашборд не обновлялся — синхронизация не работает";
  } else if (dataAge !== null && dataAge > DATA_AGE_ERROR_HOURS) {
    tone = "error";
    headline = "Данные IBKR устарели";
  } else if (runAge !== null && runAge > RUN_AGE_WARNING_HOURS) {
    tone = "warning";
    headline = "Дашборд давно не обновлялся";
  } else if (dataAge !== null && dataAge > DATA_AGE_WARNING_HOURS) {
    tone = "warning";
    headline = "Отчёт IBKR давно не обновлялся";
  } else if (level === "WARNING") {
    tone = "warning";
    headline = "Данные актуальны, есть замечания";
  }

  const problems = Number(status.issueCount || 0);
  const details = [
    dataAsOf ? `данные на ${formatDate(dataAsOf)}` : null,
    `обновлено ${formatDate(payload.generatedAt, true)}`,
    // Only when there is something to act on. The count of stale prices is not here:
    // outside trading hours every price is stale by definition, and each row already
    // says so next to the price it applies to.
    problems ? `проблемы: ${problems}` : null,
    payload.publication?.reason === "STATUS_ERROR" ? "публикация остановлена" : null,
  ].filter(Boolean);

  const container = byId("dataStatus");
  container.className = `data-status status-${tone}`;
  container.innerHTML = `
    <div class="status-main">
      <span class="status-indicator" aria-hidden="true"></span>
      <strong>${escapeHtml(headline)}</strong>
    </div>
    <div class="status-times"><span>${escapeHtml(details.join(" · "))}</span></div>
  `;
}

/* ---------------------------------------------------------------- filters --- */

function populateSelect(select, values, defaultLabel, compare = null) {
  const current = select.value;
  select.innerHTML = `<option value="">${escapeHtml(defaultLabel)}</option>` + values
    .filter(Boolean)
    .sort(compare || ((left, right) => left.localeCompare(right)))
    .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`)
    .join("");
  select.value = current;
}

function renderFilterOptions(rows) {
  populateSelect(byId("currencyFilter"), [...new Set(rows.map((row) => row.currency))], "Все валюты");
  // Every year in which anything at all happened: an execution, a dividend, a fee.
  const years = new Set();
  for (const row of rows) {
    for (const cycle of row.cycles || []) {
      for (const trade of cycle.trades || []) years.add(String(trade.timestamp || "").slice(0, 4));
      for (const event of cycle.cashEvents || []) years.add(String(event.timestamp || "").slice(0, 4));
    }
  }
  years.delete("");
  // Newest first: the year being looked at is almost always a recent one.
  populateSelect(byId("yearFilter"), [...years], "Любой год", (a, b) => b.localeCompare(a));
  renderScopeFilter();
}

/** The classes present in the payload, as a plain multiple choice. */
function renderScopeFilter() {
  const universe = scopeUniverse();
  byId("assetScopeOptions").innerHTML = universe.map((value) => {
    const checked = !state.assetScope.size || state.assetScope.has(value);
    return `<label class="scope-option">
      <input type="checkbox" value="${escapeHtml(value)}"${checked ? " checked" : ""} />
      <span>${escapeHtml(ASSET_CLASS_LABELS[value] || value)}</span>
    </label>`;
  }).join("");
  const label = byId("assetScopeSummary");
  label.textContent = scopeLabel();
  label.closest("summary").classList.toggle("is-narrowed", scopeNarrowed());
  byId("assetScopeAll").hidden = !scopeNarrowed();
}

/** Reads the boxes, then redraws everything the scope reaches. */
function applyScope() {
  const boxes = [...byId("assetScopeOptions").querySelectorAll("input[type=checkbox]")];
  const picked = boxes.filter((box) => box.checked).map((box) => box.value);
  // Unchecking the last box would leave a page with nothing on it and no way back
  // except the reset button, so an empty pick means every class, same as the default.
  state.assetScope = new Set(picked.length && picked.length < boxes.length ? picked : []);
  persistScope();
  redrawScopedBlocks();
}

/** Everything the class selection is allowed to change, and nothing else. */
function redrawScopedBlocks() {
  const payload = state.payload;
  if (!payload) return;
  renderScopeFilter();
  renderHero(payload);
  prepareCharts(payload);
  applyCollapsed();
  renderCharts();
  alignHeroSide();
  renderRows();
}

/**
 * Identity of a table row. An instrument traded in both directions is two rows with
 * the same conid, so anything that remembers a row — which one is expanded, which
 * alert box holds a half-typed price — has to key on this instead.
 */
function rowKey(row) {
  return row.rowId || `${row.conid}:${row.direction}`;
}

function isOpen(row) {
  return Math.abs(numberValue(row.quantity) || 0) > 1e-8;
}

/**
 * The entry column is the instrument's whole life, open or closed: the
 * quantity-weighted price across every cycle it ever had, on the same footing as the
 * money columns beside it, which have always been lifetime.
 *
 * The AVCO of the position held right now is a different number and has its own home:
 * "Себестоимость позиции, AVCO" in the expanded card, where it sits with the rest of
 * what is true only today. Putting it here made STLA's row read 7.56 — the average of
 * the 3750 left after averaging down — while the row's money covered all 8250 bought.
 */
function rowAverageEntry(row) {
  // A payload built before the lifetime pair existed still has the last cycle's.
  // Showing that is what the column did for a year; showing a dash is not better.
  return row.lifetimeAverageEntry ?? row.averageEntry;
}

const SORT_ACCESSORS = {
  instrument: (row) => `${row.symbol || ""} ${row.instrument || ""}`,
  currency: (row) => row.currency || "",
  status: (row) => statusLabel(row),
  cycle: (row) => row.firstTradeAt || row.cycleOpenedAt || "",
  quantity: (row) => numberValue(row.quantity),
  averageEntry: (row) => numberValue(rowAverageEntry(row)),
  averageExit: (row) => numberValue(row.lifetimeAverageExit ?? row.averageExit),
  currentPrice: (row) => numberValue(row.currentPrice?.price),
  marketValueUsd: (row) => numberValue(row.marketValueUsd),
  unrealizedPnlUsd: (row) => numberValue(row.unrealizedPnlUsd),
  realizedPnlUsd: (row) => numberValue(row.realizedPnlUsd),
  dividendsNetUsd: (row) => numberValue(row.dividendsNetUsd),
  totalResultUsd: (row) => numberValue(row.totalResultUsd),
};

function defaultRowCompare(left, right) {
  const openDifference = Number(isOpen(right)) - Number(isOpen(left));
  if (openDifference) return openDifference;
  if (isOpen(left)) {
    return Math.abs(numberValue(right.marketValueUsd) || 0) - Math.abs(numberValue(left.marketValueUsd) || 0);
  }
  return String(right.lastCloseAt || right.cycleClosedAt || "")
    .localeCompare(String(left.lastCloseAt || left.cycleClosedAt || ""));
}

function sortRows(rows) {
  const accessor = SORT_ACCESSORS[state.sortKey];
  if (!accessor || !state.sortDirection) return rows.sort(defaultRowCompare);

  return rows.sort((left, right) => {
    const leftValue = accessor(left);
    const rightValue = accessor(right);
    const leftMissing = leftValue === null || leftValue === undefined || leftValue === "";
    const rightMissing = rightValue === null || rightValue === undefined || rightValue === "";
    if (leftMissing !== rightMissing) return leftMissing ? 1 : -1;
    if (leftMissing) return defaultRowCompare(left, right);

    const comparison = typeof leftValue === "number" && typeof rightValue === "number"
      ? leftValue - rightValue
      : String(leftValue).localeCompare(String(rightValue), "ru", { sensitivity: "base", numeric: true });
    if (comparison) return state.sortDirection === "descending" ? -comparison : comparison;
    return defaultRowCompare(left, right);
  });
}

function renderSortHeaders() {
  document.querySelectorAll("button[data-sort]").forEach((button) => {
    const active = button.dataset.sort === state.sortKey && Boolean(state.sortDirection);
    const header = button.closest("th");
    const indicator = button.querySelector(".sort-indicator");
    header.setAttribute("aria-sort", active ? state.sortDirection : "none");
    button.classList.toggle("active", active);
    indicator.textContent = active ? (state.sortDirection === "descending" ? "↓" : "↑") : "↕";
  });
}

function activeFilterCount() {
  return ["directionFilter", "currencyFilter", "profitFilter", "yearFilter"]
    .filter((id) => byId(id).value).length
    + (scopeNarrowed() ? 1 : 0)
    + (byId("searchInput").value.trim() ? 1 : 0)
    + (state.activeTab === "all" ? 0 : 1);
}

const CORPORATE_ACTIONS = new Set(["TO", "TC", "IC", "SO", "SD"]);

/**
 * The row as one calendar year saw it.
 *
 * Realised, dividends and fees are re-summed from the events that carry a timestamp
 * inside the year, so the figures are the year's own rather than the instrument's
 * life. Checked against the published payload: summed back over every year they
 * reproduce each row's lifetime realised, gross, withheld, net and fees exactly.
 *
 * The prices are the weighted average of the year's own entries and exits, commission
 * included. That is deliberately not the same quantity as the unfiltered column, which
 * is AVCO of what is still held for an open position, and which also absorbs basis
 * arriving from a corporate action with no price attached. On the 526 closed cycles
 * with neither of those, the two agree exactly — checked against every one of them.
 *
 * Quantity, price, market value, cost basis and unrealised describe the position as it
 * stands today and belong to no year, so they are dropped rather than carried over from
 * a lifetime row into a 2023 view.
 *
 * Returns null when nothing happened in the year, which is what hides the row.
 */
function projectRowToYear(row, year) {
  const inYear = (stamp) => String(stamp || "").slice(0, 4) === year;
  let realised = 0;
  let gross = 0;
  let withheld = 0;
  let fees = 0;
  let commissions = 0;
  let taxes = 0;
  // Denominators carry the contract multiplier, because the values above do: an
  // option at 1.30 on a multiplier of 100 costs 130 and must still average to 1.30.
  let entryValue = 0;
  let entryShares = 0;
  let exitValue = 0;
  let exitShares = 0;
  let firstAt = null;
  let lastAt = null;
  const cycles = [];

  const seen = (stamp) => {
    if (!stamp) return;
    if (firstAt === null || stamp < firstAt) firstAt = stamp;
    if (lastAt === null || stamp > lastAt) lastAt = stamp;
  };

  for (const cycle of row.cycles || []) {
    const trades = (cycle.trades || []).filter((trade) => inYear(trade.timestamp));
    const cash = (cycle.cashEvents || []).filter((event) => inYear(event.timestamp));
    if (!trades.length && !cash.length) continue;
    cycles.push(cycle);
    const multiplier = numberValue(cycle.multiplier) || 1;
    for (const trade of trades) {
      seen(trade.timestamp);
      realised += numberValue(trade.realizedUsd) || 0;
      commissions += numberValue(trade.commission) || 0;
      taxes += numberValue(trade.taxes) || 0;
      // A corporate action moves shares without a price, so it can weight no average.
      if (CORPORATE_ACTIONS.has(trade.action)) continue;
      const quantity = Math.abs(numberValue(trade.quantity) || 0);
      const notional = quantity * (numberValue(trade.price) || 0) * multiplier;
      const cost = (numberValue(trade.commission) || 0) + (numberValue(trade.taxes) || 0);
      // Costs follow the cash, not the leg: a buy pays them on top, a sale nets them
      // out. Tying the sign to entry-versus-exit instead is right for a long and
      // backwards for a short, which showed up as ALB's short reporting 205.29 in
      // against 205.27 out — its own two prices swapped.
      const value = trade.side === "BUY" ? notional + cost : notional - cost;
      if (trade.action === "ENTRY") {
        entryValue += value;
        entryShares += quantity * multiplier;
      } else if (trade.action === "EXIT") {
        exitValue += value;
        exitShares += quantity * multiplier;
      }
    }
    for (const event of cash) {
      seen(event.timestamp);
      const amount = numberValue(event.amountUsd) || 0;
      if (event.category === "DIVIDEND") gross += amount;
      else if (event.category === "WITHHOLDING_TAX") withheld += amount;
      else fees += amount;
    }
  }

  if (!cycles.length) return null;
  const dividendsNet = gross + withheld;
  return {
    ...row,
    projectedYear: year,
    cycles,
    firstTradeAt: firstAt,
    lastCloseAt: lastAt,
    quantity: null,
    currentPrice: {},
    marketValue: null,
    marketValueUsd: null,
    openBasis: null,
    openBasisUsd: null,
    unrealizedPnl: null,
    unrealizedPnlUsd: null,
    unrealizedFxPnlUsd: null,
    lifetimeAverageEntry: entryShares ? entryValue / entryShares : null,
    lifetimeAverageExit: exitShares ? exitValue / exitShares : null,
    averageEntry: null,
    averageExit: null,
    realizedPnlUsd: realised,
    // The published split of realised into price and currency has no per-event
    // breakdown to re-sum, so it is withheld rather than shown as a lifetime figure.
    priceRealizedPnlUsd: null,
    fxRealizedPnlUsd: null,
    dividendsGrossUsd: gross,
    withholdingTaxUsd: withheld,
    dividendsNetUsd: dividendsNet,
    otherFeesUsd: fees,
    commissionsUsd: commissions,
    transactionTaxesUsd: taxes,
    totalResultUsd: realised + dividendsNet + fees,
    breakEvenStatus: "NO_OPEN_POSITION",
    breakEvenPrice: null,
  };
}

function filteredRows() {
  const search = byId("searchInput").value.trim().toLowerCase();
  const direction = byId("directionFilter").value;
  const currency = byId("currencyFilter").value;
  const profit = byId("profitFilter").value;
  const year = byId("yearFilter").value;
  // The tab and the direction describe the position as it stands, so they are applied
  // to the row itself. The result filter asks about money, so it has to wait until the
  // money is the year's.
  const rows = [];
  for (const source of state.payload?.rows || []) {
    if (state.activeTab === "open" && !isOpen(source)) continue;
    if (state.activeTab === "closed" && isOpen(source)) continue;
    if (state.activeTab === "review" && source.status !== "REVIEW") continue;
    if (!inScope(source)) continue;
    if (direction && source.direction !== direction) continue;
    if (currency && source.currency !== currency) continue;
    if (search) {
      const haystack = [source.instrument, source.symbol, source.conid, ...(source.symbolHistory || [])]
        .join(" ").toLowerCase();
      if (!haystack.includes(search)) continue;
    }
    const row = year ? projectRowToYear(source, year) : source;
    if (!row) continue;
    const result = numberValue(row.totalResultUsd) || 0;
    if (profit === "profit" && result <= 0) continue;
    if (profit === "loss" && result >= 0) continue;
    rows.push(row);
  }
  return sortRows(rows);
}

/* ------------------------------------------------------------------ table --- */

function statusLabel(row) {
  if (row.status === "REVIEW") return "Проверить";
  return isOpen(row) ? "Открыта" : "Закрыта";
}

function statusClass(row) {
  if (row.status === "REVIEW") return "review";
  return isOpen(row) ? "open" : "closed";
}

function alertDraftValue(row, side) {
  return state.alertDrafts.get(`${rowKey(row)}:${side}`) || "";
}

const BREAK_EVEN_REASONS = {
  NO_OPEN_POSITION: "Нет открытого остатка",
  ZERO_QUANTITY: "Остаток равен нулю",
  UNREACHABLE: "При текущем остатке безубыточность недостижима",
  FX_UNAVAILABLE: "Не хватает актуального курса валюты",
};

function breakEvenMarkup(row) {
  if (row.breakEvenStatus === "AVAILABLE" && row.breakEvenPrice != null) {
    const action = row.breakEvenCondition === "BUY_AT_OR_BELOW"
      ? "Покупка остатка не дороже"
      : "Продажа остатка не дешевле";
    // The caveat that used to sit under the price is true but was three lines long
    // for a number read at a glance, so it moved to the hover text.
    return `
      <div class="break-even-card" title="Учтены все проведённые комиссии и чистые дивиденды; будущая комиссия закрытия не включена">
        <span>Безубыточность всей истории</span>
        <strong>${formatMoney(row.breakEvenPrice, row.currency, true)}</strong>
        <small>${action} этой цены</small>
      </div>
    `;
  }
  const reason = BREAK_EVEN_REASONS[row.breakEvenStatus] || "Расчёт недоступен";
  return `
    <div class="break-even-card unavailable">
      <span>Безубыточность всей истории</span>
      <strong>—</strong>
      <small>${escapeHtml(reason)}</small>
    </div>
  `;
}

function alertMarkup(row) {
  return `
    <div class="alert-panel">
      <div class="alert-heading">
        <div><h3>Ценовые алерты</h3><p>Доступны для любого инструмента из истории</p></div>
        <span class="alert-draft-status">Черновик · сервер не подключён</span>
      </div>
      <div class="alert-grid">
        <label class="alert-control buy-alert">
          <span>Покупка <small>Ask ≤</small></span>
          <span class="alert-input-wrap"><input type="number" min="0" step="any" inputmode="decimal" data-alert-side="buy" data-row-key="${escapeHtml(rowKey(row))}" value="${escapeHtml(alertDraftValue(row, "buy"))}" placeholder="Цена" /><b>${escapeHtml(row.currency)}</b></span>
        </label>
        <label class="alert-control sell-alert">
          <span>Продажа <small>Bid ≥</small></span>
          <span class="alert-input-wrap"><input type="number" min="0" step="any" inputmode="decimal" data-alert-side="sell" data-row-key="${escapeHtml(rowKey(row))}" value="${escapeHtml(alertDraftValue(row, "sell"))}" placeholder="Цена" /><b>${escapeHtml(row.currency)}</b></span>
        </label>
        ${breakEvenMarkup(row)}
      </div>
      <p class="alert-footnote">Введённые уровни сохраняются только до закрытия вкладки и не отправляют уведомления. Для жёстких уровней используйте штатные алерты IBKR.</p>
    </div>
  `;
}

function cycleMarkup(row) {
  const cycles = [...(row.cycles || [])].reverse();
  return cycles.map((cycle) => {
    const fallbackResult = (numberValue(cycle.realizedPnlUsd) || 0)
      + (numberValue(cycle.dividendsNetUsd) || 0);
    const totalResult = numberValue(cycle.totalResultUsd) ?? fallbackResult;
    const corporateIn = numberValue(cycle.corporateInQuantity) || 0;
    const open = !cycle.closedAt;
    const dividend = perShareDividend(cycle, row.currency);
    // An open cycle that has already sold some of itself holds two different stories,
    // and one row of prices could only tell one of them. STLA's cycle bought 8250,
    // sold 4500 and kept 3750: the entry price is the AVCO of what is left after
    // averaging down, the exit price is what the sold half went for, and the two
    // invite a comparison that is simply false. What the sold half actually cost is
    // its proceeds less what it realised, and against that the exit price reads
    // correctly — 9.42 against 11.12 is the loss the cycle is reporting.
    const soldQuantity = numberValue(cycle.exitQuantityTotal) || 0;
    const exitAverage = numberValue(cycle.averageExit);
    const partial = open && soldQuantity > 0 && exitAverage !== null;
    const soldCostPerShare = partial
      ? (exitAverage * soldQuantity - (numberValue(cycle.realizedPnl) || 0)) / soldQuantity
      : null;
    return `
      <article class="cycle-item ${open ? "is-open" : ""}">
        <header>
          <span class="cycle-number">Цикл ${escapeHtml(cycle.number)}</span>
          <span class="cycle-direction">${escapeHtml(cycle.direction)}</span>
          <span class="cycle-period">${formatDate(cycle.openedAt)} → ${open ? "сейчас" : formatDate(cycle.closedAt)}</span>
          <strong class="${pnlClass(totalResult)}">${formatSignedUsd(totalResult)}</strong>
        </header>
        <div class="cycle-facts">
          <span><small>Остаток</small><b>${formatNumber(cycle.quantity, 8)}${corporateIn ? ` · ${formatNumber(corporateIn, 8)} по КД` : ""}</b></span>
          <span><small${partial ? ' title="AVCO того, что осталось в позиции, а не всего купленного за цикл"' : ""}>${
            partial ? "Средний вход остатка" : "Средний вход"
          }</small><b>${formatMoney(cycle.averageEntry, row.currency, true)}</b></span>
          ${partial ? `
          <span><small>Продано</small><b>${formatNumber(cycle.exitQuantityTotal, 8)}</b></span>
          <span><small title="Во что обошлись проданные акции: выручка за вычетом того, что они принесли">Себестоимость проданных</small><b>${formatMoney(soldCostPerShare, row.currency, true)}</b></span>
          <span><small>Средняя цена продажи</small><b>${formatMoney(cycle.averageExit, row.currency, true)}</b></span>
          ` : `
          <span><small>Средний выход</small><b${open ? ' title="Цикл открыт и ничего ещё не продано"' : ""}>${
            open ? '<span class="muted-value">—</span>' : formatMoney(cycle.averageExit, row.currency, true)
          }</b></span>
          `}
          <span><small>Дивиденды на акцию</small><b${dividend ? ` title="За цикл получено ${escapeHtml(dividend.total)}"` : ""}>${
            dividend ? dividend.text : '<span class="muted-value">—</span>'
          }</b></span>
          <span><small>Операций</small><b>${(cycle.trades || []).length}</b></span>
        </div>
      </article>
    `;
  }).join("") || '<div class="muted-value">Циклы отсутствуют</div>';
}

function detailHtml(row) {
  const review = (row.reviewReasons || []).length
    ? `<div class="review-box">${row.reviewReasons.map(escapeHtml).join("<br>")}</div>`
    : "";
  const corporateActions = (row.corporateActions || []).length
    ? `<div class="corporate-history"><strong>Корпоративные действия</strong>${row.corporateActions.map((event) => `<span>${formatDate(event.timestamp)} · ${escapeHtml(event.description || event.category)}</span>`).join("")}</div>`
    : "";
  // Only fields that carry a value are shown. A grid of dashes is not information,
  // and every optional entry below is genuinely absent for most instruments.
  const optional = (label, markup, present) =>
    present ? `<div class="detail-item"><span>${label}</span><strong>${markup}</strong></div>` : "";
  const foreign = String(row.currency || "USD").toUpperCase() !== "USD";
  const history = (row.symbolHistory || []).filter(Boolean);
  return `
    <tr class="detail-row"><td colspan="13">
      <div class="detail-wrap">
        <section class="detail-section">
          <h3>Инструмент</h3>
          <div class="detail-grid">
            <div class="detail-item"><span>Conid</span><strong>${escapeHtml(row.conid)}</strong></div>
            <div class="detail-item"><span>Биржа</span><strong>${escapeHtml(row.exchange || "—")}</strong></div>
            <div class="detail-item"><span>Первая сделка</span><strong>${formatDate(row.firstTradeAt, true)}</strong></div>
            ${optional("История тикеров",
              escapeHtml(history.join(" → ")), history.length > 1)}
            ${optional("Себестоимость позиции, AVCO",
              formatMoney(row.openBasis, row.currency, true), isOpen(row))}
            ${optional("Она же в USD по курсам покупок",
              formatUsd(row.openBasisUsd), isOpen(row) && foreign)}
            ${optional("Дивиденды gross",
              formatMoney(row.dividendsGross, row.currency, true),
              numberValue(row.dividendsGross))}
            ${optional("Дивиденды net, после налогов",
              formatMoney(row.dividendsNet, row.currency, true),
              numberValue(row.dividendsNet))}
            ${optional("Комиссии",
              `<span class="negative">${formatCost(row.commissionsUsd)}</span>`,
              numberValue(row.commissionsUsd))}
            ${optional("Прочие сборы",
              `<span class="${pnlClass(row.otherFeesUsd)}">${formatUsd(row.otherFeesUsd)}</span>`,
              numberValue(row.otherFeesUsd))}
            ${optional(`<span title="${escapeHtml("Реализованный P&L складывается из ценовой и валютной частей: валютная — это движение курса между покупкой и продажей")}">Валютная часть реализованного P&amp;L</span>`,
              `<span class="${pnlClass(row.fxRealizedPnlUsd)}">${formatUsd(row.fxRealizedPnlUsd)}</span>`,
              numberValue(row.fxRealizedPnlUsd))}
          </div>
          ${review}
          ${corporateActions}
        </section>
        <section class="detail-section"><h3>Позиционные циклы</h3>${
          row.projectedYear
            ? `<p class="detail-note">Показаны циклы, затронутые ${escapeHtml(row.projectedYear)} годом. Цифры внутри цикла — за весь цикл целиком, а не за год.</p>`
            : ""
        }<div class="cycle-list">${cycleMarkup(row)}</div>${alertMarkup(row)}</section>
      </div>
    </td></tr>
  `;
}

const FRESHNESS_LABELS = {
  stale: "устарела",
  fallback: "резервная",
  unavailable: "нет данных",
};

/** A hairline under a number, right-aligned like the number, sized as a share. */
function magnitudeBar(value, max, tone) {
  const parsed = numberValue(value);
  if (parsed === null || !max) return "";
  const share = Math.min(1, Math.abs(parsed) / max);
  if (share < 0.005) return "";
  const percent = (share * 100).toFixed(2);
  return `<svg class="cell-bar tone-${tone}" width="100%" height="3" preserveAspectRatio="none" aria-hidden="true"><rect x="${(100 - Number(percent)).toFixed(2)}%" y="0" width="${percent}%" height="3" rx="1.5" /></svg>`;
}

function rowHtml(row, scale) {
  const quote = row.currentPrice || {};
  // Priced in the currency the quote itself is denominated in, not the instrument's:
  // if those ever disagree the label must not hide it.
  const price = quote.price == null
    ? "—"
    : formatMoney(quote.price, quote.currency || row.currency, true);
  const stale = String(quote.freshness || "").toLowerCase() === "stale";
  // The quote type is only worth a column inch when it is not the ordinary one:
  // printing "LAST" on every row of 253 crowded out the timestamp beside it.
  const priceMeta = [
    quote.type && quote.type !== "LAST" ? quote.type : null,
    quote.marketTime ? formatDateShort(quote.marketTime, "time").replace(", ", " ") : null,
    FRESHNESS_LABELS[String(quote.freshness || "").toLowerCase()],
  ].filter(Boolean).join(" · ");
  const open = isOpen(row);
  // The instrument's whole life, not the latest cycle's: first trade to last close,
  // which is the scope the money columns to the right already report on. Both dates on
  // one line ran past the column and got cut mid-number; the status column beside it
  // already stands two lines tall, so the second line is free.
  const cycleFrom = formatDateShort(row.firstTradeAt ?? row.cycleOpenedAt);
  const cycleTo = open
    ? '<span class="cycle-now">сейчас</span>'
    : formatDateShort(row.lastCloseAt ?? row.cycleClosedAt);
  const expanded = state.expanded.has(rowKey(row));
  const total = numberValue(row.totalResultUsd);
  return `
    <tr class="data-row ${expanded ? "expanded" : ""}" data-row-key="${escapeHtml(rowKey(row))}"
      tabindex="0" role="button" aria-expanded="${expanded}">
      <td><div class="instrument-cell"><span class="instrument-text"><strong class="instrument-name" title="${escapeHtml(row.instrument)}">${escapeHtml(row.symbol)}</strong><small class="instrument-meta">${escapeHtml(row.instrument)}</small></span><span class="expand-chevron" aria-hidden="true">›</span></div></td>
      <td><span class="currency-tag">${escapeHtml(row.currency)}</span></td>
      <td class="status-cell"><span class="status-pill ${statusClass(row)}">${statusLabel(row)}</span><span class="row-note">${escapeHtml(row.direction)} · ${escapeHtml(row.assetClass)}</span></td>
      <td class="cycle-cell"><span class="cycle-line">${cycleFrom}</span><span class="cycle-line">${cycleTo}</span></td>
      <td class="numeric quantity-cell">${formatNumber(row.quantity, 8)}</td>
      <td class="numeric">${formatMoney(rowAverageEntry(row), row.currency, true)}</td>
      <td class="numeric">${open ? '<span class="muted-value">—</span>' : formatMoney(row.lifetimeAverageExit ?? row.averageExit, row.currency, true)}</td>
      <td class="numeric">${price}<span class="row-note ${stale ? "quote-stale" : ""}" title="${escapeHtml(`${quote.type || "UNAVAILABLE"} · ${formatDate(quote.marketTime, true)}`)}">${escapeHtml(priceMeta)}</span></td>
      <td class="numeric">${formatUsdCell(row.marketValueUsd)}${magnitudeBar(row.marketValueUsd, scale.marketValue, "neutral")}</td>
      <td class="numeric ${pnlClass(row.unrealizedPnlUsd)}">${formatUsdCell(row.unrealizedPnlUsd)}</td>
      <td class="numeric ${pnlClass(row.realizedPnlUsd)}">${formatUsdCell(row.realizedPnlUsd)}</td>
      <td class="numeric ${pnlClass(row.dividendsNetUsd)}">${formatUsdCell(row.dividendsNetUsd)}</td>
      <td class="numeric is-total ${pnlClass(total)}">${formatUsdCell(total)}${magnitudeBar(total, scale.total, total > 0 ? "up" : "down")}</td>
    </tr>
    ${expanded ? detailHtml(row) : ""}
  `;
}

const GROUP_LABELS = {
  open: "Открытые позиции",
  closed: "Закрытая история",
};

function groupRow(kind, count) {
  // A single cell, so the band is one unbroken colour: split across the pinned first
  // column and the rest, the label sat on the row background and the divider on the
  // group one, and the seam moved as the table scrolled. The label is pinned inside
  // the cell instead — a cell spanning the whole row has nowhere to slide to.
  return `<tr class="group-row"><td colspan="13"><div class="group-label"><span>${GROUP_LABELS[kind]}</span><b>${count}</b></div></td></tr>`;
}

function renderRows() {
  const rows = filteredRows();
  renderSortHeaders();
  renderKpis(state.payload, rows);
  const scale = {
    marketValue: Math.max(...rows.map((row) => Math.abs(numberValue(row.marketValueUsd) || 0)), 0),
    total: Math.max(...rows.map((row) => Math.abs(numberValue(row.totalResultUsd) || 0)), 0),
  };

  // Grouping only where the order is the default one: under an explicit sort a
  // heading claiming "open positions" would sit above rows that are not grouped.
  const grouped = !state.sortKey && state.activeTab === "all";
  const openCount = grouped ? rows.filter(isOpen).length : 0;
  let previousGroup = null;
  const markup = [];
  for (const row of rows) {
    if (grouped) {
      const group = isOpen(row) ? "open" : "closed";
      if (group !== previousGroup) {
        markup.push(groupRow(group, group === "open" ? openCount : rows.length - openCount));
        previousGroup = group;
      }
    }
    markup.push(rowHtml(row, scale));
  }
  portfolioBody.innerHTML = markup.join("");
  byId("resultCount").textContent = `${rows.length} из ${state.payload?.rows?.length || 0}`;
  byId("emptyState").hidden = rows.length > 0;
  // Disabled rather than hidden: appearing and disappearing shifted the whole row
  // sideways every time a filter was touched.
  byId("resetFilters").disabled = activeFilterCount() === 0;
  syncStickyOffsets();
}

/**
 * The expanded card is pinned to the scrollport and has to be exactly as wide as it,
 * which no CSS length can express: the cell it lives in is as wide as the table.
 * Published as a custom property through CSSOM, which the page's CSP allows where a
 * style attribute would be dropped.
 */
/**
 * The account-composition card is centred on the same line the figure's leading "+"
 * sits on. Nothing in CSS can express "line this box up with that glyph", so it is
 * measured and applied as padding above the column; the verdict card stays pinned to
 * the bottom, so only the meter moves.
 */
function alignHeroSide() {
  const side = document.querySelector(".hero-side");
  const figure = document.querySelector(".hero-figure");
  const meter = document.querySelector(".hero-meter");
  const main = document.querySelector(".hero-main");
  if (!side || !figure || !meter || !main) return;
  side.style.paddingTop = "0px";
  // Stacked (one column) or folded: there is no second column to line anything up with.
  if (byId("heroPanel").classList.contains("is-collapsed")
    || Math.abs(side.getBoundingClientRect().left - main.getBoundingClientRect().left) < 4) return;

  const probe = document.createElement("i");
  probe.style.display = "inline-block";
  probe.style.width = "0px";
  probe.style.height = "0px";
  figure.append(probe);
  const baseline = probe.getBoundingClientRect().top;
  probe.remove();
  const style = getComputedStyle(figure);
  const context = (alignHeroSide.canvas || (alignHeroSide.canvas = document.createElement("canvas")))
    .getContext("2d");
  context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
  const plus = context.measureText("+");
  const plusY = baseline - (plus.actualBoundingBoxAscent - plus.actualBoundingBoxDescent) / 2;

  const box = meter.getBoundingClientRect();
  const delta = plusY - (box.top + box.height / 2);
  // Only ever downwards, and only into the slack the column already has: the verdict
  // card is pinned to the bottom, so the room to move is the gap between the two cards
  // less the gap they are supposed to keep. The column itself is stretched to the row
  // height, so its own height says nothing about how much slack is inside it.
  const verdict = side.querySelector(".hero-check");
  const gap = parseFloat(getComputedStyle(side).rowGap) || 12;
  const room = verdict ? verdict.getBoundingClientRect().top - box.bottom - gap : 0;
  const shift = Math.max(0, Math.min(Math.round(delta), Math.floor(room)));
  if (shift > 0) side.style.paddingTop = `${shift}px`;
}

function syncStickyOffsets() {
  const wrap = document.querySelector(".table-wrap");
  if (!wrap || wrap.clientWidth <= 0) return;
  wrap.style.setProperty("--wrap-width", `${wrap.clientWidth}px`);
}

function toggleRow(key) {
  if (!key) return;
  if (state.expanded.has(key)) state.expanded.delete(key);
  else state.expanded.add(key);
  renderRows();
}

// One delegated listener for the whole table instead of one per row per render.
portfolioBody.addEventListener("click", (event) => {
  if (event.target.closest("input, label, .alert-panel")) return;
  toggleRow(event.target.closest("tr.data-row")?.dataset.rowKey);
});

portfolioBody.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("tr.data-row");
  if (!row) return;
  event.preventDefault();
  toggleRow(row.dataset.rowKey);
});

portfolioBody.addEventListener("input", (event) => {
  const input = event.target.closest("input[data-alert-side]");
  if (!input) return;
  const key = `${input.dataset.rowKey}:${input.dataset.alertSide}`;
  if (input.value) state.alertDrafts.set(key, input.value);
  else state.alertDrafts.delete(key);
});

/* ----------------------------------------------------------------- issues --- */

const ISSUE_TITLES = {
  QUANTITY_MISMATCH: "Количество не совпадает с IBKR",
  AVCO_IBKR_BASIS_DIFFERENCE: "AVCO отличается от базиса IBKR",
  BASIS_NOT_COMPARABLE: "Базис сравнить не удалось",
  RECONCILIATION_INCOMPLETE: "Сверка себестоимости не выполнена",
  POSITION_BASIS_CHECK_DEFERRED: "Сверка себестоимости выполнена частично",
  RECONCILIATION_STALE: "Вердикт сверки устарел",
  RECONCILIATION_MISSING: "Сверка ни разу не выполнялась",
  CURRENCY_MISMATCH: "Валюта позиции у брокера не совпадает",
  ASSET_CLASS_MISMATCH: "Класс актива у брокера не совпадает",
  BROKER_BASIS_INCONSISTENT: "Данные брокера противоречивы",
  POSITIONS_STALE: "Снимок позиций устарел",
  POSITIONS_SECTION_MISSING: "В отчёте нет раздела позиций",
  CASH_REPORT_SECTION_MISSING: "В отчёте нет раздела кэша",
  CASH_SUMMARY_DISAGREES_WITH_CURRENCY_ROWS: "Итог кэша не сходится с валютными строками",
  DUPLICATE_BROKER_POSITION_ROWS: "Брокер вернул дубликаты позиций",
  DATA_SOURCE_WARNING: "Проблема источника данных",
  ACCOUNT_IDENTITY_MISMATCH: "Итог не сходится со счётом",
  UNMATCHED_CASH_EVENT: "Кэш не привязан к инструменту",
  CORPORATE_BASIS_UNALLOCATED: "Себестоимость по КД никуда не перешла",
};

// The pipeline emits English messages; the page is Russian. Where a type has a known
// explanation it wins, and the raw message stays as the fallback for anything new.
const ISSUE_EXPLANATIONS = {
  QUANTITY_MISMATCH: "Рассчитанное количество не совпадает с Open Positions IBKR. Это учётная ошибка, а не разница методов.",
  AVCO_IBKR_BASIS_DIFFERENCE: "Локальный AVCO намеренно отличается от налоговых лотов IBKR (FIFO). Количество при этом сходится.",
  BASIS_NOT_COMPARABLE: "IBKR не отдал пригодный базис либо нет базовой стоимости для сравнения. Себестоимость по этой позиции не сверена.",
  RECONCILIATION_INCOMPLETE: "IBKR отключил расчёт себестоимости в этом отчёте, поэтому сверка не выполнена ни по одной позиции.",
  POSITION_BASIS_CHECK_DEFERRED: "По части позиций IBKR не отдал себестоимость, сверка выполнена не полностью.",
  RECONCILIATION_STALE: "Последняя сверка с IBKR слишком старая, чтобы описывать текущие цифры.",
  RECONCILIATION_MISSING: "Сверка с IBKR ни разу не выполнялась.",
  CURRENCY_MISMATCH: "Валюта позиции у брокера отличается от локальной — все конверсии по этой бумаге под вопросом.",
  ASSET_CLASS_MISMATCH: "IBKR относит инструмент к другому классу активов.",
  BROKER_BASIS_INCONSISTENT: "Себестоимость за единицу и общий итог у самого IBKR не согласуются между собой.",
  POSITIONS_STALE: "Снимок позиций IBKR старше трёх суток: совпадение количеств мало что доказывает.",
  POSITIONS_SECTION_MISSING: "В отчёте не было раздела позиций, использован предыдущий снимок.",
  CASH_REPORT_SECTION_MISSING: "В отчёте не было раздела кэша, использованы предыдущие остатки.",
  CASH_SUMMARY_DISAGREES_WITH_CURRENCY_ROWS: "Итог кэша в базовой валюте не равен сумме валютных строк по курсам того же отчёта.",
  DUPLICATE_BROKER_POSITION_ROWS: "Брокер вернул несколько строк на один conid; сравнивалась только последняя.",
  ACCOUNT_IDENTITY_MISMATCH: "Стоимость активов плюс кэш минус внесённое не равно сумме компонентов результата.",
  UNMATCHED_CASH_EVENT: "Дивиденд или налог не удалось привязать ни к одному инструменту.",
  CORPORATE_BASIS_UNALLOCATED: "Себестоимость, освободившаяся при корпоративном действии, никуда не перешла.",
};

const SEVERITY_RANK = { ERROR: 0, WARNING: 1, INFO: 2 };

function issueNumbers(issue) {
  const parts = [];
  if (issue.local != null || issue.ibkr != null) {
    const currency = issue.comparisonCurrency || issue.currency || "USD";
    parts.push(`локально ${formatMoney(issue.local, currency, true)} · IBKR ${formatMoney(issue.ibkr, currency, true)}`);
  }
  if (issue.differencePercent != null) {
    parts.push(`разница ${formatNumber(issue.differencePercent, 2)} %`);
  }
  if (issue.basisDifferenceUsd != null) {
    parts.push(`на ${formatUsd(issue.basisDifferenceUsd)}`);
  }
  if (issue.count != null) parts.push(`${issue.count} позиц.`);
  if (issue.ageHours != null) parts.push(`возраст ${formatNumber(issue.ageHours, 1)} ч`);
  return parts.join(" · ");
}

function renderIssues(payload) {
  const reconciliationIssues = (payload.reconciliation?.issues || [])
    // INFO items are informational by construction. The AVCO-versus-FIFO difference in
    // particular is the expected consequence of choosing average cost, and listing it
    // once per position taught the reader to skim past the panel entirely.
    .filter((issue) => String(issue.severity || "").toUpperCase() !== "INFO");
  const globalIssues = (payload.globalReviewEvents || []).map((event) => ({
    severity: "ERROR",
    type: event.category,
    message: event.description,
  }));
  const issues = [...reconciliationIssues, ...globalIssues].sort((left, right) => {
    const bySeverity = (SEVERITY_RANK[String(left.severity).toUpperCase()] ?? 3)
      - (SEVERITY_RANK[String(right.severity).toUpperCase()] ?? 3);
    if (bySeverity) return bySeverity;
    return Math.abs(numberValue(right.basisDifferenceUsd) || 0)
      - Math.abs(numberValue(left.basisDifferenceUsd) || 0);
  });
  byId("issuesPanel").hidden = issues.length === 0;
  byId("issuesList").innerHTML = issues.map((issue) => {
    const severity = String(issue.severity || "WARNING").toUpperCase();
    const tone = SEVERITY_RANK[severity] === undefined ? "warning" : severity.toLowerCase();
    const title = ISSUE_TITLES[issue.type] || issue.type;
    const explanation = ISSUE_EXPLANATIONS[issue.type] || issue.message || "";
    const numbers = issueNumbers(issue);
    return `
      <div class="issue-item ${escapeHtml(tone)}">
        <span class="severity">${escapeHtml(severity)}</span>
        <span class="issue-type">${escapeHtml(issue.symbol ? `${issue.symbol} · ${title}` : title)}</span>
        <span class="issue-message">${numbers ? `${escapeHtml(numbers)} — ` : ""}${escapeHtml(explanation)}</span>
      </div>
    `;
  }).join("");
}

/* ------------------------------------------------------------- lifecycle --- */

function renderDashboard(payload) {
  state.payload = payload;
  scopeCache = null;
  state.assetScope = storedScope();
  // Before the first block reads it: the hero is drawn ahead of the filter control.
  pruneScope();
  const version = Number(payload.schemaVersion);
  byId("schemaWarning").hidden = SUPPORTED_SCHEMA_VERSIONS.includes(version);
  if (!SUPPORTED_SCHEMA_VERSIONS.includes(version)) {
    byId("schemaWarning").textContent =
      `Формат данных версии ${payload.schemaVersion} новее этой страницы — часть значений может не отображаться.`;
  }
  renderStatus(payload);
  renderHero(payload);
  renderAccountPanel(payload);
  prepareCharts(payload);
  // Before the charts, so a panel that starts collapsed is measured as collapsed
  // rather than drawn at full width and then folded away.
  applyCollapsed();
  renderCharts();
  alignHeroSide();
  renderFilterOptions(payload.rows || []);
  renderRows();
  renderIssues(payload);
}

function showDashboard(payload, key) {
  state.cryptoKey = key;
  passwordInput.value = "";
  unlockMessage.textContent = "";
  unlockView.hidden = true;
  dashboardView.hidden = false;
  byId("lockButton").hidden = false;
  byId("refreshButton").hidden = false;
  renderDashboard(payload);
}

const CLEARED_ON_LOCK = [
  "kpiGrid", "issuesList", "accountIdentity", "dataStatus", "totalsCheck",
  "heroPanel", "buildupChart", "buildupTable", "timelineChart", "yearChart",
  "classStrip", "allocationChart", "extremesChart",
];

/**
 * Locking has to remove the plaintext from the page, not just hide the container:
 * with the markup still in the DOM the whole portfolio was one devtools inspection
 * away, and a reload restored it outright.
 */
function lockDashboard(message = "") {
  state.payload = null;
  state.cryptoKey = null;
  state.expanded.clear();
  state.alertDrafts.clear();
  state.charts.clear();
  state.sortKey = null;
  state.sortDirection = null;
  portfolioBody.innerHTML = "";
  for (const id of CLEARED_ON_LOCK) byId(id).innerHTML = "";
  for (const id of ["accountPanel", "issuesPanel", "totalsCheck", "buildupPanel",
    "timelinePanel", "allocationPanel", "extremesPanel"]) {
    byId(id).hidden = true;
  }
  tooltip.hidden = true;
  dashboardView.hidden = true;
  unlockView.hidden = false;
  byId("lockButton").hidden = true;
  byId("refreshButton").hidden = true;
  unlockMessage.textContent = message;
  passwordInput.focus();
}

async function unlockWithPassword(password) {
  const key = await deriveKey(password, state.envelope);
  const payload = await decryptEnvelope(state.envelope, key);
  showDashboard(payload, key);
  if (rememberDevice.checked) {
    // After the dashboard is up, and with its own failure path: a storage error is
    // not a wrong password and must not be reported as one.
    try {
      await saveDeviceKey(state.envelope, key);
    } catch {
      unlockMessage.textContent = "Ключ не удалось сохранить на этом устройстве.";
    }
  }
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.envelope) {
    await initialize();
    if (!state.envelope) return;
  }
  unlockButton.disabled = true;
  unlockMessage.textContent = "Расшифровываем…";
  try {
    await unlockWithPassword(passwordInput.value);
  } catch {
    unlockMessage.textContent = "Пароль не подошёл или файл данных повреждён.";
  } finally {
    unlockButton.disabled = false;
  }
});

byId("togglePassword").addEventListener("click", () => {
  passwordInput.type = passwordInput.type === "password" ? "text" : "password";
  byId("togglePassword").textContent = passwordInput.type === "password" ? "Показать" : "Скрыть";
});

byId("lockButton").addEventListener("click", () => lockDashboard());
byId("forgetDevice").addEventListener("click", async () => {
  await forgetDeviceKeys();
  lockDashboard("Сохранённый ключ удалён с этого устройства.");
});

byId("refreshButton").addEventListener("click", async () => {
  const button = byId("refreshButton");
  const label = byId("refreshButtonLabel");
  const feedback = byId("refreshFeedback");
  const previousGeneratedAt = state.payload?.generatedAt || "";
  if (state.refreshTimer) window.clearTimeout(state.refreshTimer);
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.classList.add("is-refreshing");
  label.textContent = "Обновляем…";
  feedback.textContent = "Загружаем свежий снимок…";
  try {
    await loadEnvelope({ bypassCache: true });
    const payload = await decryptEnvelope(state.envelope, state.cryptoKey);
    renderDashboard(payload);
    const changed = Boolean(payload.generatedAt && payload.generatedAt !== previousGeneratedAt);
    label.textContent = changed ? "Обновлено" : "Актуально";
    feedback.textContent = changed
      ? `Обновлено: ${formatDate(payload.generatedAt, true)}`
      : "Новых данных пока нет";
  } catch (error) {
    label.textContent = "Ошибка";
    feedback.textContent = error.message || "Не удалось обновить данные.";
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.classList.remove("is-refreshing");
    state.refreshTimer = window.setTimeout(() => {
      label.textContent = "Обновить";
      feedback.textContent = "";
      state.refreshTimer = null;
    }, 3200);
  }
});

document.querySelector("thead").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-sort]");
  if (!button) return;
  const key = button.dataset.sort;
  if (state.sortKey !== key) {
    state.sortKey = key;
    state.sortDirection = "descending";
  } else if (state.sortDirection === "descending") {
    state.sortDirection = "ascending";
  } else {
    state.sortKey = null;
    state.sortDirection = null;
  }
  renderRows();
});

byId("quickTabs").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-tab]");
  if (!button) return;
  state.activeTab = button.dataset.tab;
  byId("quickTabs").querySelectorAll("button").forEach((item) => item.classList.toggle("active", item === button));
  renderRows();
});

byId("searchInput").addEventListener("input", () => {
  if (state.searchTimer) window.clearTimeout(state.searchTimer);
  state.searchTimer = window.setTimeout(() => {
    state.searchTimer = null;
    renderRows();
  }, SEARCH_DEBOUNCE_MS);
});

["directionFilter", "currencyFilter", "profitFilter", "yearFilter"].forEach((id) => {
  byId(id).addEventListener("change", renderRows);
});

byId("assetScopeOptions").addEventListener("change", applyScope);

// <details> only closes on its own summary. A filter that stays open until you find
// that summary again behaves unlike every other control in the row.
document.addEventListener("click", (event) => {
  const scope = byId("assetScope");
  if (scope.open && !scope.contains(event.target)) scope.open = false;
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  const scope = byId("assetScope");
  if (!scope.open) return;
  scope.open = false;
  scope.querySelector("summary").focus();
});
byId("assetScopeAll").addEventListener("click", () => {
  state.assetScope = new Set();
  persistScope();
  redrawScopedBlocks();
});

byId("resetFilters").addEventListener("click", () => {
  for (const id of ["directionFilter", "currencyFilter", "profitFilter", "yearFilter"]) {
    byId(id).value = "";
  }
  state.assetScope = new Set();
  persistScope();
  byId("searchInput").value = "";
  state.activeTab = "all";
  byId("quickTabs").querySelectorAll("button")
    .forEach((item) => item.classList.toggle("active", item.dataset.tab === "all"));
  redrawScopedBlocks();
});

// Locking on tab-hide protects an unattended screen, but it also closes the dashboard
// every time you switch windows, so it is opt-in and the choice is remembered.
const LOCK_ON_HIDE_KEY = "portfolio-ledger:lock-on-hide";

function lockOnHideEnabled() {
  try {
    return window.localStorage.getItem(LOCK_ON_HIDE_KEY) === "true";
  } catch {
    return false;
  }
}

const lockOnHideToggle = byId("lockOnHide");
lockOnHideToggle.checked = lockOnHideEnabled();
lockOnHideToggle.addEventListener("change", () => {
  try {
    window.localStorage.setItem(LOCK_ON_HIDE_KEY, String(lockOnHideToggle.checked));
  } catch {
    /* private mode: the setting simply does not persist */
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden" && state.payload && lockOnHideEnabled()) {
    lockDashboard("Панель заблокирована, пока вкладка была скрыта.");
  }
});

async function initialize() {
  unlockButton.disabled = true;
  byId("retryLoad").hidden = true;
  unlockMessage.textContent = "Загружаем зашифрованный снимок…";
  try {
    const envelope = await loadEnvelope();
    unlockButton.disabled = false;
    unlockMessage.textContent = "";
    try {
      const savedKey = await loadDeviceKey(envelope);
      if (savedKey) {
        const payload = await decryptEnvelope(envelope, savedKey);
        showDashboard(payload, savedKey);
      }
    } catch {
      await forgetDeviceKeys();
      unlockMessage.textContent = "Сохранённый ключ устарел. Введите пароль снова.";
    }
  } catch (error) {
    unlockMessage.textContent = error.message;
    byId("retryLoad").hidden = false;
  }
}

byId("retryLoad").addEventListener("click", initialize);

/* Charts are drawn at a measured pixel width rather than into a scaled viewBox, so
   they have to be redrawn whenever that width actually changes. Three things change
   it and none of them fired a redraw before: the first paint at a narrow viewport,
   where the panel is measured before the layout has settled; a window resize or a
   phone rotation; and collapsing a neighbouring panel in a two-column row. A chart
   drawn for the previous width is then clipped by its own container, which at 360 px
   cut roughly 60 px — the axis labels and the newest point — off every chart. */
const CHART_HOST_IDS = [
  "heroMeter", "buildupChart", "timelineChart", "yearChart",
  "classStrip", "allocationChart", "extremesChart",
];
const chartHostWidths = new Map();
let chartRedrawHandle = null;

function observeChartHosts() {
  if (typeof ResizeObserver !== "function") return;
  const observer = new ResizeObserver((entries) => {
    let changed = false;
    for (const entry of entries) {
      const width = Math.round(entry.contentRect.width);
      // Only a real change counts: writing the SVG must not feed itself a new event.
      if (width > 0 && chartHostWidths.get(entry.target.id) !== width) {
        chartHostWidths.set(entry.target.id, width);
        changed = true;
      }
    }
    if (!changed || !state.payload) return;
    // A timer rather than requestAnimationFrame: rAF does not run while the tab is
    // hidden, so a redraw scheduled during a background resize would sit pending and
    // the charts would still be wrong the moment the tab came back. The delay also
    // coalesces the burst of events a drag-resize produces.
    if (chartRedrawHandle) clearTimeout(chartRedrawHandle);
    chartRedrawHandle = setTimeout(() => {
      chartRedrawHandle = null;
      renderCharts();
    }, 60);
  });
  for (const id of CHART_HOST_IDS) {
    const host = byId(id);
    if (host) observer.observe(host);
  }
}

observeChartHosts();
initialize();
