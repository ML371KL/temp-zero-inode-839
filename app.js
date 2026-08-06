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
} from "./charts.js?v=20260806-1";

/*
 * The Content-Security-Policy is delivered in a <meta> tag, and a meta CSP cannot
 * carry frame-ancestors — so the no-framing rule lives here instead. Inside someone
 * else's frame the page empties itself and stops: no unlock form, no decryption,
 * nothing for a clickjacking overlay to harvest.
 */
if (window.top !== window.self) {
  document.documentElement.innerHTML = "";
  throw new Error("Portfolio Ledger не работает внутри фрейма.");
}

const SUPPORTED_SCHEMA_VERSIONS = [2, 3];
const SUPPORTED_ENVELOPE_VERSIONS = [1, 2];
// The additional authenticated data the pipeline binds into every envelope. It is a
// constant of the page, never read from the envelope: an envelope vouching for its
// own aad field authenticates nothing, since any envelope agrees with itself.
const EXPECTED_AAD = "temp-zero-inode-839:portfolio:v1";
// A saved key is a standing grant of access to the whole portfolio from this browser
// profile. It expires so that a device left behind stops being a key eventually.
const DEVICE_KEY_MAX_AGE_MS = 12 * 60 * 60 * 1000;
const SEARCH_DEBOUNCE_MS = 200;
// Домен живого слоя. Свой, не payload'а: конверт, открывающийся под чужим AAD, —
// ровно та ошибка, ради которой AAD и существует. Без разделения payload, попавший
// в бакет котировок, расшифровался бы здесь и нарисовался как цены.
const LIVE_QUOTES_AAD = "temp-zero-inode-839:quotes:v1";
const LIVE_QUOTES_FORMAT = "ibkr-quotes-aes-gcm";
// Агент выкладывает снимок не чаще, чем меняются цифры, и держит Cache-Control 10 с.
// Опрашивать чаще — значит платить запросами за один и тот же объект.
const LIVE_QUOTES_REFRESH_MS = 20_000;
// Позже этого срока снимок перестаёт быть живым слоем и убирается со страницы.
// Не «показать посерее»: цена, помеченная как живая и отставшая на десять минут,
// хуже отсутствия живого слоя, потому что по ней принимают решение.
const LIVE_QUOTES_MAX_AGE_MS = 4 * 60 * 1000;

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
  charts: new Map(),
  // The table is the default: it is the exact statement of what the number is made
  // of, and the chart is the illustration of it.
  buildupAsTable: true,
  timelineMode: "absolute",
  // Which asset classes the whole page is about. Empty means every class; the
  // selection is restored from localStorage on load.
  assetScope: new Set(),
  // Conids the pipeline refused to put in its own totals. Rebuilt from every payload.
  quarantined: new Set(),
  // Живой слой. Держится ОТДЕЛЬНО от payload и никогда в него не вписывается:
  // все денежные итоги на странице посчитаны по ценам снимка, и подмена цены в
  // строке развалила бы проверку «итоги равны сумме строк», которая эти итоги и
  // стережёт. Живая цена показывается рядом, а не вместо.
  // Payload в том виде, в каком его опубликовал пайплайн. `state.payload` — он же
  // с подставленными живыми числами; каждое перекрытие считается от снимка.
  snapshot: null,
  liveQuotes: null,
  liveKey: null,
  // Правила алертов, как их видит сервер. Ключ на запись отдельный: тот, что
  // расшифровывает котировки, WebCrypto шифровать не даст.
  alertRules: [],
  alertKey: null,
  alertError: null,
  alertsSentAt: 0,
  // Недонабранное значение и то, где стоял курсор. В DOM это держать нельзя:
  // строку перерисовывает и тик живого слоя, и кнопка обновления, и смена среза —
  // а набранная наполовину цена обязана пережить их все, иначе ввести уровень
  // нельзя в принципе, если печатать медленнее двадцати секунд.
  alertDraft: {},
  alertFocus: null,
  liveError: null,
  liveTimer: null,
};

/* ------------------------------------------------------------ live quotes --- */

/*
 * Живые котировки лежат отдельным зашифрованным объектом, а ключ к нему — внутри
 * payload. Порядок здесь и есть весь смысл схемы: ключ становится известен только
 * после того, как payload открыт паролем, поэтому живой слой не стоит владельцу ни
 * второго ввода пароля, ни одной лишней итерации PBKDF2, а ключ, снятый с сервера,
 * даёт цены и не ведёт обратно к payload.
 */

async function importLiveKey(descriptor) {
  return crypto.subtle.importKey(
    "raw",
    bytesFromBase64(descriptor.key),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
}

async function fetchLiveQuotes(descriptor, key) {
  // no-store, а не reload: объект переписывается чаще, чем истекает любой кэш, и
  // единственный честный ответ на «какая сейчас цена» — тот, что пришёл сейчас.
  const response = await fetch(descriptor.url, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const envelope = await response.json();
  if (envelope.format !== LIVE_QUOTES_FORMAT) {
    throw new Error("Это не конверт живых котировок.");
  }
  const aad = new TextEncoder().encode(LIVE_QUOTES_AAD);
  const declared = bytesFromBase64(envelope.cipher.aad);
  if (declared.length !== aad.length
    || declared.some((byte, index) => byte !== aad[index])) {
    throw new Error("Конверт не от живого слоя.");
  }
  const decrypted = new Uint8Array(await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytesFromBase64(envelope.cipher.iv),
      additionalData: aad,
      tagLength: 128,
    },
    key,
    bytesFromBase64(envelope.ciphertext),
  ));
  const body = String(envelope.compression || "none") === "gzip"
    ? await inflate(decrypted)
    : decrypted;
  return JSON.parse(new TextDecoder().decode(body));
}

/**
 * Перекрытие: денежные числа, пересчитанные сервером по живым ценам.
 *
 * Страница ничего не вычисляет. Числа приходят готовыми, посчитанными той же
 * функцией, которой собран payload, на том же журнале и той же сверке — отличается
 * только таблица котировок. Поэтому проверка «итоги равны сумме строк» сохраняет
 * смысл: она проверяет живые числа ровно так же, как числа снимка.
 *
 * Привязка обязательна. Перекрытие несёт отпечаток payload, для которого посчитано,
 * и если пайплайн уже опубликовал новый, применить старое перекрытие значило бы
 * показать смесь двух прогонов — часть строк из одного, часть из другого, и итог,
 * не равный ни тому ни другому. Тогда его не применяем вовсе: снимок целиком верен.
 */
function overlayForPayload(payload) {
  const overlay = state.liveQuotes?.overlay;
  if (!overlay || !payload) return null;
  const age = liveSnapshotAgeMs();
  if (age === null || age > LIVE_QUOTES_MAX_AGE_MS) return null;
  if (String(overlay.basedOn?.generatedAt || "") !== String(payload.generatedAt || "")) {
    return null;
  }
  return overlay;
}

/**
 * payload с подставленными живыми числами — новый объект, исходный не трогаем.
 *
 * Мутировать `state.payload` было бы дешевле и неверно: перекрытие приходит каждые
 * несколько секунд и каждое следующее считается от снимка, а не от предыдущего
 * результата. Затерев снимок один раз, дальше пришлось бы накладывать поправку на
 * поправку — и первая же пропущенная выгрузка оставила бы страницу с числами,
 * которые не сходятся ни с чем.
 */
function payloadWithLive(payload) {
  const overlay = overlayForPayload(payload);
  if (!overlay) return payload;
  const rows = overlay.rows || {};
  const totals = overlay.totals || {};
  if (!Object.keys(rows).length && !Object.keys(totals).length) return payload;
  return {
    ...payload,
    rows: (payload.rows || []).map((row) => {
      const patch = rows[String(row.rowId ?? "")];
      return patch ? { ...row, ...patch } : row;
    }),
    totals: { ...payload.totals, ...totals },
    ...(overlay.allocation ? { allocation: overlay.allocation } : {}),
  };
}

/* ---------------------------------------------------------------- alerts --- */

/*
 * Правила алертов владелец задаёт здесь, а срабатывают они на сервере — в этом весь
 * смысл: уведомление должно приходить с закрытым браузером. Страница поэтому не
 * хранит состояние алертов, она его отображает: правила уезжают в объект, состояние
 * приезжает обратно вместе с котировками, и единственный источник правды — сервер.
 *
 * Ссылка на запись подписана сервером и лежит внутри зашифрованного объекта, то есть
 * доступна только тому, кто уже открыл payload паролем. Ключей R2 на странице нет.
 */

const ALERT_AAD = "temp-zero-inode-839:alerts:v1";
const ALERT_KINDS = ["BUY_BELOW", "SELL_ABOVE", "DATE"];
// Сколько ждать, пока сервер увидит только что записанные правила, прежде чем
// снова верить его списку. Больше двух тиков живого слоя и меньше времени,
// за которое человек успеет решить, что запись потерялась.
const ALERT_SYNC_GRACE_MS = 90_000;

function alertsSection() {
  return state.liveQuotes?.alerts || null;
}

/** Правила, как их видит сервер, плюс несохранённые местные изменения. */
function alertRules() {
  return state.alertRules || [];
}

function alertStateFor(id) {
  return alertsSection()?.state?.[id] || null;
}

async function encryptAlertRules(rules, key) {
  const body = JSON.stringify({ schemaVersion: 1, rules });
  const bytes = new TextEncoder().encode(body);
  const gz = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
  const compressed = new Uint8Array(await new Response(gz).arrayBuffer());
  const aad = new TextEncoder().encode(ALERT_AAD);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    compressed,
  ));
  return {
    format: "ibkr-alerts-aes-gcm",
    version: 1,
    cipher: {
      name: "AES-GCM",
      iv: base64FromBytes(iv),
      aad: base64FromBytes(aad),
    },
    compression: "gzip",
    ciphertext: base64FromBytes(ciphertext),
  };
}

function base64FromBytes(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Записать правила. Ключ шифрования — тот же, что у котировок, домен другой.
 *
 * Оптимистично: список на экране меняется сразу, а состояние строки говорит, доехало
 * ли. Ждать ответа перед отрисовкой значило бы держать интерфейс замороженным на
 * время сетевого запроса ради изменения, которое почти всегда проходит.
 */
async function saveAlertRules(rules) {
  const url = alertsSection()?.writeUrl;
  if (!url) throw new Error("сервер не выдал ссылку для записи");
  const descriptor = state.payload?.liveQuotes;
  if (!descriptor?.key) throw new Error("нет ключа");
  // Свой ключ на запись: тот, что в state.liveKey, импортирован только на
  // расшифровку, и WebCrypto не даст им зашифровать.
  state.alertKey = state.alertKey || await crypto.subtle.importKey(
    "raw", bytesFromBase64(descriptor.key), { name: "AES-GCM" }, false, ["encrypt"],
  );
  const envelope = await encryptAlertRules(rules, state.alertKey);
  let response;
  try {
    response = await fetch(url, { method: "PUT", body: JSON.stringify(envelope) });
  } catch (error) {
    // fetch падает с "Failed to fetch" на всём, что случилось до ответа, и чаще
    // всего это отбитый предзапрос CORS: PUT — не простой метод, браузер сначала
    // спрашивает OPTIONS, и хранилище обязано разрешить PUT с этого адреса. Само
    // сообщение браузера про это не говорит ни слова, поэтому говорим мы.
    throw new Error(
      "хранилище не приняло запрос — в правилах CORS бакета должен быть разрешён "
      + "метод PUT с адреса дашборда",
    );
  }
  if (!response.ok) throw new Error(`хранилище отказало (${response.status})`);
}

/** Живая котировка строки, если она есть и ещё не протухла. */
function liveQuoteFor(row) {
  const quotes = state.liveQuotes?.quotes;
  if (!quotes) return null;
  return quotes[String(row?.conid ?? "")] || null;
}

function liveSnapshotAgeMs() {
  const generated = timeValue(state.liveQuotes?.generatedAt);
  return generated === null ? null : Date.now() - generated;
}

async function refreshLiveQuotes() {
  const descriptor = state.payload?.liveQuotes;
  if (!descriptor?.url || !descriptor?.key) return;
  try {
    if (!state.liveKey) state.liveKey = await importLiveKey(descriptor);
    const snapshot = await fetchLiveQuotes(descriptor, state.liveKey);
    // Тот же порядок, которого держится обработчик обновления: всякий, кто вернулся
    // из await, обязан заново проверить блокировку. Иначе снимок дорисуется в уже
    // очищенный DOM — то есть после «Закрыть» на экране снова появятся цены.
    if (!state.cryptoKey) return;
    state.liveQuotes = snapshot;
    state.liveError = null;
    // Правила берутся от сервера — он источник правды, а не то, что браузер думает,
    // что записал. Пока висит несохранённое изменение, местный список сохраняется:
    // иначе ответ сервера, отставший на один тик, стёр бы только что добавленный чип.
    // Ответ сервера отстаёт от записи на один-два тика. Раньше он безусловно
    // перетирал местный список — и второй добавленный алерт ложился поверх
    // устаревшего ответа, стирая первый. Пока набор правил у сервера не совпал
    // с тем, что мы отправили, местный список главнее.
    const serverRules = snapshot.alerts?.rules || [];
    const key = (rules) => rules.map((rule) => String(rule.id)).sort().join("|");
    const settled = key(serverRules) === key(state.alertRules || []);
    const waiting = state.alertsSentAt
      && Date.now() - state.alertsSentAt < ALERT_SYNC_GRACE_MS;
    if (settled || !waiting) {
      state.alertRules = serverRules;
      if (settled) state.alertsSentAt = 0;
    }
  } catch (error) {
    // Живой слой не обязателен: страница осталась ровно тем, чем была до него.
    // Поэтому ошибка гасит слой и печатается строкой, а не всплывает наверх.
    state.liveQuotes = null;
    state.liveError = error?.message || String(error);
  }
  if (!state.cryptoKey) return;
  // Пока владелец печатает в панели алертов — не перерисовываем. Тик приходит
  // раз в двадцать секунд и полностью пересобирает строку: набранная наполовину
  // цена исчезала, а фокус уходил в никуда, то есть ввести уровень было нельзя
  // в принципе, если печатать медленнее двадцати секунд. Живые числа подождут
  // до конца ввода — это несравнимо дешевле.
  if (document.activeElement?.closest?.(".alerts-panel")) {
    renderLiveNote();
    return;
  }
  // Перерисовываем целиком, а не только строки: перекрытие двигает и шапку, и
  // аллокацию, и сверку итогов, и рисовать их из разных перекрытий нельзя.
  renderDashboard(state.snapshot || state.payload);
}

function startLiveQuotes() {
  stopLiveQuotes();
  // Единственное поле, которое оставалось: расшифрованный payload целиком висел
  // в памяти вкладки после «Закрыть».
  state.snapshot = null;
  if (!state.payload?.liveQuotes?.url) return;
  refreshLiveQuotes();
  state.liveTimer = window.setInterval(refreshLiveQuotes, LIVE_QUOTES_REFRESH_MS);
}

function stopLiveQuotes() {
  if (state.liveTimer) {
    window.clearInterval(state.liveTimer);
    state.liveTimer = null;
  }
  state.liveQuotes = null;
  state.liveKey = null;
  state.alertKey = null;
  state.alertRules = [];
  state.alertError = null;
  state.alertsSentAt = 0;
  state.alertDraft = {};
  state.alertFocus = null;
  state.liveError = null;
}

/* ------------------------------------------------------------- quarantine --- */

/*
 * An instrument whose executions arrived without an FX rate is converted by the
 * pipeline at a par rate of 1:1 — a rate nobody published. The row survives with all
 * the figures that rate implies, because the money is real and hiding it would be a
 * lie; what the pipeline does instead is leave the instrument out of `payload.totals`
 * and say so in `payload.quarantine`.
 *
 * The page has to draw the same line. Summing every row against totals that exclude
 * one of them makes the two disagree by the whole quarantined amount, and the "totals
 * equal the sum of the rows" check then reports the pipeline as broken when the only
 * thing broken is the page's arithmetic. A snapshot published before this block
 * existed simply quarantines nothing.
 */
function quarantinedConids(payload) {
  return new Set((payload?.quarantine?.fxInstruments || [])
    .map((item) => String(item?.conid ?? ""))
    .filter(Boolean));
}

function isQuarantined(row) {
  return state.quarantined.size > 0 && state.quarantined.has(String(row?.conid ?? ""));
}

/**
 * Every row the page is allowed to add up — the one place the quarantine is applied.
 * The table draws from `payload.rows` directly and keeps showing the excluded rows,
 * flagged; everything that produces a summary figure goes through this instead.
 */
function trustedRows(payload = state.payload) {
  const rows = payload?.rows || [];
  return state.quarantined.size ? rows.filter((row) => !isQuarantined(row)) : rows;
}

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
  return trustedRows().filter(inScope);
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
  // Quarantined instruments are in neither half of the split: they are not part of the
  // kept rows, and they must not be carved out as "excluded" either — their cash flows
  // are the same 1:1 fiction as their totals, and feeding them to the money-weighted
  // return would corrupt a rate the page prints to a basis point.
  const all = trustedRows(payload);
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
  // With something in quarantine the account cannot be split by class at all, and a
  // narrowed headline would be precise-looking and wrong either way. The account
  // result is built on the broker's cash, which holds the quarantined instrument's
  // real money; its own figures are the 1:1 fiction. Subtracting the fiction from the
  // real leaves a number that is neither, and leaving it in puts money from a class
  // nobody selected inside the headline — measured at 8,675 dollars on one snapshot.
  // So a narrowed scope reports what its own instruments did and declines to state a
  // return, and the notice above the table says how much sits outside the totals.
  const undecomposable = state.quarantined.size > 0 && scopeNarrowed();
  const value = {
    rows,
    excluded,
    narrowed: scopeNarrowed(),
    label: scopeLabel(),
    instrumentResult,
    undecomposable,
    result: accountResult === null || undecomposable
      ? instrumentResult
      : accountResult - droppedResult,
    realized: sum("realizedPnlUsd"),
    unrealized: sum("unrealizedPnlUsd"),
    dividends: sum("dividendsNetUsd"),
    fees: sum("otherFeesUsd"),
    // No `openCount` here on purpose. It counted the trusted rows, the hero read it for
    // the "N открытых · M закрытых" pair, and the pair describes what the table lists —
    // quarantined rows included. Leaving the field would leave the wrong one to hand.
    // The solver would be fed par-rate cash flows for the quarantined instrument and
    // would return a rate printed to a basis point. No rate is better than that one.
    moneyWeighted: known && !undecomposable ? xirr(flows) : null,
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
  // Decryption runs against the page's own constant. The declared aad is only
  // checked first so a wrong envelope fails with its real reason instead of the
  // generic authentication error a mismatched AAD would produce below.
  const aad = new TextEncoder().encode(EXPECTED_AAD);
  const declared = bytesFromBase64(envelope.cipher.aad);
  if (declared.length !== aad.length
    || declared.some((byte, index) => byte !== aad[index])) {
    throw new Error("Конверт не для этой страницы.");
  }
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytesFromBase64(envelope.cipher.iv),
      additionalData: aad,
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
  if (!formatter) return `${formatNumber(parsed, digits)} ${escapeHtml(code)}`;
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
/**
 * A share count as a round number, with the exact one on hover when it is not.
 *
 * Fractional holdings come from dividend reinvestment and spin-offs and run to four
 * decimals; printing them in full turned a column of counts into a column of noise.
 */
function quantityCell(value) {
  const parsed = numberValue(value);
  if (parsed === null) return { text: "—", title: "" };
  const exact = formatNumber(value, 8);
  const rounded = formatNumber(Math.round(parsed), 0);
  return { text: rounded, title: rounded === exact ? "" : exact };
}

function perShareDividend(cycle, currency) {
  const total = numberValue(cycle.dividendsNet);
  // Everything that entered the position earns the payout, bought or handed over by
  // a corporate action — the same denominator the entry average divides by. GGB's
  // cycle 2 collected 1661.43 on 5300 bought plus 780 from a stock dividend, and
  // dividing by the 5300 alone overstated the per-share payout by 15 %.
  const quantity = (numberValue(cycle.entryQuantityTotal) || 0)
    + (numberValue(cycle.corporateInQuantity) || 0);
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
const COLLAPSIBLE = ["hero", "buildup", "timeline", "allocation", "extremes", "quality", "income", "account", "issues"];

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

/**
 * Where a row field and the published total for the same money are named differently.
 *
 * Only one is: a row carries `otherFeesUsd`, `payload.totals` publishes the same sum as
 * `instrumentFeesUsd`. Looking the row name up in the totals returned undefined, which
 * `renderTotalsCheck` reads as "the pipeline did not publish this" and skips — so the
 * fees column was never once compared. A five-thousand-dollar drift planted in
 * `totals.instrumentFeesUsd` raised no banner at all while the same drift in
 * `realizedPnlUsd` raised one correctly.
 */
const PUBLISHED_TOTAL_FIELDS = { otherFeesUsd: "instrumentFeesUsd" };

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
  // Against the trusted rows, because that is what was summed: the published totals
  // leave the quarantined instruments out, so an unfiltered page is one whose sum
  // covers every row the pipeline itself counted.
  return rows.length !== trustedRows().length;
}

function renderKpis(payload, rows) {
  // The cards follow the filter, but never the quarantine: a row converted at a par
  // rate of 1:1 is displayed and not added up, here as in `payload.totals`.
  const counted = state.quarantined.size ? rows.filter((row) => !isQuarantined(row)) : rows;
  const { totals, partial } = aggregateRows(counted);
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
    // By ex-date, the same rule `projectRowToYear` files the event under and the same
    // one the income block and the cumulative line follow. "Получено в 2023" was wrong
    // for every dividend whose cash landed in the next calendar year — 36 of them in
    // one snapshot, DOX among them: register closed 28.12.2023, paid 26.01.2024.
    ["Чистые дивиденды", totals.dividendsNetUsd, year ? `По отсечке в ${year}` : "После налогов"],
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
  renderTotalsCheck(payload, counted, totals);
}

/**
 * The cards deliberately reflect the active filter. That makes them impossible to
 * compare against the payload totals unless nothing is filtered out — which is
 * exactly when a mismatch would mean the frontend and the pipeline disagree.
 */
function renderTotalsCheck(payload, rows, totals) {
  const banner = byId("totalsCheck");
  if (isFiltered(rows)) {
    // Emptied, not merely hidden: an ERROR rendered before the filter was applied
    // stayed in the DOM, one `hidden` toggle or one screen reader away from being
    // read as a live verdict on figures it no longer describes.
    banner.hidden = true;
    banner.innerHTML = "";
    return;
  }
  const published = payload.totals || {};
  const drifted = AGGREGATE_FIELDS
    .map((field) => {
      const name = PUBLISHED_TOTAL_FIELDS[field] || field;
      const mine = totals[field];
      const theirs = numberValue(published[name]);
      if (theirs === null) return null;
      return Math.abs(mine - theirs) > 0.01 ? { field: name, mine, theirs } : null;
    })
    .filter(Boolean);
  banner.hidden = drifted.length === 0;
  banner.innerHTML = drifted.map((item) => `
    <div class="issue-item error">
      <span class="severity">ERROR</span>
      <span class="issue-type">${escapeHtml(item.field)}</span>
      <span class="issue-message">Сумма по строкам ${formatUsd(item.mine)} не совпадает с опубликованным итогом ${formatUsd(item.theirs)}</span>
    </div>
  `).join("");
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
  // Every row, quarantined ones included: this is used only for the "N open · M closed"
  // count, which describes the instruments the table lists. Counting trusted rows here
  // while `status.openPositionCount` counts all of them would subtract a quarantined
  // open position from the closed histories and leave the pair short of the table.
  //
  // The invariant is the whole pair, both halves of it: the count the header prints has
  // to equal the number of rows the table would show with only the class filter on.
  // Nothing that summarises money may be read from here — those go through
  // `trustedRows`, and `scope` below is where they come from.
  const rows = payload.rows || [];

  const scope = scopeSummary(payload);
  const result = numberValue(identity.accountResultUsd);
  const fallback = result === null ? numberValue(payload.totals?.totalResultUsd) : null;
  // Narrowed, the headline is what the chosen instruments made. It cannot be the
  // account result: that one includes interest, account fees and the currency
  // conversions, none of which belong to an asset class.
  const headline = scope.narrowed ? scope.result : (result === null ? fallback : result);
  const contributions = numberValue(identity.netContributionsUsd);
  // Net contributions are the account's, and an undecomposable headline is a subset of
  // the instruments — dividing one by the other states a return on money most of which
  // bought something the headline does not count. The rule for a scope the quarantine
  // makes unsplittable is to claim no return at all, and this figure is printed to a
  // tenth of a point; zeroing the XIRR and leaving this one is half a rule.
  const returnOnMoney = contributions && !scope.undecomposable
    ? headline / Math.abs(contributions)
    : null;
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

  // The pair counts what the table lists, narrowed or not — so the narrowed half has to
  // come from `payload.rows` too, only class-filtered. Built on the trusted rows it
  // silently dropped the quarantined ones, and the header said "20 открытых · 257
  // закрытых" while the counter under the very same table said "278 из 303".
  const listedRows = scope.narrowed ? rows.filter(inScope) : rows;
  const openCount = scope.narrowed
    ? listedRows.filter(isOpen).length
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
  // "N из M" read as "N of M positions", but M was the row count — open positions
  // plus every instrument ever closed. Naming the two parts is what the number means.
  const closedCount = listedRows.length - openCount;
  const facts = [
    ["Внесено минус выведено", formatUsd(identity.netContributionsUsd), "",
      contributions === null ? missingHint : ""],
    ["Сейчас на счёте", formatUsd(netAssetValue), "",
      netAssetValue === null ? (payload.accountIdentity ? "нет секции Cash Report" : missingHint) : ""],
    ["Годовая доходность, XIRR", formatPercent(returnRate), pnlClass(returnRate),
      numberValue(returnRate) === null && !scope.narrowed ? missingHint : ""],
    ["Позиции", `${openCount} открытых · ${closedCount} закрытых историй`, "", ""],
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

  // The table ends here when the account cannot be split by class at all. Its closing
  // line is captioned "то же число, что в шапке", and with something in quarantine the
  // header prints `instrumentResult` while the line below would have printed the
  // account result less what was dropped — the very figure the header refused as
  // neither real nor fiction. Two different numbers on one page, one of them with a
  // caption swearing they are the same. So no account-level rows, no residual, no
  // second total: the last line stays the one the header agrees with, and
  // `buildupScopeNote` says why the rest is missing.
  if (scope.undecomposable) return items;

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
      // Normally this gap is the unconverted foreign cash. With an instrument in
      // quarantine it also holds that instrument's real money, which the totals
      // above deliberately leave out — so it stops being "revaluation" and has to
      // stop claiming to be.
      const quarantined = state.quarantined.size > 0;
      items.push({
        label: quarantined ? "Не отнесено к позициям" : "Переоценка валютных остатков",
        value: residual,
        note: quarantined
          ? "переоценка непереведённых валютных остатков плюс реальные деньги инструментов, вынесенных за пределы итогов — см. предупреждение выше"
          : "непереведённые остатки в AUD, CAD, GBP и JPY стоят сегодня иначе, чем в день, когда попали на счёт",
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
 * When a cash event happened, for every block that groups cash events by period.
 *
 * The ex-date, not the payment date: a dividend was earned by the position that held
 * the shares on the day the register closed, and the cash can land weeks later and in
 * the next calendar year. Withholding tax inherits the ex-date of its dividend, or a
 * payment and its own tax could be filed under different years.
 *
 * This is the one rule, in one place, deliberately. The cumulative chart and the
 * income block dated dividends this way while the year filter dated them by payment,
 * so the same page reported two different dividend totals for the same year — 1 742,96
 * apart for 2025 alone. Fees carry no ex-date and are unaffected.
 */
function cashEventDate(event) {
  return event.exDate || event.timestamp;
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

  const add = (time, amount) => {
    if (!amount) return;
    // Undated money is not accumulated here on purpose. It used to be, and the
    // figure was never read: the self-check derives the same quantity as
    // `expected - dated`, which also catches money the line never saw at all —
    // a source `add` was not called for cannot be counted by `add`.
    if (time === null) return;
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
        add(timeValue(cashEventDate(event)), numberValue(event.amountUsd) || 0);
      }
    }
  }

  // Interest, account fees and the result of each currency conversion are dated, so
  // they belong on a line that claims to be cumulative. They are not attributable to
  // an asset class, so they stay whatever the scope is — the same rule the
  // composition block follows. Unrealised P&L is the one thing that cannot be here:
  // it would need the market value of every position on every past day.
  //
  // The exception is the case where the composition block itself stops at the
  // instruments: with money in quarantine and a scope narrowed, the account cannot
  // be split by class at all. Carrying the account-level flows here while the
  // composition drops them left the two blocks nearly twenty thousand dollars
  // apart, each captioned as though it held the same thing.
  const accountLevelBelongsHere = !scopeSummary(payload).undecomposable;
  if (accountLevelBelongsHere) {
    for (const flow of payload.accountCashFlows || []) {
      add(timeValue(flow.timestamp), numberValue(flow.amountUsd) || 0);
    }
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
  // ...and over the same *sources*. When the account-level flows are kept off the
  // line above, adding them here makes the check disagree with the line by exactly
  // their total — twenty thousand dollars on this account — so the page reported
  // that much as "undated", which is false: those movements have dates, they were
  // deliberately left out. Worse, the discrepancy swallowed the check: any genuinely
  // undated drift smaller than it became invisible.
  const expected = sumRows("realizedPnlUsd")
    + sumRows("dividendsNetUsd")
    + sumRows("otherFeesUsd")
    + (accountLevelBelongsHere
      ? (payload.accountCashFlows || [])
        .reduce((total, flow) => total + (numberValue(flow.amountUsd) || 0), 0)
      : 0);
  const yearList = [...years.entries()].sort((left, right) => left[0] - right[0]);
  // The denominator is what the *account* was given, and when the quarantine makes
  // the scope unsplittable the numerator is a subset of the instruments — dividing
  // one by the other draws a curve of "return" on money most of which bought
  // something the line does not count. The headline percentage and the XIRR are
  // already withheld for that reason; this curve is the same claim with a shape.
  const percentUsable = contributed > 0 && accountLevelBelongsHere;
  return {
    points,
    percentPoints: percentUsable
      ? points.map((point) => ({ time: point.time, value: share(point.value), delta: share(point.delta) }))
      : [],
    percentAvailable: percentUsable && points.length >= 2,
    percentBase: percentUsable ? contributed : null,
    years: yearList.map(([year, value]) => ({ label: String(year), value })),
    percentYears: percentUsable
      ? yearList.map(([year, value]) => ({ label: String(year), value: share(value) }))
      : [],
    dated,
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
  const open = trustedRows(payload).filter((row) => isOpen(row)
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

/* ---------------------------------------------------------- trade quality --- */

/**
 * Closed cycles of the visible slice, judged one by one. A cycle's verdict is its
 * whole result — realised price movement, the dividends it earned, the fees it
 * paid — the same `totalResultUsd` the cycle card prints. Anything within half a
 * cent of zero is a scratch, neither win nor loss.
 */
function tradeQualityModel() {
  const rows = scopedRows();
  const closed = [];
  for (const row of rows) {
    for (const cycle of row.cycles || []) {
      if (!cycle.closedAt) continue;
      const fallback = (numberValue(cycle.realizedPnlUsd) || 0)
        + (numberValue(cycle.dividendsNetUsd) || 0);
      const result = numberValue(cycle.totalResultUsd) ?? fallback;
      const openedAt = timeValue(cycle.openedAt);
      const closedAt = timeValue(cycle.closedAt);
      closed.push({
        symbol: String(row.symbol || row.conid),
        result,
        // Whole days held, floored: a cycle opened Monday noon and closed Friday
        // morning was held four days, not five calendar dates.
        days: openedAt !== null && closedAt !== null
          ? Math.floor((closedAt - openedAt) / 86_400_000)
          : null,
      });
    }
  }
  if (!closed.length) return null;

  const wins = closed.filter((cycle) => cycle.result >= 0.005);
  const losses = closed.filter((cycle) => cycle.result <= -0.005);
  const sum = (items) => items.reduce((total, item) => total + item.result, 0);
  const median = (values) => {
    if (!values.length) return null;
    const sorted = [...values].sort((left, right) => left - right);
    const middle = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
  };
  const holdDays = (items) => median(items
    .map((item) => item.days)
    .filter((value) => value !== null));
  const grossProfit = sum(wins);
  const grossLoss = sum(losses);

  // Costs are the whole slice's, open cycles included: a commission is paid whether
  // or not the cycle has closed yet. The realised figure is grossed back up by the
  // costs already deducted from it, so the ratio reads "of what the trades made
  // before costs, this much went to the broker and the taxman".
  const rowSum = (field) => rows.reduce(
    (total, row) => total + (numberValue(row[field]) || 0), 0);
  const costs = rowSum("commissionsUsd") + rowSum("transactionTaxesUsd");
  const grossRealized = rowSum("realizedPnlUsd") + costs;

  // Concentration is by name, never by table row: an instrument traded long and
  // short is two rows but one recurring decision.
  const bySymbol = new Map();
  for (const cycle of closed) {
    bySymbol.set(cycle.symbol, (bySymbol.get(cycle.symbol) || 0) + cycle.result);
  }
  const positive = [...bySymbol.values()]
    .filter((value) => value > 0)
    .sort((left, right) => right - left);
  const positiveTotal = positive.reduce((total, value) => total + value, 0);
  let concentrated = 0;
  let running = 0;
  for (const value of positive) {
    running += value;
    concentrated += 1;
    if (running >= positiveTotal * 0.8) break;
  }

  return {
    count: closed.length,
    wins: wins.length,
    losses: losses.length,
    flats: closed.length - wins.length - losses.length,
    averageWin: wins.length ? grossProfit / wins.length : null,
    medianWin: median(wins.map((item) => item.result)),
    averageLoss: losses.length ? grossLoss / losses.length : null,
    medianLoss: median(losses.map((item) => item.result)),
    profitFactor: grossLoss ? grossProfit / Math.abs(grossLoss) : null,
    expectancy: sum(closed) / closed.length,
    medianHoldWin: holdDays(wins),
    medianHoldLoss: holdDays(losses),
    costs,
    grossRealized,
    concentrated,
    positiveNames: positive.length,
  };
}

function renderQualityPanel() {
  const quality = tradeQualityModel();
  byId("qualityPanel").hidden = !quality;
  if (!quality) {
    byId("qualityStats").innerHTML = "";
    return;
  }
  const days = (value) => (value === null ? "—" : `${formatNumber(value, 1)} дн.`);
  const tableRows = [
    { label: "Закрытых циклов", value: formatNumber(quality.count, 0) },
    {
      label: "Прибыльных / убыточных / в ноль",
      value: `${formatNumber(quality.wins, 0)} / ${formatNumber(quality.losses, 0)} / ${formatNumber(quality.flats, 0)}`,
    },
    { label: "Доля прибыльных", value: percentLabel(quality.wins / quality.count) },
    { label: "Средняя прибыль", value: formatSignedUsd(quality.averageWin), tone: "positive" },
    { label: "Медианная прибыль", value: formatSignedUsd(quality.medianWin), tone: "positive" },
    { label: "Средний убыток", value: formatSignedUsd(quality.averageLoss), tone: "negative" },
    { label: "Медианный убыток", value: formatSignedUsd(quality.medianLoss), tone: "negative" },
    {
      label: "Profit factor, Σ прибылей / |Σ убытков|",
      value: quality.profitFactor === null ? "—" : formatNumber(quality.profitFactor, 2),
    },
    {
      label: "Матожидание на цикл",
      value: formatSignedUsd(quality.expectancy),
      tone: pnlClass(quality.expectancy),
    },
    { label: "Медианное удержание прибыльных", value: days(quality.medianHoldWin) },
    { label: "Медианное удержание убыточных", value: days(quality.medianHoldLoss) },
  ];
  const notes = [
    quality.grossRealized > 0 && quality.costs > 0
      ? `Издержки — комиссии инструментов и налоги сделок ${formatUsd(quality.costs)}: `
        + `${percentLabel(quality.costs / quality.grossRealized)} валового реализованного результата.`
      : "",
    quality.positiveNames
      ? `80 % прибыли закрытых циклов дали ${formatNumber(quality.concentrated, 0)} имён `
        + `из ${formatNumber(quality.positiveNames, 0)} прибыльных.`
      : "",
  ].filter(Boolean);
  byId("qualityStats").innerHTML = chartTable(tableRows, { head: ["Показатель", "Значение"] })
    + notes.map((note) => `<p class="stats-note">${escapeHtml(note)}</p>`).join("");
}

/* ------------------------------------------------------- dividend income --- */

/**
 * Dividend and interest income by year, dated the way the cumulative chart dates
 * them: a dividend belongs to the position that earned it, on its ex-date; interest
 * is the account's, on the day it was credited. This block deliberately ignores the
 * asset-class scope — income history is a property of the whole account.
 */
function renderIncomePanel(payload) {
  const dividendYears = new Map();
  const payers = new Map();
  let dividendTotal = 0;
  for (const row of trustedRows(payload)) {
    const net = numberValue(row.dividendsNetUsd) || 0;
    if (net) {
      const symbol = String(row.symbol || row.conid);
      payers.set(symbol, (payers.get(symbol) || 0) + net);
    }
    for (const cycle of row.cycles || []) {
      for (const event of cycle.cashEvents || []) {
        if (!["DIVIDEND", "WITHHOLDING_TAX"].includes(String(event.category || ""))) continue;
        const year = String(cashEventDate(event) || "").slice(0, 4);
        if (!year) continue;
        const amount = numberValue(event.amountUsd) || 0;
        dividendYears.set(year, (dividendYears.get(year) || 0) + amount);
        dividendTotal += amount;
      }
    }
  }
  const interestYears = new Map();
  let interestTotal = 0;
  for (const flow of payload.accountCashFlows || []) {
    if (String(flow.category || "") !== "INTEREST") continue;
    const year = String(flow.timestamp || "").slice(0, 4);
    if (!year) continue;
    const amount = numberValue(flow.amountUsd) || 0;
    interestYears.set(year, (interestYears.get(year) || 0) + amount);
    interestTotal += amount;
  }

  const years = [...new Set([...dividendYears.keys(), ...interestYears.keys()])].sort();
  byId("incomePanel").hidden = !years.length;
  if (!years.length) {
    byId("incomeStats").innerHTML = "";
    return;
  }

  const yearsTable = `
    <table class="mini-table income-years">
      <thead><tr>
        <th>Год</th>
        <th class="numeric">Дивиденды net, по дате отсечки</th>
        <th class="numeric">Проценты брокера</th>
      </tr></thead>
      <tbody>
        ${years.map((year) => `<tr>
          <th scope="row">${escapeHtml(year)}</th>
          <td class="numeric">${formatUsd(dividendYears.get(year) || 0)}</td>
          <td class="numeric">${formatUsd(interestYears.get(year) || 0)}</td>
        </tr>`).join("")}
        <tr class="is-total">
          <th scope="row">Всего</th>
          <td class="numeric">${formatUsd(dividendTotal)}</td>
          <td class="numeric">${formatUsd(interestTotal)}</td>
        </tr>
      </tbody>
    </table>
  `;
  const top = [...payers.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5);
  const topTable = chartTable(
    top.map(([symbol, value]) => ({ label: symbol, value: formatUsd(value) })),
    { head: ["Плательщик", "Net за всё время"] },
  );

  const gross = numberValue(payload.totals?.dividendsGrossUsd);
  const withheld = numberValue(payload.totals?.withholdingTaxUsd);
  const note = gross && withheld !== null
    ? `Удержано у источника: ${percentLabel(Math.abs(withheld) / gross)} `
      + `(${formatUsd(Math.abs(withheld))} из ${formatUsd(gross)}).`
    : "";

  byId("incomeStats").innerHTML = `
    <div class="income-grid">
      <div><h3>По годам</h3>${yearsTable}</div>
      <div><h3>Топ-5 плательщиков</h3>${topTable}</div>
    </div>
    ${note ? `<p class="stats-note">${escapeHtml(note)}</p>` : ""}
  `;
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
  // The percent mode used to replace the subtitle outright, taking the statement of
  // what the line holds — and any complaint about undated money — with it. Switching
  // the axis does not change either fact.
  byId("timelineNote").textContent = percent
    ? [
      `Тот же результат в процентах от внесённых денег — от ${formatUsd(timeline.percentBase)} за всё время.`,
      state.timelineCoverage || "",
    ].filter(Boolean).join(" ")
    : [state.timelineCoverage || "", state.timelineBridge || ""].filter(Boolean).join(" ");
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
  // Two thresholds, because either alone has a blind spot. The relative one alone
  // cannot judge a scope whose own rows net out to nothing — and dropping the
  // account-level flows from `expected` made that reachable, so a narrowed class
  // summing to zero declared full coverage over eight thousand dollars of real
  // drift. The absolute one alone would cry at rounding on an account this size.
  // A dollar of undated money is worth naming whatever the scope totals.
  const covered = Math.abs(drift) <= 1
    || (Math.abs(timeline.expected) > 1
      && Math.abs(drift) / Math.abs(timeline.expected) < 0.001);
  // The dividend is bucketed by ex-date, which is what `realisedTimeline` reads and
  // which position earned it; the payment can land weeks later and in another year.
  // Sales are dated individually, not at the close of the cycle they belong to. The
  // account-level items are on the line too — except in the one case where the
  // composition block drops them as well, and then the caption must not promise them.
  const accountLevelOnLine = !scopeSummary(payload).undecomposable;
  // The caveat states what the line holds, and that is true whether or not the
  // self-check balanced — so it is a separate sentence rather than the alternative
  // to the complaint. Printing only the complaint left the reader of a narrowed
  // scope with no way to learn that interest, account fees and FX are missing from
  // it, in exactly the case where the page had most to explain.
  const contents = accountLevelOnLine
    ? "Продажи, дивиденды по отсечке, сборы по инструментам, проценты брокера, сборы по счёту и FX-конверсии — по своим датам. Нереализованный P&L не входит."
    : "Продажи, дивиденды по отсечке и сборы выбранных инструментов — по своим датам. Проценты брокера, сборы по счёту и FX-конверсии принадлежат счёту целиком и в этот срез не входят; нереализованный P&L не входит тоже.";
  state.timelineCoverage = covered
    ? contents
    : `${contents} ${formatUsd(drift)} без даты в график не попали.`;

  /*
   * The line ends short of the headline on purpose: the unrealised has no date, the
   * open currency balances have realised nothing, and the closing revaluation
   * belongs to today. The bridge states the exact gap term by term — and is only
   * printed when the payload's own components reproduce the headline to a dollar,
   * so a narrowed scope that drops unrealised money silently drops the line too.
   */
  state.timelineBridge = "";
  const scope = scopeSummary(payload);
  const lineEnd = timeline.points.length
    ? timeline.points[timeline.points.length - 1].value
    : null;
  const unrealized = numberValue(payload.totals?.unrealizedPnlUsd);
  const revaluation = numberValue(payload.accountIdentity?.differenceUsd);
  const accountResult = numberValue(payload.accountIdentity?.accountResultUsd);
  const headline = scope.narrowed ? scope.result : accountResult;
  const currencyOpen = numberValue(payload.accountCash?.currencyOpenUsd);
  if (lineEnd !== null && unrealized !== null && revaluation !== null
    && headline !== null && currencyOpen !== null
    && Math.abs(lineEnd + unrealized + currencyOpen + revaluation - headline) <= 1) {
    // The residual is what the equation itself leaves, checked above against the
    // payload's open-currency figure; printing the residual keeps the sum exact.
    const residual = headline - lineEnd - unrealized - revaluation;
    const term = (label, value) =>
      `${value < 0 ? "−" : "+"} ${label} ${formatUsd(Math.abs(value))}`;
    state.timelineBridge = `Конец линии ${formatUsd(lineEnd)} `
      + `${term("нереализованный P&L", unrealized)} `
      + `${term("валютные остатки", residual)} `
      + `${term(state.quarantined.size ? "не отнесено к позициям" : "переоценка", revaluation)} `
      + `= ${formatUsd(headline)} в шапке.`;
  }
  updateTimelineNote();

  // The percent view divides by dated funding. Offering the button when there is
  // nothing to divide by would just produce an empty plot.
  const percentButton = byId("timelineMode").querySelector('button[data-mode="percent"]');
  percentButton.disabled = !timeline.percentAvailable;
  // The denominator is the *dated* funding, and it can be missing three different
  // ways: no funding at all, funding that nets to zero, and funding whose rows carry
  // no timestamp. The old wording named only the first, so a page printing "Внесено
  // минус выведено 808 290,14 $" two lines below claimed there were no deposits.
  percentButton.title = timeline.percentAvailable
    ? "Тот же результат в процентах от внесённых денег"
    : scopeSummary(payload).undecomposable
      ? "Недоступно: пока часть денег в карантине, доля счёта не делится по классам — знаменателем был бы весь счёт, а числителем только выбранные инструменты"
      : "Недоступно: делить не на что — внесения с датами в снимке отсутствуют, гасят друг друга или в сумме отрицательны";
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

  // Says why the composition stops at the instruments. `buildupItems` drops the
  // account-level rows in this case, and a block that simply ends early looks like
  // data went missing rather than like a figure was declined.
  const buildupScope = scopeSummary(payload);
  // Tolerant of an absent node: a visitor can hold a cached index.html while the
  // browser fetches a newer app.js, and a hard `byId(...).hidden` there threw inside
  // the render, where the catch reported it as a wrong password.
  const buildupNote = byId("buildupScopeNote");
  if (buildupNote) {
    buildupNote.hidden = !buildupScope.undecomposable;
    buildupNote.textContent = buildupScope.undecomposable
      ? "Пока часть инструментов вынесена за пределы итогов, счёт по классам не раскладывается: здесь только выбранные инструменты. Проценты брокера, сборы по счёту и валютные конверсии принадлежат счёту целиком и показаны, когда выбраны все классы."
      : "";
  }

  // Rendered alongside the other derived blocks: the quality table follows the
  // asset-class scope the way the composition block does, the income block by
  // design does not, and both simply recompute on every redraw.
  renderQualityPanel();
  renderIncomePanel(payload);
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

/* ------------------------------------------------------------- quarantine --- */

/** Russian counts three ways, and "1 инструментов" reads as a bug in the page. */
function pluralRu(count, one, few, many) {
  const hundreds = Math.abs(Math.trunc(count)) % 100;
  const tens = hundreds % 10;
  if (hundreds >= 11 && hundreds <= 14) return many;
  if (tens === 1) return one;
  if (tens >= 2 && tens <= 4) return few;
  return many;
}

/**
 * One line saying how much money the page is deliberately not counting.
 *
 * The problems panel already carries the pipeline's own WARNING about it, so this is
 * not a second alarm: it is the amount. Without it the difference between the headline
 * and the sum of the table is unexplained, and the honest answer — "these rows exist,
 * they are shown, they are excluded, and here is by how much" — is unavailable
 * anywhere on the page.
 */
function renderQuarantineNotice(payload) {
  const notice = byId("quarantineNotice");
  const instruments = payload.quarantine?.fxInstruments || [];
  notice.hidden = instruments.length === 0;
  if (!instruments.length) {
    notice.innerHTML = "";
    return;
  }
  // One entry per row representation, not per instrument: an instrument traded both
  // long and short has two rows and lands in the list twice, with one and the same
  // `missing_fx_trades` behind both. That printed "2 инструмента … ALB, ALB" over a
  // single conid. Five instruments on this account are two-directional. The amount is
  // not re-summed from the list for the same reason — the pipeline publishes it.
  const unique = new Map();
  for (const item of instruments) {
    const key = String(item?.conid ?? item?.symbol ?? "?");
    if (!unique.has(key)) unique.set(key, String(item?.symbol || item?.conid || "?"));
  }
  const count = unique.size;
  const word = pluralRu(count, "инструмент", "инструмента", "инструментов");
  const symbols = [...unique.values()].join(", ");
  notice.innerHTML = `
    <strong>${escapeHtml(`Вне итогов: ${count} ${word} на `)}${formatUsd(payload.quarantine?.fxResultUsdAtParRate)}</strong>
    <span>${escapeHtml(`${symbols} — исполнения пришли без валютного курса, и USD-суммы по ним посчитаны по курсу 1:1. Эти суммы ни в одну сводку страницы не входят, строки остаются в таблице. Реальные деньги по этим сделкам лежат в кэше брокера, поэтому в общем результате счёта они есть.`)}</span>
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

/**
 * Одна строка о живом слое — и она обязана быть скучной, когда всё хорошо.
 *
 * Печатает не «сколько котировок пришло», а сколько из них относится к строкам,
 * которые на странице действительно есть: снимок содержит только открытые позиции,
 * и «9 живых» рядом с таблицей из 309 строк читалось бы как поломка.
 */
function renderLiveNote() {
  const container = byId("liveQuotesNote");
  if (!container) return;
  const descriptor = state.payload?.liveQuotes;
  if (!descriptor?.url) {
    container.hidden = true;
    container.textContent = "";
    return;
  }
  container.hidden = false;

  if (state.liveError) {
    container.className = "live-note live-note-off";
    container.textContent = `живые цены недоступны · ${state.liveError} · показан снимок`;
    return;
  }
  const age = liveSnapshotAgeMs();
  if (age === null || age > LIVE_QUOTES_MAX_AGE_MS) {
    container.className = "live-note live-note-off";
    container.textContent = "живые цены устарели · показан снимок";
    return;
  }
  const quotes = state.liveQuotes?.quotes || {};
  const values = Object.values(quotes);
  const delayed = values.filter((quote) => Number(quote?.delayedByMinutes) > 0).length;
  const derived = values.filter((quote) => quote?.derivedFrom).length;
  // Главное в этой строке — действует ли пересчёт. Живые цены без него означают
  // совсем другое: деньги на странице всё ещё от снимка.
  const applied = Boolean(overlayForPayload(state.snapshot));
  const parts = [applied
    ? `живые цены: ${values.length}, деньги пересчитаны`
    : `живые цены: ${values.length}, деньги из снимка`];
  // Отложенные и выведенные считаются отдельно, потому что это разные вещи и обе
  // надо назвать: первая — цена биржи, которую та придерживает, вторая — цена,
  // которой на этой площадке вообще не печатали.
  if (delayed) parts.push(`с задержкой биржи: ${delayed}`);
  if (derived) parts.push(`выведено из листинга США: ${derived}`);
  parts.push(`обновлено ${Math.round(age / 1000)} с назад`);
  container.className = "live-note live-note-on";
  container.textContent = parts.join(" · ");
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
      // The same date `projectRowToYear` files the event under, or the list could
      // offer a year with nothing in it and withhold one that has something.
      for (const event of cycle.cashEvents || []) years.add(String(cashEventDate(event) || "").slice(0, 4));
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
 * Whether the instrument is open today, surviving the year projection. The
 * projection nulls the quantity because a position belongs to no year, which made
 * `isOpen` read every projected row as closed: the open tab under a year showed a
 * "Закрыта" pill on every row and the grouping filed them all under closed history.
 * Openness belongs to today, so it is carried over from the source row instead.
 */
function isOpenNow(row) {
  return row.openNow ?? isOpen(row);
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

// `isOpenNow`, not `isOpen`: under a year filter the default order is what the
// grouping walks, and grouping by a flag the sort ignores would emit a new group
// band at every flip between an open and a closed instrument.
function defaultRowCompare(left, right) {
  const openDifference = Number(isOpenNow(right)) - Number(isOpenNow(left));
  if (openDifference) return openDifference;
  if (isOpenNow(left)) {
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
    // Dividends by ex-date, the same rule the cumulative chart and the income block
    // read: filed by the payment date instead, this block disagreed with both of them
    // about how much the same year paid.
    const cash = (cycle.cashEvents || []).filter((event) => inYear(cashEventDate(event)));
    if (!trades.length && !cash.length) continue;
    cycles.push(cycle);
    const multiplier = numberValue(cycle.multiplier) || 1;
    for (const trade of trades) {
      seen(trade.timestamp);
      realised += numberValue(trade.realizedUsd) || 0;
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
      // The date it was filed under, so the row's own from–to line cannot fall outside
      // the year the row was projected into.
      seen(cashEventDate(event));
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
    // The openness of the source row, for the status pill, the grouping and the
    // "сейчас" cell: the projected quantity below is null and says nothing about it.
    openNow: isOpen(row),
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
    // A trade's `commission` and `taxes` are in the instrument's own currency —
    // summed into these USD fields they printed CAD totals with a dollar sign
    // (YGR 2023: "−315,72 $" for what is ~236 USD). There is no per-trade USD
    // figure to re-sum and no honest rate to invent, so the year view withholds
    // the lines; the card hides them through `optional()`.
    commissionsUsd: null,
    transactionTaxesUsd: null,
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
    if (state.activeTab === "review" && source.status !== "REVIEW" && !isQuarantined(source)) continue;
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

// A quarantined row is a row whose money the page will not vouch for, which is what
// the review pill says. The pipeline marks it too; asserting it here as well means the
// label cannot drift apart from the arithmetic that produced the quarantine.
function statusLabel(row) {
  if (row.status === "REVIEW" || isQuarantined(row)) return "Проверить";
  return isOpenNow(row) ? "Открыта" : "Закрыта";
}

function statusClass(row) {
  if (row.status === "REVIEW" || isQuarantined(row)) return "review";
  return isOpenNow(row) ? "open" : "closed";
}

/** The line under the status pill: what the position is, and whether it counts. */
function rowNote(row) {
  return [
    row.direction,
    row.assetClass,
    isQuarantined(row) ? "вне итогов: курс 1:1" : "",
  ].filter(Boolean).join(" · ");
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

/**
 * The break-even card and one honest sentence. The former alert-draft inputs kept
 * half-typed prices in memory, notified nobody and pretended otherwise; native IBKR
 * alerts do the actual job, so the card now just says so.
 */
/**
 * Панель алертов — единственный ввод на странице, где всё остальное вывод.
 *
 * Поэтому она и выглядит иначе: карточка-с-полями рядом с карточками-с-числами, в
 * которые начнут тыкать как в неё, если их не различить. Тип — сегментированный
 * переключатель, а не список: вариантов три, они всё время на виду, и клик один
 * вместо двух. Подписи зависят от направления позиции — шорту закрывающая сделка
 * это откуп, и назвать её продажей значило бы назвать не ту сделку.
 */
/**
 * Число из того, что человек действительно набирает.
 *
 * `replace(",", ".")` меняет ТОЛЬКО первую запятую, поэтому «1 234,56» превращалось
 * в «1 234.56» с пробелом и давало NaN, а «1,234,56» — в «1.234,56». Здесь: пробелы
 * (включая неразрывный, который приезжает вставкой из самой страницы) выбрасываются,
 * а разделителем считается ПОСЛЕДНИЙ знак — остальные это разряды. Так «1,234.56» и
 * «1 234,56» дают одно и то же, и обе привычки работают.
 */
function parseDecimalInput(raw) {
  const cleaned = String(raw ?? "").replace(/[\s\u00a0\u202f]/g, "");
  if (!cleaned) return null;
  const lastSeparator = Math.max(cleaned.lastIndexOf(","), cleaned.lastIndexOf("."));
  const normalized = lastSeparator === -1
    ? cleaned
    : cleaned.slice(0, lastSeparator).replace(/[.,]/g, "") + "." + cleaned.slice(lastSeparator + 1);
  if (!/^-?\d*\.?\d*$/.test(normalized)) return null;
  const value = Number(normalized);
  return Number.isFinite(value) ? value : null;
}

/**
 * Дата в том виде, в каком её пишут здесь: ДД-ММ-ГГГГ.
 *
 * Хранится и проверяется на сервере она в ISO, и переводится ровно на границе —
 * ввод разбирается сюда, вывод форматируется отсюда. Держать в состоянии местный
 * формат значило бы гонять его через шифрование и сверку, где он ничей.
 */
function parseLocalDate(raw) {
  const match = /^(\d{2})[-./](\d{2})[-./](\d{4})$/.exec(String(raw ?? "").trim());
  if (!match) return null;
  const [, day, month, year] = match;
  const iso = `${year}-${month}-${day}`;
  const parsed = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return null;
  // Отсеивает 31-02-2026: Date такое молча переносит на март.
  if (parsed.toISOString().slice(0, 10) !== iso) return null;
  return iso;
}

function formatLocalDate(iso) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(iso ?? ""));
  return match ? `${match[3]}-${match[2]}-${match[1]}` : String(iso ?? "");
}

function alertsPanelMarkup(row) {
  const conid = String(row.conid ?? "");
  const short = String(row.direction || "").toUpperCase() === "SHORT";
  const rules = alertRules().filter((rule) => String(rule.conid) === conid);
  const quote = displayQuote(row);
  const price = numberValue(quote.price);
  const section = alertsSection();
  const offline = !section?.writeUrl;
  const failure = state.alertError?.conid === conid ? state.alertError.message : "";
  const draft = state.alertDraft[conid];

  const kinds = [
    ["BUY_BELOW", short ? "Откупить" : "Купить", "цена опустится до"],
    ["SELL_ABOVE", short ? "Нарастить" : "Продать", "цена поднимется до"],
    ["DATE", "Дата", "наступит день (ДД-ММ-ГГГГ)"],
  ];
  const chips = rules.map((rule) => alertChipMarkup(rule)).join("");

  return `
    <div class="alerts-panel" data-alert-conid="${escapeHtml(conid)}">
      <span class="alerts-title">Уведомить меня, когда…</span>
      <div class="alerts-kinds" role="group" aria-label="Тип уведомления">
        ${kinds.map(([kind, label, hint], index) => `
          <button type="button" class="alerts-kind ${index === 0 ? "is-active" : ""}"
            data-alert-kind="${kind}" data-alert-hint="${escapeHtml(hint)}"
            aria-pressed="${index === 0}">${escapeHtml(label)}</button>`).join("")}
      </div>
      <div class="alerts-entry">
        <label class="alerts-hint" for="alert-value-${escapeHtml(conid)}">${escapeHtml(kinds[0][2])}</label>
        <div class="alerts-row">
          <input id="alert-value-${escapeHtml(conid)}" class="alerts-input" type="text"
            inputmode="decimal" autocomplete="off"
            value="${escapeHtml(draft === undefined ? (price === null ? "" : String(price)) : draft)}"
            data-alert-current-price="${price === null ? "" : escapeHtml(String(price))}"
            data-alert-currency="${escapeHtml(quote.currency || row.currency || "")}" />
          <button type="button" class="alerts-add" ${offline ? "disabled" : ""}>Добавить</button>
        </div>
        <p class="alerts-feedback ${failure ? "is-bad" : ""}" role="status">${escapeHtml(failure)}</p>
      </div>
      ${chips ? `<div class="alerts-chips">${chips}</div>` : ""}
      ${offline
        ? '<p class="alerts-offline">Сервер уведомлений недоступен — правила сейчас не сохранить.</p>'
        : ""}
    </div>
  `;
}

/**
 * Одно правило. Состояние честное и это важнее вида: алерт, который выглядит
 * поставленным и не доехал, хуже отсутствующего.
 */
function alertChipMarkup(rule) {
  const status = alertStateFor(rule.id);
  const pending = rule._pending;
  const failed = rule._failed;
  const fired = status?.firedAt;
  const blocked = status?.blockedBy;

  let tone = "is-armed";
  let note = "проверяется на сервере";
  if (pending) { tone = "is-pending"; note = "сохраняется…"; }
  else if (failed) { tone = "is-failed"; note = "не сохранён — повторить"; }
  else if (fired) { tone = "is-fired"; note = `сработал ${formatDateShort(fired, "time")}`; }
  else if (blocked) { tone = "is-blocked"; note = `ждёт живой цены (${blocked})`; }

  const what = rule.kind === "DATE"
    ? escapeHtml(formatLocalDate(rule.date))
    : `${rule.kind === "BUY_BELOW" ? "≤" : "≥"} ${escapeHtml(rule.price)}`;
  const label = rule.kind === "DATE" ? "дата" : (rule.kind === "BUY_BELOW" ? "покупка" : "продажа");

  return `
    <span class="alert-chip ${tone}" data-alert-id="${escapeHtml(rule.id)}" title="${escapeHtml(note)}">
      <span class="alert-chip-what">${escapeHtml(label)} ${what}</span>
      <span class="alert-chip-note">${escapeHtml(note)}</span>
      <button type="button" class="alert-chip-remove" aria-label="Убрать уведомление">×</button>
    </span>
  `;
}

/**
 * Ряд из двух карточек: слева ввод, справа число. Порядок не декоративный —
 * читают слева направо, а безубыточность это ответ на вопрос, который задаёт
 * панель слева: до какой цены имеет смысл ждать.
 */
function levelsMarkup(row) {
  return `
    <div class="levels-panel">
      ${alertsPanelMarkup(row)}
      ${breakEvenMarkup(row)}
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
    // A closed cycle has no remainder by definition, so the slot is better spent on
    // what actually went through it. Which side "entry" is depends on the direction:
    // a short opens by selling and closes by buying.
    const entryQuantity = numberValue(cycle.entryQuantityTotal) || 0;
    const exitQuantity = numberValue(cycle.exitQuantityTotal) || 0;
    const corporateOut = numberValue(cycle.corporateOutQuantity) || 0;
    const short = cycle.direction === "SHORT";
    const openedLabel = short ? "Продано" : "Куплено";
    const closedLabel = short ? "Куплено" : "Продано";
    // The entry average divides by everything that entered the position, bought or
    // handed over by a corporate action — GGB's basis of 23697 is spread over 5300
    // bought plus 780 from a stock dividend, so printing 5300 beside a price of 3.90
    // invites a multiplication that misses by four thousand. Verified against all nine
    // cycles that have a corporate action: the entry average is always over this sum,
    // and bought + received - surrendered always equals sold.
    const entrySide = entryQuantity + corporateIn;
    const sidesDiffer = !open && Math.abs(entrySide - exitQuantity) > 1e-9;
    const entrySideCell = quantityCell(entrySide);
    const exitCell = quantityCell(exitQuantity);
    const remainderCell = quantityCell(cycle.quantity);
    const corporateNote = (corporateIn || corporateOut)
      ? `${formatNumber(entryQuantity, 8)} куплено`
        + (corporateIn ? `, ${formatNumber(corporateIn, 8)} получено по корпоративному действию` : "")
        + (corporateOut ? `, ${formatNumber(corporateOut, 8)} ушло по корпоративному действию` : "")
        + `, ${formatNumber(exitQuantity, 8)} продано`
      : "";
    const soldQuantity = numberValue(cycle.exitQuantityTotal) || 0;
    const exitAverage = numberValue(cycle.averageExit);
    const partial = open && soldQuantity > 0 && exitAverage !== null;
    // The entry price attributable to the closed part of the cycle. For a long the
    // sold shares cost their proceeds less what they realised; a short's entry is
    // the buyback cost plus the result — the same identity with the realisation's
    // sign flipped, because a short realises by buying back cheaper than it sold.
    const realizedPart = numberValue(cycle.realizedPnl) || 0;
    const soldCostPerShare = partial
      ? (exitAverage * soldQuantity + (short ? realizedPart : -realizedPart)) / soldQuantity
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
          ${open ? `
          <span><small${corporateNote ? ` title="${escapeHtml(corporateNote)}"` : ""}>Остаток</small><b${remainderCell.title ? ` title="${escapeHtml(remainderCell.title)}"` : ""}>${remainderCell.text}${corporateIn ? ` · ${quantityCell(corporateIn).text} по КД` : ""}</b>${
            partial ? `<small class="cycle-sub">${escapeHtml(closedLabel)}</small><b class="cycle-sub"${exitCell.title ? ` title="${escapeHtml(exitCell.title)}"` : ""}>${exitCell.text}</b>` : ""
          }</span>
          ` : `
          <span><small${corporateNote ? ` title="${escapeHtml(corporateNote)}"` : ""}>${
            // Three cycles hold shares that arrived from a spin-off with nothing bought
            // at all. "Куплено 0" is true and useless; naming the corporate action is.
            !entryQuantity && corporateIn
              ? (sidesDiffer ? "Получено по КД" : "Получено по КД и продано")
              : sidesDiffer
                ? escapeHtml(openedLabel)
                : `${escapeHtml(openedLabel)} и ${escapeHtml(closedLabel.toLowerCase())}`
          }</small><b${entrySideCell.title ? ` title="${escapeHtml(entrySideCell.title)}"` : ""}>${entrySideCell.text}</b>${
            sidesDiffer
              ? `<small class="cycle-sub">${escapeHtml(closedLabel)}</small><b class="cycle-sub"${exitCell.title ? ` title="${escapeHtml(exitCell.title)}"` : ""}>${exitCell.text}</b>`
              : ""
          }</span>
          `}
          <span><small${partial ? ' title="AVCO того, что осталось в позиции, а не всего купленного за цикл"' : ""}>Средний вход</small><b>${
            formatMoney(cycle.averageEntry, row.currency, true)
          }</b>${
            partial ? `<small class="cycle-sub" title="${escapeHtml(short
              ? "По какой цене были открыты выкупленные контракты: затраты на выкуп плюс то, что они принесли"
              : "Во что обошлись проданные акции: выручка за вычетом того, что они принесли")}">${escapeHtml(closedLabel)}</small><b class="cycle-sub">${formatMoney(soldCostPerShare, row.currency, true)}</b>` : ""
          }</span>
          <span><small>Средний выход</small><b${open && !partial ? ' title="Цикл открыт и ничего ещё не продано"' : ""}>${
            open ? '<span class="muted-value">—</span>' : formatMoney(cycle.averageExit, row.currency, true)
          }</b>${
            partial ? `<small class="cycle-sub">${escapeHtml(closedLabel)}</small><b class="cycle-sub">${formatMoney(cycle.averageExit, row.currency, true)}</b>` : ""
          }</span>
          <span><small>Дивиденды на акцию</small><b${dividend ? ` title="За цикл получено ${escapeHtml(dividend.total)}"` : ""}>${
            dividend ? dividend.text : '<span class="muted-value">—</span>'
          }</b></span>
          <span><small>Операций</small><b>${(cycle.trades || []).length}</b></span>
        </div>
      </article>
    `;
  }).join("") || '<div class="muted-value">Циклы отсутствуют</div>';
}

/**
 * Цена последнего выхода из инструмента и движение цены с тех пор.
 *
 * Выход — это `action: "EXIT"`, а не «продажа»: для длинной позиции выходом
 * действительно является продажа, для короткой — обратный выкуп. Поле `action`
 * уже различает их правильно, и брать вместо него `side` значило бы для шортов
 * показать цену открытия вместо цены закрытия.
 *
 * Берётся последняя по времени сделка, а не средняя цена выхода: вопрос владельца —
 * «почём я вышел в последний раз», а `averageExit` отвечает на другой.
 */
function lastExitTrade(row) {
  let best = null;
  for (const cycle of row?.cycles || []) {
    for (const trade of cycle?.trades || []) {
      if (String(trade?.action || "").toUpperCase() !== "EXIT") continue;
      if (numberValue(trade?.price) === null) continue;
      if (!best || String(trade.timestamp || "") > String(best.timestamp || "")) {
        best = trade;
      }
    }
  }
  return best;
}

/**
 * Плашка «сколько цена прошла с моего выхода».
 *
 * Знак раскрашен одинаково для длинных и коротких, и это осознанно: величина
 * отвечает на вопрос «не рано ли я вышел и стоит ли заходить снова», а не на
 * вопрос о прибыли. Для шорта зелёный здесь НЕ означает заработок, поэтому
 * подпись в title говорит, что это движение цены, а не результат.
 */
function lastExitTileHtml(row) {
  const exit = lastExitTrade(row);
  if (!exit) return "";
  const short = String(row.direction || "").toUpperCase() === "SHORT";
  const label = short ? "Последняя цена откупа" : "Последняя цена продажи";
  const exitPrice = numberValue(exit.price);
  const shown = formatMoney(exit.price, row.currency, true);

  // Живая цена, если она есть, иначе цена снимка: смысл плашки — расстояние до
  // текущего рынка, и считать его от вчерашней цены значит отвечать не на тот вопрос.
  const live = liveQuoteFor(row);
  const fresh = live && liveSnapshotAgeMs() !== null
    && liveSnapshotAgeMs() <= LIVE_QUOTES_MAX_AGE_MS ? live : null;
  const current = numberValue((fresh || row.currentPrice || {}).price);

  let drift = "";
  if (current !== null && exitPrice) {
    const percent = ((current - exitPrice) / Math.abs(exitPrice)) * 100;
    const tone = Math.abs(percent) < 0.005 ? "" : (percent > 0 ? "positive" : "negative");
    const sign = percent > 0 ? "+" : "";
    drift = ` <span class="exit-drift ${tone}">${escapeHtml(sign + formatNumber(percent, 2))} %</span>`;
  }
  const title = [
    `выход ${formatDate(exit.timestamp, true)}`,
    exit.quantity ? `количество ${formatNumber(exit.quantity, 8)}` : null,
    current === null ? null : `текущая ${formatMoney(current, row.currency, true)}`
      + (fresh ? " (живая)" : " (снимок)"),
    "процент — движение цены с момента выхода, а не результат по позиции",
  ].filter(Boolean).join(" · ");

  return `<div class="detail-item" title="${escapeHtml(title)}"><span>${label}</span>`
    + `<strong>${shown}${drift}</strong></div>`;
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
            ${lastExitTileHtml(row)}
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
        }<div class="cycle-list">${cycleMarkup(row)}</div>${levelsMarkup(row)}</section>
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

/**
 * Цена, которую показывает строка, — одна.
 *
 * Живая берётся только тогда, когда действует перекрытие: деньги в этой же строке
 * пересчитаны сервером именно по ней. Без перекрытия живая цена рядом со стоимостью
 * из снимка — это строка, противоречащая себе, и тогда честнее показать цену снимка,
 * от которой посчитано всё остальное.
 */
function displayQuote(row) {
  if (!overlayForPayload(state.snapshot)) return row.currentPrice || {};
  const live = liveQuoteFor(row);
  return live || row.currentPrice || {};
}

function rowHtml(row, scale) {
  const quote = displayQuote(row);
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
    // Задержка биржи называется словами, а не прячется в оттенок: цена Торонто
    // приходит с текущей меткой времени и отстаёт на пятнадцать минут, и это
    // единственное место, где страница может об этом сказать.
    Number(quote.delayedByMinutes) > 0 ? `задержка ${quote.delayedByMinutes} мин` : null,
    quote.derivedFrom ? `выведено из ${quote.derivedFrom.usSymbol || "США"}` : null,
    FRESHNESS_LABELS[String(quote.freshness || "").toLowerCase()],
  ].filter(Boolean).join(" · ");
  const open = isOpenNow(row);
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
      <td class="status-cell"><span class="status-pill ${statusClass(row)}">${statusLabel(row)}</span><span class="row-note">${escapeHtml(rowNote(row))}</span></td>
      <td class="cycle-cell"><span class="cycle-line">${cycleFrom}</span><span class="cycle-line">${cycleTo}</span></td>
      <td class="numeric quantity-cell">${formatNumber(row.quantity, 8)}</td>
      <td class="numeric">${formatMoney(rowAverageEntry(row), row.currency, true)}</td>
      <td class="numeric">${open && row.openNow === undefined ? '<span class="muted-value">—</span>' : formatMoney(row.lifetimeAverageExit ?? row.averageExit, row.currency, true)}</td>
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
  const openCount = grouped ? rows.filter(isOpenNow).length : 0;
  let previousGroup = null;
  const markup = [];
  for (const row of rows) {
    if (grouped) {
      const group = isOpenNow(row) ? "open" : "closed";
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
  toggleRow(event.target.closest("tr.data-row")?.dataset.rowKey);
});

portfolioBody.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("tr.data-row");
  if (!row) return;
  event.preventDefault();
  toggleRow(row.dataset.rowKey);
});

/* ----------------------------------------------------------------- issues --- */

const ISSUE_TITLES = {
  SETTLEMENT_DAY_UNKNOWN: "Выписку не удалось привязать ко дню",
  MARK_DATE_MISMATCH: "Марка брокера снята не в день остатков",
  CASH_DATE_BORROWED: "День остатков взят из снимка позиций",
  QUANTITY_MISMATCH: "Количество не совпадает с IBKR",
  AVCO_IBKR_BASIS_DIFFERENCE: "AVCO отличается от базиса IBKR",
  BASIS_NOT_COMPARABLE: "Базис сравнить не удалось",
  RECONCILIATION_INCOMPLETE: "Сверка себестоимости не выполнена",
  POSITION_BASIS_CHECK_DEFERRED: "Сверка себестоимости выполнена частично",
  RECONCILIATION_STALE: "Вердикт сверки устарел",
  RECONCILIATION_DATE_INVALID: "Дату последней сверки прочитать не удалось",
  RECONCILIATION_DATE_IN_FUTURE: "Вердикт сверки датирован будущим",
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
  QUARANTINED_FX_EXECUTIONS: "Исполнения без валютного курса",
  QUARANTINED_CASH: "Кэш без пересчёта в доллары",
  UNCLASSIFIED_CASH_IN_RESULT: "Неклассифицированный кэш внутри итога",
};

// The pipeline emits English messages; the page is Russian. Where a type has a known
// explanation it wins, and the raw message stays as the fallback for anything new.
const ISSUE_EXPLANATIONS = {
  SETTLEMENT_DAY_UNKNOWN: "В выписке есть позиции, но день, на который снят баланс, установить не удалось: либо у позиций нет даты, либо её нет у остатков, либо она есть, но не является датой. Пока это так, маржинальный контракт, открытый после снятия баланса, неотличим от того, что брокер уже рассчитал, а итог по счёту не с чем сверить.",
  MARK_DATE_MISMATCH: "Расчётная цена маржинального контракта у брокера относится не к тому дню, на который сняты остатки по счёту. Оценить контракт по такой цене нельзя: вариационная маржа за прошедшие дни уже лежит в кэше, и стоимость контракта учла бы её второй раз. Контракты оставлены вне стоимости счёта. Замыкающее тождество при этом проверено: отброшенная нога возвращается на место, и вердикт рядом относится к счёту целиком.",
  CASH_DATE_BORROWED: "У остатков по счёту не было читаемой даты, поэтому днём баланса взята дата снимка позиций. Если снимок и остатки на самом деле относятся к разным дням, стоимость счёта, оценка маржинальных контрактов и замыкающее тождество описывают не тот день — и расхождение спишется на цифры, хотя причина в дате.",
  QUANTITY_MISMATCH: "Рассчитанное количество не совпадает с Open Positions IBKR. Это учётная ошибка, а не разница методов.",
  AVCO_IBKR_BASIS_DIFFERENCE: "Локальный AVCO намеренно отличается от налоговых лотов IBKR (FIFO). Количество при этом сходится.",
  BASIS_NOT_COMPARABLE: "IBKR не отдал пригодный базис либо нет базовой стоимости для сравнения. Себестоимость по этой позиции не сверена.",
  RECONCILIATION_INCOMPLETE: "IBKR отключил расчёт себестоимости в этом отчёте, поэтому сверка не выполнена ни по одной позиции. Это независимая перепроверка вашего среднего входа против расчёта брокера; на публикуемые числа она не влияет, замыкающее тождество проверено отдельно. Обычно снимается сама, когда брокер досчитает.",
  POSITION_BASIS_CHECK_DEFERRED: "IBKR отключил расчёт себестоимости в этом отчёте, поэтому по перечисленным позициям сверка не выполнена. По остальным — выполнена. Это независимая перепроверка вашего среднего входа против расчёта брокера; на публикуемые числа она не влияет, замыкающее тождество проверено отдельно. Обычно снимается сама, когда брокер досчитает.",
  DATA_SOURCE_WARNING: "Это дословное уведомление самого IBKR из выписки, а не вывод дашборда: брокер сообщает, что часть расчётов на его стороне недоступна. Строка приведена как есть, потому что переписывать чужую диагностику — значит терять её. Что именно из-за этого не проверено, сказано отдельной строкой выше или ниже.",
  RECONCILIATION_STALE: "Последняя сверка с IBKR слишком старая, чтобы описывать текущие цифры.",
  RECONCILIATION_DATE_INVALID: "У последней сверки с IBKR нечитаемая отметка времени, поэтому проверить, описывает ли она сегодняшние цифры, невозможно. Считайте сверку невыполненной, пока не пройдёт следующая.",
  RECONCILIATION_DATE_IN_FUTURE: "Последняя сверка с IBKR датирована будущим — обычно это сбитые часы на машине, которая её записала. Пока это так, возраст вердикта ничего не означает, и свежим он считаться не может.",
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
  // The pipeline announces the quarantine here; the plate under the header states the
  // amount. Both are wanted: the panel says a rule fired, the plate says how much money.
  QUARANTINED_FX_EXECUTIONS: "У части исполнений нет опубликованного курса валюты, поэтому долларовые суммы по этим инструментам посчитаны по курсу 1:1 и вынесены за пределы итогов.",
  QUARANTINED_CASH: "Кэш-события без долларовой оценки: в долларовые итоги они не входят, суммы известны только в своей валюте.",
  UNCLASSIFIED_CASH_IN_RESULT: "Кэш, который не удалось отнести ни к одной категории. Он входит в итог отдельной строкой, пока не будет классифицирован.",
};

const SEVERITY_RANK = { ERROR: 0, WARNING: 1, INFO: 2 };

// `count` means positions for most issues and something else for the quarantine ones,
// where it counts the executions or the cash events that could not be converted.
// Used instead of ISSUE_EXPLANATIONS when the issue names instruments, so the
// sentence can introduce the list that follows it.
const ISSUE_EXPLANATIONS_WITH_SYMBOLS = {
  SETTLEMENT_DAY_UNKNOWN: "В выписке есть позиции, но день, на который снят баланс, установить не удалось: либо у позиций нет даты, либо её нет у остатков, либо она есть, но не является датой. Пока это так, маржинальный контракт, открытый после снятия баланса, неотличим от того, что брокер уже рассчитал, — и перечисленные контракты в стоимость счёта не входят:",
  MARK_DATE_MISMATCH: "Расчётная цена у брокера относится не к тому дню, на который сняты остатки по счёту, поэтому оценить контракт нечем: вариационная маржа за прошедшие дни уже лежит в кэше и была бы учтена второй раз. Замыкающее тождество проверено — отброшенная нога возвращается на место, и вердикт рядом относится к счёту целиком, — а в стоимость счёта не вошли контракты:",
};

const ISSUE_COUNT_UNITS = {
  QUARANTINED_FX_EXECUTIONS: "исполн.",
  QUARANTINED_CASH: "событ.",
  UNCLASSIFIED_CASH_IN_RESULT: "событ.",
  // Counts contracts, not positions — the default unit printed "3 позиц." on a page
  // listing twenty-two of them.
  SETTLEMENT_DAY_UNKNOWN: "контр.",
  MARK_DATE_MISMATCH: "контр.",
};

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
  if (issue.count != null) parts.push(`${issue.count} ${ISSUE_COUNT_UNITS[issue.type] || "позиц."}`);
  if (issue.ageHours != null) parts.push(`возраст ${formatNumber(issue.ageHours, 1)} ч`);
  // Computed here rather than taken from the message, because the panel prefers a
  // static explanation and drops `issue.message` whenever one exists — so a duration
  // written into the message would never reach the page. Reading the clock here also
  // keeps it right for as long as the page is open.
  if (issue.unavailableSince) {
    const began = timeValue(issue.unavailableSince);
    if (began !== null) {
      const hours = (Date.now() - began) / 3_600_000;
      if (hours >= 0) {
        parts.push(hours >= 48
          ? `тянется ${formatNumber(hours / 24, 1)} сут`
          : `тянется ${formatNumber(hours, 0)} ч`);
      }
    }
  }
  if (issue.aheadHours != null) parts.push(`вперёд на ${formatNumber(issue.aheadHours, 1)} ч`);
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
    // A type can explain itself differently depending on what it carries. The
    // settlement-day complaint has two costs — contracts left out of net asset
    // value, or an identity nothing could check — and one static sentence claimed
    // the second while listing the instruments of the first.
    const explanation = (Array.isArray(issue.symbols) && issue.symbols.length
      ? ISSUE_EXPLANATIONS_WITH_SYMBOLS[issue.type]
      : null)
      || ISSUE_EXPLANATIONS[issue.type] || issue.message || "";
    const numbers = issueNumbers(issue);
    // An issue can name the instruments it is about. The explanation says "the
    // contracts listed", and until this was rendered there was no list — the field
    // arrived from the pipeline and nothing read it.
    const named = Array.isArray(issue.symbols) && issue.symbols.length
      ? ` ${issue.symbols.join(", ")}.`
      : "";
    return `
      <div class="issue-item ${escapeHtml(tone)}">
        <span class="severity">${escapeHtml(severity)}</span>
        <span class="issue-type">${escapeHtml(issue.symbol ? `${issue.symbol} · ${title}` : title)}</span>
        <span class="issue-message">${numbers ? `${escapeHtml(numbers)} — ` : ""}${escapeHtml(explanation + named)}</span>
      </div>
    `;
  }).join("");
}

/* ------------------------------------------------------------- lifecycle --- */

function renderDashboard(payload) {
  // Снимок в исходном виде — то, от чего считается каждое следующее перекрытие.
  state.snapshot = payload;
  state.payload = payloadWithLive(payload);
  payload = state.payload;
  // Before anything reads a row: every summary in the page is filtered through this.
  state.quarantined = quarantinedConids(payload);
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
  renderQuarantineNotice(payload);
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
  renderLiveNote();
  // Последним: узлы уже на месте, и курсу есть куда вернуться.
  restoreAlertFocus();
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
  // Запускается ЗДЕСЬ, а не внутри renderDashboard: тик перекрытия перерисовывает
  // страницу целиком, и таймер, заведённый в отрисовке, перезапускал бы сам себя
  // на каждом тике — то есть отрисовка вызывала бы отрисовку без конца.
  startLiveQuotes();
}

const CLEARED_ON_LOCK = [
  "kpiGrid", "issuesList", "accountIdentity", "dataStatus", "totalsCheck",
  "heroPanel", "buildupChart", "buildupTable", "timelineChart", "yearChart",
  "classStrip", "allocationChart", "extremesChart", "qualityStats", "incomeStats",
  "timelineNote", "allocationNote", "kpiContext", "resultCount", "quarantineNotice",
  // On its own it says that something is in quarantine and that a class is selected —
  // two facts about the portfolio, which is exactly what locking removes.
  "buildupScopeNote",
];

/**
 * Locking has to remove the plaintext from the page, not just hide the container:
 * with the markup still in the DOM the whole portfolio was one devtools inspection
 * away, and a reload restored it outright. The same applies to everything derived
 * from the payload — the search text, the year and currency option lists, the
 * asset-class menu and the cached scope summary all say what the portfolio holds.
 */
function lockDashboard(message = "") {
  state.payload = null;
  state.cryptoKey = null;
  state.quarantined = new Set();
  // Раньше очистки DOM: таймер живого слоя, сработавший после блокировки, дорисовал
  // бы цены в уже вычищенную таблицу.
  stopLiveQuotes();
  // A debounced search or a lingering refresh label firing after the lock would
  // call render paths against a null payload — a TypeError in a timer at best.
  if (state.searchTimer) {
    window.clearTimeout(state.searchTimer);
    state.searchTimer = null;
  }
  if (state.refreshTimer) {
    window.clearTimeout(state.refreshTimer);
    state.refreshTimer = null;
  }
  state.expanded.clear();
  state.charts.clear();
  state.sortKey = null;
  state.sortDirection = null;
  state.timelineCoverage = "";
  state.timelineBridge = "";
  scopeCache = null;
  portfolioBody.innerHTML = "";
  byId("searchInput").value = "";
  // The option lists were built from the payload, so they are emptied the same way
  // they were filled — down to the one default option `populateSelect` always writes.
  populateSelect(byId("currencyFilter"), [], "Все валюты");
  populateSelect(byId("yearFilter"), [], "Любой год");
  // Mirrors `renderScopeFilter` with nothing to show: no class checkboxes, the
  // default summary, no narrowed highlight, and the popover closed.
  byId("assetScopeOptions").innerHTML = "";
  const scopeLabelNode = byId("assetScopeSummary");
  scopeLabelNode.textContent = "Все классы";
  scopeLabelNode.closest("summary").classList.remove("is-narrowed");
  byId("assetScopeAll").hidden = true;
  byId("assetScope").open = false;
  // Skips an id the document does not have: locking must clear what is there, not
  // throw part-way through and leave the rest of the plaintext on the page.
  for (const id of CLEARED_ON_LOCK) {
    const node = byId(id);
    if (node) node.innerHTML = "";
  }
  for (const id of ["accountPanel", "issuesPanel", "totalsCheck", "buildupPanel",
    "timelinePanel", "allocationPanel", "extremesPanel", "qualityPanel", "incomePanel",
    "quarantineNotice"]) {
    byId(id).hidden = true;
  }
  // Hiding the tooltip leaves whatever it last said in the DOM: hover one bar of the
  // cumulative chart, lock, and the symbol and the amount are still there to be read
  // out of the markup. The refresh line is the same — "Обновлено: <date>" is a fact
  // about the portfolio, and the label beside it has to go back to its resting text.
  tooltip.innerHTML = "";
  byId("refreshFeedback").textContent = "";
  byId("refreshButtonLabel").textContent = "Обновить";
  // The percent button's tooltip explains *why* the view is withheld — "money in
  // quarantine", "the scope is narrowed" — which is two facts about the portfolio
  // left readable in the markup after locking. Same rule as the scope note above:
  // locking must remove facts, and a disabled state is one too.
  const percentButton = byId("timelineMode")?.querySelector('button[data-mode="percent"]');
  if (percentButton) {
    percentButton.title = "";
    percentButton.disabled = false;
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
/*
 * Lock first, delete second. `forgetDeviceKeys` opens IndexedDB and can reject —
 * storage denied in a private window, the database blocked by another tab of the same
 * page, a quota error — and with the await ahead of the lock a rejection took the
 * handler out before `lockDashboard` ever ran. The button whose whole meaning is
 * "stop trusting this device" then left the entire portfolio on screen.
 *
 * So the half that costs nothing and cannot fail goes first, and the removal is
 * reported afterwards onto the already-locked screen. The failure message says what is
 * actually true: the dashboard is closed, the stored key may still be on the device.
 */
byId("forgetDevice").addEventListener("click", async () => {
  lockDashboard("Удаляем сохранённый ключ…");
  let outcome;
  try {
    await forgetDeviceKeys();
    outcome = "Сохранённый ключ удалён с этого устройства.";
  } catch {
    outcome = "Ключ с этого устройства удалить не удалось: дашборд заблокирован, но сохранённый ключ мог остаться в хранилище браузера — очистите данные сайта.";
  }
  // Same rule the refresh handler follows: whoever comes back after an await has to
  // check that the screen is still the one it was talking to. Unlocking again inside
  // the storage round trip would otherwise leave this line waiting on the unlock form
  // for the next lock, describing something that happened two sessions ago.
  if (!state.cryptoKey) unlockMessage.textContent = outcome;
});

byId("refreshButton").addEventListener("click", async () => {
  const button = byId("refreshButton");
  const label = byId("refreshButtonLabel");
  const feedback = byId("refreshFeedback");
  if (!state.cryptoKey) return;
  const previousGeneratedAt = state.payload?.generatedAt || "";
  if (state.refreshTimer) window.clearTimeout(state.refreshTimer);
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.classList.add("is-refreshing");
  label.textContent = "Обновляем…";
  feedback.textContent = "Загружаем свежий снимок…";
  try {
    await loadEnvelope({ bypassCache: true });
    // Locking can land between any two awaits here, and the tail of this handler
    // would otherwise re-render the whole portfolio into a page that already shows
    // the password form. Checking the key after every await makes the lock final.
    if (!state.cryptoKey) return;
    const payload = await decryptEnvelope(state.envelope, state.cryptoKey);
    if (!state.cryptoKey) return;
    renderDashboard(payload);
    const changed = Boolean(payload.generatedAt && payload.generatedAt !== previousGeneratedAt);
    label.textContent = changed ? "Обновлено" : "Актуально";
    feedback.textContent = changed
      ? `Обновлено: ${formatDate(payload.generatedAt, true)}`
      : "Новых данных пока нет";
  } catch (error) {
    // The same rule as the success path, which the failure paths were exempt from:
    // locking during a request that then failed wrote "Ошибка" and the error text into
    // a toolbar the lock had just emptied. `lockDashboard` puts both nodes back to
    // their resting text itself, so the correct action here is none at all.
    if (!state.cryptoKey) return;
    label.textContent = "Ошибка";
    feedback.textContent = error.message || "Не удалось обновить данные.";
  } finally {
    // These three run whatever happened. The button is hidden by the lock, not reset by
    // the unlock, so a spinning disabled button left behind here would still be
    // spinning and disabled the next time the dashboard opens.
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.classList.remove("is-refreshing");
    // The timer is the opposite case: every early return above lands here too, and
    // arming it against a locked page scheduled one more write into the cleared nodes
    // three seconds after the lock — long after the button that owns it went away.
    if (state.cryptoKey) {
      state.refreshTimer = window.setTimeout(() => {
        label.textContent = "Обновить";
        feedback.textContent = "";
        state.refreshTimer = null;
      }, 3200);
    }
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

/**
 * One place that says which tab is chosen, in all four ways it has to be said: the
 * class the design draws, `aria-selected` for anything that is not looking at the
 * screen, the roving tab stop that keeps the whole group one Tab press wide, and the
 * label of the panel the tabs switch. They used to be one class, and the reset button
 * set that class by hand — so any of them could drift out of step with the others.
 */
function setActiveTab(button, { focus = false } = {}) {
  if (!button) return;
  state.activeTab = button.dataset.tab;
  for (const item of byId("quickTabs").querySelectorAll("button[data-tab]")) {
    const chosen = item === button;
    item.classList.toggle("active", chosen);
    item.setAttribute("aria-selected", String(chosen));
    // Arrow keys move between the tabs; Tab moves past the whole group. Only the
    // chosen tab is in the document's tab order, which is what makes that true.
    item.tabIndex = chosen ? 0 : -1;
  }
  byId("instrumentsTable").setAttribute("aria-labelledby", button.id);
  if (focus) button.focus();
}

byId("quickTabs").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-tab]");
  if (!button) return;
  setActiveTab(button);
  renderRows();
});

// The arrow-key half of the tablist pattern, with activation following focus: these
// tabs are a filter, so the list under them should change as the caret moves, exactly
// as it does when the tab is clicked.
byId("quickTabs").addEventListener("keydown", (event) => {
  const tabs = [...byId("quickTabs").querySelectorAll("button[data-tab]")];
  const current = tabs.indexOf(event.target.closest("button[data-tab]"));
  if (current < 0) return;
  let next = current;
  if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
  else if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = tabs.length - 1;
  else return;
  // Home and End otherwise scroll the page out from under the control being used, and
  // the arrows scroll the filter row sideways on a phone, where it is a scroller.
  event.preventDefault();
  if (next === current) return;
  setActiveTab(tabs[next], { focus: true });
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
  setActiveTab(byId("quickTabs").querySelector('button[data-tab="all"]'));
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

/* --------------------------------------------------------- alerts: события --- */

/*
 * Делегирование на таблице, а не обработчики на каждой карточке: раскрытая строка
 * перерисовывается на каждом тике живого слоя, и обработчики, повешенные на её
 * узлы, пришлось бы вешать заново двадцать раз в минуту — а половина из них
 * пережила бы удаление своего узла.
 */
function alertPanelOf(node) {
  return node.closest(".alerts-panel");
}

function activeKind(panel) {
  return panel.querySelector(".alerts-kind.is-active")?.dataset.alertKind || "BUY_BELOW";
}

function setFeedback(panel, message, tone = "") {
  const node = panel.querySelector(".alerts-feedback");
  if (!node) return;
  node.textContent = message;
  node.className = `alerts-feedback ${tone}`;
}

/** Проверка по ходу: кнопка гаснет сразу и говорит почему, а не после нажатия. */
function validateEntry(panel) {
  const input = panel.querySelector(".alerts-input");
  const add = panel.querySelector(".alerts-add");
  const kind = activeKind(panel);
  const raw = input.value.trim();
  let problem = "";
  if (!raw) problem = "";
  else if (kind === "DATE") {
    const iso = parseLocalDate(raw);
    if (!iso) problem = "дата в формате ДД-ММ-ГГГГ";
    else if (iso < new Date().toISOString().slice(0, 10)) problem = "дата в прошлом";
  } else {
    const value = parseDecimalInput(raw);
    if (value === null) problem = "нужно число";
    else if (value <= 0) problem = "цена больше нуля";
  }
  const ready = Boolean(raw) && !problem && !alertsSection()?.writeUrl === false;
  add.disabled = !raw || Boolean(problem) || !alertsSection()?.writeUrl;
  setFeedback(panel, problem, problem ? "is-bad" : "");
  return ready;
}

async function commitRules(panel, rules, revert) {
  state.alertRules = rules;
  renderRows();
  try {
    await saveAlertRules(rules.map(({ _pending, _failed, ...rule }) => rule));
    state.alertRules = rules.map(({ _pending, _failed, ...rule }) => rule);
    state.alertsSentAt = Date.now();
    state.alertError = null;
  } catch (error) {
    // Сообщение кладётся в состояние, а не в узел: строка сейчас будет
    // перерисована, и текст, записанный в DOM, исчезнет вместе с ней. Первая
    // редакция делала именно так, и отказ записи выглядел как её успех.
    state.alertRules = revert();
    state.alertError = {
      conid: panel.dataset.alertConid,
      message: error?.message || "не удалось сохранить",
    };
  }
  if (state.cryptoKey) renderRows();
}

byId("portfolioBody").addEventListener("click", async (event) => {
  const panel = alertPanelOf(event.target);
  if (!panel) return;

  const kindButton = event.target.closest(".alerts-kind");
  if (kindButton) {
    event.stopPropagation();
    for (const button of panel.querySelectorAll(".alerts-kind")) {
      const active = button === kindButton;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    }
    const input = panel.querySelector(".alerts-input");
    panel.querySelector(".alerts-hint").textContent = kindButton.dataset.alertHint;
    // Предзаполнение снимает большую часть набора: обычно правят одну цифру.
    input.value = kindButton.dataset.alertKind === "DATE"
      ? formatLocalDate(new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10))
      // dataset.alertCurrentPrice раньше не существовало (в разметке атрибута не
      // было), поэтому переключение с даты на цену оставляло в поле дату — и
      // «06.09.2026» уходило в разбор числа как уровень 6.092026.
      : (input.dataset.alertCurrentPrice || "");
    input.setAttribute("inputmode", kindButton.dataset.alertKind === "DATE" ? "numeric" : "decimal");
    state.alertDraft[panel.dataset.alertConid] = input.value;
    validateEntry(panel);
    return;
  }

  const remove = event.target.closest(".alert-chip-remove");
  if (remove) {
    event.stopPropagation();
    const id = remove.closest(".alert-chip")?.dataset.alertId;
    const before = alertRules();
    await commitRules(panel, before.filter((rule) => rule.id !== id), () => before);
    return;
  }

  if (event.target.closest(".alerts-add")) {
    event.stopPropagation();
    if (!validateEntry(panel)) return;
    const input = panel.querySelector(".alerts-input");
    const kind = activeKind(panel);
    const conid = panel.dataset.alertConid;
    const raw = input.value.trim();
    const rule = kind === "DATE"
      ? { conid, kind, date: parseLocalDate(raw) }
      : { conid, kind, price: String(parseDecimalInput(raw)) };
    // Идентификатор считает сервер, но он нужен здесь и сейчас, чтобы чип можно
    // было нарисовать и удалить до того, как ответ вернётся.
    rule.id = `local-${conid}-${kind}-${rule.price || rule.date}`;
    const before = alertRules();
    delete state.alertDraft[conid];
    if (before.some((item) => item.conid === conid && item.kind === kind
      && (item.price === rule.price) && (item.date === rule.date))) {
      setFeedback(panel, "такое уведомление уже стоит", "is-bad");
      return;
    }
    await commitRules(panel, [...before, { ...rule, _pending: true }], () => before);
    return;
  }
});

byId("portfolioBody").addEventListener("input", (event) => {
  const panel = alertPanelOf(event.target);
  if (!panel || !event.target.classList.contains("alerts-input")) return;
  state.alertDraft[panel.dataset.alertConid] = event.target.value;
  state.alertFocus = panel.dataset.alertConid;
  validateEntry(panel);
});

byId("portfolioBody").addEventListener("focusin", (event) => {
  const panel = alertPanelOf(event.target);
  if (panel && event.target.classList.contains("alerts-input")) {
    state.alertFocus = panel.dataset.alertConid;
  }
});

/**
 * Вернуть курсор туда, где он был до перерисовки.
 *
 * Значение восстанавливается разметкой из черновика, а фокус — здесь: браузер
 * теряет его вместе с удалённым узлом, и без этого владелец после каждого тика
 * набирал бы цену в никуда.
 */
function restoreAlertFocus() {
  if (!state.alertFocus) return;
  const panel = document.querySelector(
    `.alerts-panel[data-alert-conid="${CSS.escape(state.alertFocus)}"]`,
  );
  const input = panel?.querySelector(".alerts-input");
  if (!input || document.activeElement === input) return;
  const at = input.value.length;
  input.focus({ preventScroll: true });
  try { input.setSelectionRange(at, at); } catch { /* type=date не поддерживает */ }
}

// Перехватывающего слушателя здесь НЕТ намеренно. Он тут был — чтобы клик по панели
// не схлопывал строку, — и глушил собственные обработчики этого файла: stopPropagation
// в фазе перехвата не пускает событие ко всплывающим, то есть к коду выше. А нужен он
// не был: панель лежит в соседней строке tr.detail-row, и обработчик раскрытия,
// который ищет closest("tr.data-row"), до неё не достаёт.
