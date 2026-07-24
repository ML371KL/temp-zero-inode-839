"use strict";

const state = {
  envelope: null,
  payload: null,
  cryptoKey: null,
  activeTab: "all",
  expanded: new Set(),
  sortKey: null,
  sortDirection: null,
  refreshTimer: null,
};

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
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
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
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytesFromBase64(envelope.cipher.iv),
      additionalData: bytesFromBase64(envelope.cipher.aad),
      tagLength: 128,
    },
    key,
    bytesFromBase64(envelope.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
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
  return record?.key || null;
}

async function forgetDeviceKeys() {
  await withKeyStore("readwrite", (store) => store.clear());
}

async function loadEnvelope() {
  const response = await fetch(`data/portfolio.enc?v=${Date.now()}`, { cache: "no-store" });
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error("Данные ещё не опубликованы. Сначала запустите workflow в приватном репозитории.");
    }
    throw new Error(`Не удалось загрузить зашифрованные данные (${response.status}).`);
  }
  const envelope = await response.json();
  if (envelope.format !== "ibkr-portfolio-aes-gcm" || envelope.version !== 1) {
    throw new Error("Неподдерживаемый формат зашифрованных данных.");
  }
  state.envelope = envelope;
  return envelope;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function numberValue(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function formatNumber(value, maximumFractionDigits = 4) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  return new Intl.NumberFormat("ru-RU", {
    maximumFractionDigits,
    minimumFractionDigits: 0,
  }).format(parsed);
}

function formatMoney(value, currency = "USD", showCode = false) {
  const parsed = numberValue(value);
  if (parsed === null) return "—";
  try {
    return new Intl.NumberFormat("ru-RU", {
      style: "currency",
      currency,
      currencyDisplay: showCode ? "code" : "narrowSymbol",
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(parsed);
  } catch {
    return `${formatNumber(parsed, 2)} ${escapeHtml(currency)}`;
  }
}

function formatDate(value, includeTime = false) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return escapeHtml(value);
  return new Intl.DateTimeFormat("ru-RU", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    ...(includeTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  }).format(parsed);
}

function pnlClass(value) {
  const parsed = numberValue(value);
  if (parsed === null || parsed === 0) return "muted-value";
  return parsed > 0 ? "positive" : "negative";
}

function aggregateRows(rows) {
  const fields = [
    "marketValueUsd",
    "openBasisUsd",
    "unrealizedPnlUsd",
    "realizedPnlUsd",
    "dividendsNetUsd",
    "totalResultUsd",
  ];
  const totals = Object.fromEntries(fields.map((field) => [field, 0]));
  let partial = false;

  for (const row of rows) {
    for (const field of fields) {
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
  for (const id of ["assetFilter", "directionFilter", "currencyFilter", "profitFilter"]) {
    const select = byId(id);
    if (select.value) parts.push(select.selectedOptions[0]?.textContent || select.value);
  }
  return `${rows.length} из ${total}${parts.length ? ` · ${parts.join(" · ")}` : " · все инструменты"}`;
}

function renderKpis(payload, rows) {
  const { totals, partial } = aggregateRows(rows);
  const cash = payload.cash || {};
  const cashNote = cash.available
    ? `Весь счёт · Activity Flex на ${formatDate(cash.asOf)}`
    : "Добавьте Cash Report в Activity Flex";
  const cards = [
    ["Рыночная стоимость", totals.marketValueUsd, "Открытые позиции"],
    ["AVCO-себестоимость открытых позиций", totals.openBasisUsd, ""],
    ["Кэш на балансе", cash.endingCash, cashNote, false],
    ["Нереализованный P&L", totals.unrealizedPnlUsd, "Текущий"],
    ["Реализованный P&L", totals.realizedPnlUsd, "Выбранные инструменты"],
    ["Чистые дивиденды", totals.dividendsNetUsd, "После налогов"],
    ["Общий результат", totals.totalResultUsd, "Выбранные инструменты"],
  ];
  byId("kpiContext").textContent = filterContext(rows);
  byId("kpiGrid").innerHTML = cards.map(([label, value, note, filtered = true]) => `
    <article class="kpi-card">
      <span>${escapeHtml(label)}</span>
      <strong class="${label.includes("P&L") || label.includes("результат") ? pnlClass(value) : ""}">${formatMoney(value, payload.baseCurrency || "USD")}</strong>
      ${(note || (partial && filtered)) ? `<small>${escapeHtml(note)}${partial && filtered ? `${note ? " · " : ""}неполные FX/цены` : ""}</small>` : ""}
    </article>
  `).join("");
}

function renderStatus(payload) {
  const status = payload.status || {};
  const level = String(status.level || "WARNING").toUpperCase();
  const labels = {
    OK: "Сверка пройдена — расхождений нет",
    WARNING: "Есть предупреждения или сверка ещё не завершена",
    ERROR: "Обнаружены расхождения, требующие внимания",
  };
  const container = byId("dataStatus");
  container.className = `data-status status-${level.toLowerCase()}`;
  container.innerHTML = `
    <div class="status-main"><span class="status-indicator"></span><strong>${labels[level] || labels.WARNING}</strong></div>
    <div class="status-times">
      <span>Сделка: ${formatDate(status.lastTradeAt, true)}</span>
      <span>Котировки: ${formatDate(status.quotesUpdatedAt, true)}</span>
      <span>Activity: ${formatDate(status.activityReconciledAt, true)}</span>
      <span>Проблемы: ${Number(status.issueCount || 0)}</span>
    </div>
  `;
}

function populateSelect(select, values, defaultLabel) {
  const current = select.value;
  select.innerHTML = `<option value="">${escapeHtml(defaultLabel)}</option>` + values
    .filter(Boolean)
    .sort((left, right) => left.localeCompare(right))
    .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`)
    .join("");
  select.value = current;
}

function renderFilterOptions(rows) {
  populateSelect(byId("assetFilter"), [...new Set(rows.map((row) => row.assetClass))], "Все классы");
  populateSelect(byId("currencyFilter"), [...new Set(rows.map((row) => row.currency))], "Все валюты");
}

function isOpen(row) {
  return Math.abs(numberValue(row.quantity) || 0) > 1e-8;
}

const SORT_ACCESSORS = {
  instrument: (row) => `${row.symbol || ""} ${row.instrument || ""}`,
  status: (row) => statusLabel(row),
  cycle: (row) => row.cycleOpenedAt || "",
  quantity: (row) => numberValue(row.quantity),
  averageEntry: (row) => numberValue(row.averageEntry),
  averageExit: (row) => numberValue(row.averageExit),
  currentPrice: (row) => numberValue(row.currentPrice?.price),
  marketValueUsd: (row) => numberValue(row.marketValueUsd),
  unrealizedPnlUsd: (row) => numberValue(row.unrealizedPnlUsd),
  realizedPnlUsd: (row) => numberValue(row.realizedPnlUsd),
  dividendsNetUsd: (row) => numberValue(row.dividendsNetUsd),
  totalResultUsd: (row) => numberValue(row.totalResultUsd),
  currency: (row) => row.currency || "",
};

function defaultRowCompare(left, right) {
  const openDifference = Number(isOpen(right)) - Number(isOpen(left));
  if (openDifference) return openDifference;
  if (isOpen(left)) {
    return Math.abs(numberValue(right.marketValueUsd) || 0) - Math.abs(numberValue(left.marketValueUsd) || 0);
  }
  return String(right.cycleClosedAt || "").localeCompare(String(left.cycleClosedAt || ""));
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

function filteredRows() {
  const search = byId("searchInput").value.trim().toLowerCase();
  const asset = byId("assetFilter").value;
  const direction = byId("directionFilter").value;
  const currency = byId("currencyFilter").value;
  const profit = byId("profitFilter").value;
  const rows = [...(state.payload?.rows || [])].filter((row) => {
    if (state.activeTab === "open" && !isOpen(row)) return false;
    if (state.activeTab === "closed" && isOpen(row)) return false;
    if (state.activeTab === "review" && row.status !== "REVIEW") return false;
    if (asset && row.assetClass !== asset) return false;
    if (direction && row.direction !== direction) return false;
    if (currency && row.currency !== currency) return false;
    const result = numberValue(row.totalResultUsd) || 0;
    if (profit === "profit" && result <= 0) return false;
    if (profit === "loss" && result >= 0) return false;
    if (search) {
      const haystack = [row.instrument, row.symbol, row.conid, ...(row.symbolHistory || [])]
        .join(" ").toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
  return sortRows(rows);
}

function statusLabel(row) {
  if (row.status === "REVIEW") return "Проверить";
  return isOpen(row) ? "Открыта" : "Закрыта";
}

function statusClass(row) {
  if (row.status === "REVIEW") return "review";
  return isOpen(row) ? "open" : "closed";
}

function detailHtml(row) {
  const cycles = [...(row.cycles || [])].reverse();
  const cycleMarkup = cycles.map((cycle) => {
    const fallbackResult = (numberValue(cycle.realizedPnlUsd) || 0)
      + (numberValue(cycle.dividendsNetUsd) || 0);
    const totalResult = numberValue(cycle.totalResultUsd) ?? fallbackResult;
    return `
      <div class="cycle-item">
        <span class="cycle-number">Цикл ${cycle.number}</span>
        <span class="cycle-period"><strong>${escapeHtml(cycle.direction)}</strong>${formatDate(cycle.openedAt)} → ${formatDate(cycle.closedAt)}</span>
        <span><strong>${formatNumber(cycle.quantity, 8)}</strong>остаток</span>
        <span><strong>${formatMoney(cycle.averageEntry, row.currency)}</strong>средний вход</span>
        <span><strong>${formatMoney(cycle.averageExit, row.currency)}</strong>средний выход</span>
        <span><strong class="${pnlClass(totalResult)}">${formatMoney(totalResult, "USD")}</strong>общий результат · ${(cycle.trades || []).length} операций</span>
      </div>
    `;
  }).join("") || '<div class="muted-value">Циклы отсутствуют</div>';
  const review = (row.reviewReasons || []).length
    ? `<div class="review-box">${row.reviewReasons.map(escapeHtml).join("<br>")}</div>`
    : "";
  const corporateActions = (row.corporateActions || []).length
    ? `<div class="corporate-history"><strong>Корпоративные действия</strong>${row.corporateActions.map((event) => `<span>${formatDate(event.timestamp)} · ${escapeHtml(event.description || event.category)}</span>`).join("")}</div>`
    : "";
  return `
    <tr class="detail-row"><td colspan="13">
      <div class="detail-wrap">
        <section class="detail-section">
          <h3>Инструмент</h3>
          <div class="detail-grid">
            <div class="detail-item"><span>Conid</span><strong>${escapeHtml(row.conid)}</strong></div>
            <div class="detail-item"><span>Биржа</span><strong>${escapeHtml(row.exchange || "—")}</strong></div>
            <div class="detail-item"><span>Первая сделка</span><strong>${formatDate(row.firstTradeAt, true)}</strong></div>
            <div class="detail-item"><span>История тикеров</span><strong>${escapeHtml((row.symbolHistory || []).join(" → ") || row.symbol)}</strong></div>
            <div class="detail-item"><span>AVCO-себестоимость открытой позиции</span><strong>${isOpen(row) ? formatMoney(row.openBasis, row.currency) : "—"}</strong></div>
            <div class="detail-item"><span>Дивиденды в валюте инструмента</span><strong>${formatMoney(row.dividendsNet, row.currency)}</strong></div>
          </div>
          ${review}
          ${corporateActions}
        </section>
        <section class="detail-section"><h3>Позиционные циклы</h3><div class="cycle-list">${cycleMarkup}</div></section>
      </div>
    </td></tr>
  `;
}

function rowHtml(row) {
  const quote = row.currentPrice || {};
  const price = quote.price == null ? "—" : formatMoney(quote.price, row.currency);
  const freshnessLabels = {
    stale: "устарела",
    fallback: "резервная",
    unavailable: "нет данных",
  };
  const priceMeta = [
    quote.type || "UNAVAILABLE",
    formatDate(quote.marketTime, true),
    freshnessLabels[String(quote.freshness || "").toLowerCase()],
  ].filter(Boolean).join(" · ");
  const cycleDates = `${formatDate(row.cycleOpenedAt)} → ${formatDate(row.cycleClosedAt)}`;
  const initial = escapeHtml((row.symbol || "?").slice(0, 2).toUpperCase());
  return `
    <tr class="data-row ${state.expanded.has(row.conid) ? "expanded" : ""}" data-conid="${escapeHtml(row.conid)}">
      <td><div class="instrument-cell"><span class="instrument-avatar">${initial}</span><span><strong class="instrument-name" title="${escapeHtml(row.instrument)}">${escapeHtml(row.symbol)} · ${escapeHtml(row.instrument)}</strong><small class="instrument-meta">${escapeHtml(row.assetClass)} · ${escapeHtml(row.exchange || "—")}</small></span></div></td>
      <td><span class="status-pill ${statusClass(row)}">${statusLabel(row)}</span><span class="price-note">${escapeHtml(row.direction)}</span></td>
      <td>${cycleDates}</td>
      <td class="numeric">${formatNumber(row.quantity, 8)}</td>
      <td class="numeric">${formatMoney(row.averageEntry, row.currency)}</td>
      <td class="numeric">${isOpen(row) ? "—" : formatMoney(row.averageExit, row.currency)}</td>
      <td class="numeric">${price}<span class="price-note ${quote.freshness === "stale" ? "quote-stale" : ""}">${escapeHtml(priceMeta)}</span></td>
      <td class="numeric">${formatMoney(row.marketValueUsd, "USD")}</td>
      <td class="numeric ${pnlClass(row.unrealizedPnlUsd)}">${formatMoney(row.unrealizedPnlUsd, "USD")}</td>
      <td class="numeric ${pnlClass(row.realizedPnlUsd)}">${formatMoney(row.realizedPnlUsd, "USD")}</td>
      <td class="numeric ${pnlClass(row.dividendsNetUsd)}">${formatMoney(row.dividendsNetUsd, "USD")}</td>
      <td class="numeric ${pnlClass(row.totalResultUsd)}">${formatMoney(row.totalResultUsd, "USD")}</td>
      <td>${escapeHtml(row.currency)}</td>
    </tr>
    ${state.expanded.has(row.conid) ? detailHtml(row) : ""}
  `;
}

function renderRows() {
  const rows = filteredRows();
  renderSortHeaders();
  renderKpis(state.payload, rows);
  portfolioBody.innerHTML = rows.map(rowHtml).join("");
  byId("resultCount").textContent = `${rows.length} из ${state.payload?.rows?.length || 0}`;
  byId("emptyState").hidden = rows.length > 0;
  portfolioBody.querySelectorAll("tr.data-row").forEach((element) => {
    element.addEventListener("click", () => {
      const conid = element.dataset.conid;
      state.expanded.has(conid) ? state.expanded.delete(conid) : state.expanded.add(conid);
      renderRows();
    });
  });
}

function renderIssues(payload) {
  const reconciliationIssues = payload.reconciliation?.issues || [];
  const globalIssues = (payload.globalReviewEvents || []).map((event) => ({
    severity: "ERROR",
    type: event.category,
    message: event.description,
  }));
  const issues = [...reconciliationIssues, ...globalIssues];
  byId("issuesPanel").hidden = issues.length === 0;
  byId("issuesList").innerHTML = issues.map((issue) => `
    <div class="issue-item ${String(issue.severity).toLowerCase()}">
      <span class="severity">${escapeHtml(issue.severity || "WARNING")}</span>
      <span class="issue-type">${escapeHtml(issue.symbol ? `${issue.symbol} · ${issue.type}` : issue.type)}</span>
      <span class="issue-message">${escapeHtml(issue.message)}</span>
    </div>
  `).join("");
}

function renderDashboard(payload) {
  state.payload = payload;
  byId("generatedAt").textContent = formatDate(payload.generatedAt, true);
  renderStatus(payload);
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

function lockDashboard() {
  state.payload = null;
  state.cryptoKey = null;
  dashboardView.hidden = true;
  unlockView.hidden = false;
  byId("lockButton").hidden = true;
  byId("refreshButton").hidden = true;
  passwordInput.focus();
}

async function unlockWithPassword(password) {
  const key = await deriveKey(password, state.envelope);
  const payload = await decryptEnvelope(state.envelope, key);
  if (rememberDevice.checked) await saveDeviceKey(state.envelope, key);
  showDashboard(payload, key);
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.envelope) return;
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

byId("lockButton").addEventListener("click", lockDashboard);
byId("forgetDevice").addEventListener("click", async () => {
  await forgetDeviceKeys();
  lockDashboard();
  unlockMessage.textContent = "Сохранённый ключ удалён с этого устройства.";
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
    await loadEnvelope();
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

["searchInput", "assetFilter", "directionFilter", "currencyFilter", "profitFilter"].forEach((id) => {
  byId(id).addEventListener(id === "searchInput" ? "input" : "change", renderRows);
});

async function initialize() {
  unlockButton.disabled = true;
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
  }
}

initialize();
