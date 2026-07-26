"use strict";

/**
 * SVG chart primitives for the dashboard.
 *
 * Every mark is drawn with geometry in attributes and colour in classes: the page
 * ships a Content-Security-Policy without `unsafe-inline`, so a `style="width:…"`
 * attribute is silently dropped by the browser and a bar sized that way renders at
 * zero. Nothing here may reach for an inline style.
 *
 * Charts are rendered at the container's measured pixel width rather than into a
 * scaled viewBox, so label text keeps the size it was designed at instead of
 * growing and shrinking with the panel.
 */

const SVG_NS = "http://www.w3.org/2000/svg";

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

const compactFormatter = new Intl.NumberFormat("ru-RU", {
  notation: "compact",
  maximumFractionDigits: 1,
});

const wholeFormatter = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 0 });

/** Axis ticks and in-chart labels: the exact cent belongs in the table, not on a tick. */
export function compactUsd(value) {
  if (!Number.isFinite(value)) return "—";
  if (value === 0) return "0 $";
  const sign = value < 0 ? "−" : "";
  const magnitude = Math.abs(value);
  if (magnitude < 1000) return `${sign}${wholeFormatter.format(magnitude)} $`;
  return `${sign}${compactFormatter.format(magnitude)} $`;
}

export function signedCompactUsd(value) {
  if (!Number.isFinite(value) || value === 0) return compactUsd(value);
  return value > 0 ? `+${compactUsd(value)}` : compactUsd(value);
}

const percentFormatter = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 });

export function sharePercent(value) {
  if (!Number.isFinite(value)) return "—";
  return `${percentFormatter.format(value * 100)} %`;
}

function toneOf(value) {
  if (!Number.isFinite(value) || value === 0) return "flat";
  return value > 0 ? "up" : "down";
}

/**
 * Rounded on the growing end, square at the baseline. Written as a path rather than
 * a `rect` with `rx`, because a rect rounds all four corners and the baseline corner
 * has to stay sharp for the bar to look anchored.
 */
function barPath(x, y, width, height, radius, side) {
  const r = Math.max(0, Math.min(radius, Math.min(width, height) / 2));
  if (r === 0) return `M${x} ${y} h${width} v${height} h${-width} Z`;
  if (side === "right") {
    return `M${x} ${y} h${width - r} a${r} ${r} 0 0 1 ${r} ${r} v${height - 2 * r} a${r} ${r} 0 0 1 ${-r} ${r} h${-(width - r)} Z`;
  }
  if (side === "left") {
    return `M${x + r} ${y} h${width - r} v${height} h${-(width - r)} a${r} ${r} 0 0 1 ${-r} ${-r} v${-(height - 2 * r)} a${r} ${r} 0 0 1 ${r} ${-r} Z`;
  }
  if (side === "down") {
    return `M${x} ${y} h${width} v${height - r} a${r} ${r} 0 0 1 ${-r} ${r} h${-(width - 2 * r)} a${r} ${r} 0 0 1 ${-r} ${-r} Z`;
  }
  return `M${x} ${y + r} a${r} ${r} 0 0 1 ${r} ${-r} h${width - 2 * r} a${r} ${r} 0 0 1 ${r} ${r} v${height - r} h${-width} Z`;
}

function tipAttributes(title, value, note) {
  const parts = [`data-tip-title="${escapeHtml(title)}"`, `data-tip-value="${escapeHtml(value)}"`];
  if (note) parts.push(`data-tip-note="${escapeHtml(note)}"`);
  return parts.join(" ");
}

function svgOpen(width, height, label) {
  return `<svg class="chart" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(label)}" xmlns="${SVG_NS}">`;
}

/** Measure once per render so labels can be placed without colliding or clipping. */
function measurer() {
  const canvas = measurer.canvas || (measurer.canvas = document.createElement("canvas"));
  return canvas.getContext("2d");
}

function textWidth(text, font) {
  const context = measurer();
  context.font = font;
  return context.measureText(String(text)).width;
}

const LABEL_FONT = '600 12px "Segoe UI", system-ui, sans-serif';
const VALUE_FONT = '600 12px ui-monospace, "SFMono-Regular", Consolas, monospace';

function truncateToWidth(text, font, maxWidth) {
  if (textWidth(text, font) <= maxWidth) return text;
  let result = String(text);
  while (result.length > 1 && textWidth(`${result}…`, font) > maxWidth) {
    result = result.slice(0, -1);
  }
  return `${result}…`;
}

/**
 * Horizontal waterfall: one row per contribution, subtotals drawn from zero.
 *
 * Horizontal rather than columnar because the categories are Russian phrases —
 * as columns they would need rotated labels, which is the least readable option
 * available.
 */
export function waterfall(items, width) {
  const rowHeight = 32;
  const barHeight = 13;
  // On a phone the labels would otherwise take half the card and leave the bars
  // with nothing; the printed values carry the reading there.
  const labelWidth = Math.min(230, Math.max(width < 520 ? 116 : 150, Math.round(width * 0.24)));
  const valueWidth = 116;
  const gutter = 14;
  const plotLeft = labelWidth + gutter;
  const plotWidth = Math.max(80, width - plotLeft - valueWidth - gutter);
  const height = items.length * rowHeight + 10;

  let cumulative = 0;
  const spans = items.map((item) => {
    if (item.kind === "total") {
      return { item, from: 0, to: cumulative };
    }
    const from = cumulative;
    cumulative += item.value;
    return { item, from, to: cumulative };
  });

  const bounds = spans.flatMap((span) => [span.from, span.to]).concat([0]);
  const min = Math.min(...bounds);
  const max = Math.max(...bounds);
  const range = max - min || 1;
  const scale = (value) => plotLeft + ((value - min) / range) * plotWidth;
  const zero = scale(0);

  let markup = svgOpen(width, height, "Вклад каждой составляющей в итог за всё время");
  markup += `<line class="chart-axis" x1="${zero}" y1="4" x2="${zero}" y2="${height - 8}" />`;

  spans.forEach((span, index) => {
    const { item } = span;
    const top = index * rowHeight + 6;
    const y = top + (rowHeight - barHeight) / 2 - 6;
    const left = Math.min(scale(span.from), scale(span.to));
    const right = Math.max(scale(span.from), scale(span.to));
    const barWidth = Math.max(2, right - left);
    const growsRight = span.to >= span.from;
    const tone = item.kind === "total" ? "total" : toneOf(item.value);
    const shown = item.kind === "total" ? span.to : item.value;
    const label = truncateToWidth(item.label, LABEL_FONT, labelWidth);
    const tip = tipAttributes(item.label, compactUsd(shown), item.note);

    if (index > 0 && item.kind !== "total" && spans[index - 1].item.kind !== "total") {
      const previousEnd = scale(spans[index - 1].to);
      markup += `<line class="chart-connector" x1="${previousEnd}" y1="${y - (rowHeight - barHeight)}" x2="${previousEnd}" y2="${y}" />`;
    }

    markup += `<g class="wf-row tone-${tone}" tabindex="0" role="listitem" aria-label="${escapeHtml(`${item.label}: ${compactUsd(shown)}`)}" ${tip}>`;
    markup += `<rect class="chart-hit" x="0" y="${top - 6}" width="${width}" height="${rowHeight}" />`;
    markup += `<text class="chart-label" x="${labelWidth}" y="${y + barHeight / 2 + 4}" text-anchor="end">${escapeHtml(label)}</text>`;
    markup += `<path class="chart-bar" d="${barPath(left, y, barWidth, barHeight, 4, growsRight ? "right" : "left")}" />`;
    markup += `<text class="chart-value" x="${width - 2}" y="${y + barHeight / 2 + 4}" text-anchor="end">${escapeHtml(compactUsd(shown))}</text>`;
    markup += `<title>${escapeHtml(`${item.label}: ${compactUsd(shown)}`)}</title>`;
    markup += `</g>`;
  });

  return `${markup}</svg>`;
}

/**
 * Cumulative value over time: a single series, so no legend — the title names it.
 * `options.format` decides how ticks and the end label read, so the same plot can
 * show money or a ratio without a second axis ever appearing.
 */
const TICK_FONT = '400 11px ui-monospace, "SFMono-Regular", Consolas, monospace';
const END_FONT = '700 12px ui-monospace, "SFMono-Regular", Consolas, monospace';

/**
 * Shared by the plot and by the hover layer, which have to agree to the pixel.
 * The right gutter is measured from the widest tick label rather than fixed, so
 * "6 млн $" and "1 250 %" each get exactly the room they need and no more.
 */
function areaLayout(points, width, options = {}) {
  const format = options.format || compactUsd;
  const height = options.height || 220;
  const padTop = 18;
  const padBottom = 26;
  const padLeft = 8;
  const plotHeight = height - padTop - padBottom;

  const values = points.map((point) => point.value);
  const rawMin = Math.min(0, ...values);
  const rawMax = Math.max(0, ...values);
  const span = rawMax - rawMin || 1;
  const min = rawMin - span * 0.06;
  const max = rawMax + span * 0.08;

  const ticks = niceTicks(min, max, 4);
  const gutter = Math.ceil(Math.max(28, ...ticks.map((tick) => textWidth(format(tick), TICK_FONT)))) + 12;
  const plotWidth = Math.max(60, width - padLeft - gutter);

  const first = points[0]?.time ?? 0;
  const last = points[points.length - 1]?.time ?? 1;
  const timeSpan = last - first || 1;

  return {
    format, height, padTop, padBottom, padLeft, plotHeight, plotWidth, gutter,
    min, max, ticks, first, last,
    x: (time) => padLeft + ((time - first) / timeSpan) * plotWidth,
    y: (value) => padTop + (1 - (value - min) / (max - min)) * plotHeight,
    fromX: (px) => first + ((px - padLeft) / plotWidth) * timeSpan,
  };
}

export function areaChart(points, width, options = {}) {
  if (points.length < 2) return "";
  const layout = areaLayout(points, width, options);
  const { format, height, padTop, padLeft, plotHeight, plotWidth, min, max, ticks, first, last, x, y } = layout;

  const line = points.map((point, index) => `${index ? "L" : "M"}${x(point.time).toFixed(1)} ${y(point.value).toFixed(1)}`).join(" ");
  const baseline = y(Math.max(min, Math.min(0, max)));
  const area = `${line} L${x(last).toFixed(1)} ${baseline.toFixed(1)} L${x(first).toFixed(1)} ${baseline.toFixed(1)} Z`;

  let markup = svgOpen(width, height, options.label || "Динамика");

  // Gridlines: solid hairlines, one step off the surface, carrying the values that
  // are not directly labelled.
  for (const tick of ticks) {
    const ty = y(tick);
    if (ty < padTop - 2 || ty > padTop + plotHeight + 2) continue;
    markup += `<line class="chart-grid" x1="${padLeft}" y1="${ty.toFixed(1)}" x2="${padLeft + plotWidth}" y2="${ty.toFixed(1)}" />`;
    markup += `<text class="chart-tick" x="${padLeft + plotWidth + 6}" y="${(ty + 4).toFixed(1)}">${escapeHtml(format(tick))}</text>`;
  }
  if (min < 0 && max > 0) {
    markup += `<line class="chart-axis" x1="${padLeft}" y1="${y(0).toFixed(1)}" x2="${padLeft + plotWidth}" y2="${y(0).toFixed(1)}" />`;
  }

  for (const year of yearTicks(first, last)) {
    const tx = x(year.time);
    if (tx < padLeft || tx > padLeft + plotWidth) continue;
    markup += `<text class="chart-tick" x="${tx.toFixed(1)}" y="${height - 8}" text-anchor="middle">${year.label}</text>`;
  }

  markup += `<path class="chart-area" d="${area}" />`;
  markup += `<path class="chart-line" d="${line}" />`;

  // The one directly-labelled point. It is drawn inside the plot, to the left of the
  // endpoint: the space to its right belongs to the axis ticks, and a label placed
  // there lands on whichever tick happens to sit at the same height.
  const endValue = points[points.length - 1].value;
  const endText = format(endValue);
  const endX = x(last);
  const endY = y(endValue);
  const labelY = Math.min(Math.max(endY - 11, padTop + 11), padTop + plotHeight - 3);
  markup += `<circle class="chart-endpoint" cx="${endX.toFixed(1)}" cy="${endY.toFixed(1)}" r="4.5" />`;
  markup += `<text class="chart-endlabel" x="${(endX - 9).toFixed(1)}" y="${labelY.toFixed(1)}" text-anchor="end">${escapeHtml(endText)}</text>`;

  // One hit rectangle for the whole plot; the nearest point is found on move, so a
  // reader never has to land on the line itself.
  markup += `<g class="chart-crosshair" hidden><line class="chart-crosshair-line" x1="0" y1="${padTop}" x2="0" y2="${padTop + plotHeight}" /><circle class="chart-crosshair-dot" cx="0" cy="0" r="4.5" /></g>`;
  markup += `<rect class="chart-surface" x="${padLeft}" y="${padTop}" width="${plotWidth}" height="${plotHeight}" />`;

  return `${markup}</svg>`;
}

/** Geometry the hover layer needs to map a pointer position back to a data point. */
export function areaGeometry(points, width, options = {}) {
  const layout = areaLayout(points, width, options);
  return {
    toX: layout.x,
    toY: layout.y,
    fromX: layout.fromX,
    padLeft: layout.padLeft,
    plotWidth: layout.plotWidth,
  };
}

function niceTicks(min, max, count) {
  const range = max - min;
  if (!Number.isFinite(range) || range <= 0) return [min];
  const rough = range / count;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const step = [1, 2, 2.5, 5, 10].map((factor) => factor * magnitude)
    .find((candidate) => candidate >= rough) || 10 * magnitude;
  const ticks = [];
  for (let value = Math.ceil(min / step) * step; value <= max; value += step) {
    ticks.push(Math.abs(value) < step / 1000 ? 0 : value);
  }
  return ticks;
}

function yearTicks(first, last) {
  const ticks = [];
  const start = new Date(first).getUTCFullYear();
  const end = new Date(last).getUTCFullYear();
  const step = end - start > 8 ? 2 : 1;
  for (let year = start; year <= end; year += step) {
    ticks.push({ time: Date.UTC(year, 0, 1), label: String(year) });
  }
  return ticks;
}

/** Columns for a small ordered set — one per year. Diverging by sign. */
export function columnChart(items, width, options = {}) {
  // The columns are the yearly change of the line above them, so they have to read in
  // whatever unit the line is currently showing.
  const format = options.format || signedCompactUsd;
  const height = options.height || 156;
  // Room above for the caps of positive columns and below for two stacked rows:
  // the value under a negative column, then the year. Sized so the two never meet.
  const padTop = 22;
  const padBottom = 40;
  const plotHeight = height - padTop - padBottom;
  if (!items.length) return "";
  const values = items.map((item) => item.value);
  const max = Math.max(0, ...values);
  const min = Math.min(0, ...values);
  const range = max - min || 1;
  const slot = width / items.length;
  const barWidth = Math.min(18, slot - 14);
  const zeroY = padTop + (max / range) * plotHeight;

  let markup = svgOpen(width, height, options.label || "По годам");
  markup += `<line class="chart-axis" x1="0" y1="${zeroY.toFixed(1)}" x2="${width}" y2="${zeroY.toFixed(1)}" />`;

  items.forEach((item, index) => {
    const centre = slot * index + slot / 2;
    const x = centre - barWidth / 2;
    const magnitude = Math.abs(item.value) / range * plotHeight;
    const barHeight = Math.max(2, magnitude);
    const up = item.value >= 0;
    const y = up ? zeroY - barHeight : zeroY;
    const tone = toneOf(item.value);
    const shown = format(item.value);
    markup += `<g class="col-item tone-${tone}" tabindex="0" aria-label="${escapeHtml(`${item.label}: ${shown}`)}" ${tipAttributes(item.label, shown, item.note)}>`;
    markup += `<rect class="chart-hit" x="${(centre - slot / 2).toFixed(1)}" y="0" width="${slot.toFixed(1)}" height="${height}" />`;
    markup += `<path class="chart-bar" d="${barPath(x, y, barWidth, barHeight, 4, up ? "up" : "down")}" />`;
    const capY = up ? y - 7 : Math.min(y + barHeight + 13, height - padBottom + 14);
    markup += `<text class="chart-mini" x="${centre.toFixed(1)}" y="${capY.toFixed(1)}" text-anchor="middle">${escapeHtml(shown)}</text>`;
    markup += `<text class="chart-tick" x="${centre.toFixed(1)}" y="${height - 7}" text-anchor="middle">${escapeHtml(item.label)}</text>`;
    markup += `<title>${escapeHtml(`${item.label}: ${shown}`)}</title>`;
    markup += `</g>`;
  });
  return `${markup}</svg>`;
}

/**
 * Ranked horizontal bars for magnitude. One series, therefore one colour for every
 * bar: darkening the big ones would burn the only free channel restating the length.
 */
export function rankedBars(items, width, options = {}) {
  const rowHeight = options.rowHeight || 28;
  const barHeight = 10;
  const labelWidth = Math.min(150, Math.max(84, Math.round(width * 0.2)));
  const valueWidth = options.valueWidth || 132;
  const gutter = 12;
  const plotLeft = labelWidth + gutter;
  const plotWidth = Math.max(40, width - plotLeft - valueWidth - gutter);
  const height = items.length * rowHeight + 6;
  const max = Math.max(...items.map((item) => Math.abs(item.value)), 1);

  let markup = svgOpen(width, height, options.label || "Распределение");
  items.forEach((item, index) => {
    const top = index * rowHeight + 3;
    const y = top + (rowHeight - barHeight) / 2 - 3;
    const barWidth = Math.max(2, (Math.abs(item.value) / max) * plotWidth);
    const label = truncateToWidth(item.label, LABEL_FONT, labelWidth);
    const value = item.display ?? compactUsd(item.value);
    markup += `<g class="rank-item ${item.muted ? "is-muted" : ""}" tabindex="0" aria-label="${escapeHtml(`${item.label}: ${value}`)}" ${tipAttributes(item.label, value, item.note)}>`;
    markup += `<rect class="chart-hit" x="0" y="${top - 3}" width="${width}" height="${rowHeight}" />`;
    markup += `<text class="chart-label" x="${labelWidth}" y="${y + barHeight / 2 + 4}" text-anchor="end">${escapeHtml(label)}</text>`;
    markup += `<path class="chart-bar" d="${barPath(plotLeft, y, barWidth, barHeight, 4, "right")}" />`;
    markup += `<text class="chart-value" x="${width - 2}" y="${y + barHeight / 2 + 4}" text-anchor="end">${escapeHtml(value)}</text>`;
    markup += `<title>${escapeHtml(`${item.label}: ${value}`)}</title>`;
    markup += `</g>`;
  });
  return `${markup}</svg>`;
}

/** Winners and losers around a shared zero. Sign is printed, never colour alone. */
export function divergingBars(items, width, options = {}) {
  const rowHeight = 26;
  const barHeight = 10;
  const labelWidth = Math.min(168, Math.max(96, Math.round(width * 0.14)));
  const valueWidth = 118;
  const gutter = 10;
  const plotLeft = labelWidth + gutter;
  const plotWidth = Math.max(60, width - plotLeft - valueWidth - gutter);
  const height = items.length * rowHeight + 6;
  // One scale for both arms — the comparison is the whole point — but zero sits
  // where the two extremes put it rather than at the midpoint, so a chart whose
  // losses are small does not leave half its width empty.
  const positiveMax = Math.max(0, ...items.map((item) => item.value));
  const negativeMax = Math.max(0, ...items.map((item) => -item.value));
  const total = positiveMax + negativeMax || 1;
  const perUnit = plotWidth / total;
  const zero = plotLeft + negativeMax * perUnit;
  const max = total;
  const halfWidth = plotWidth;

  let markup = svgOpen(width, height, options.label || "Лучшие и худшие");
  markup += `<line class="chart-axis" x1="${zero}" y1="2" x2="${zero}" y2="${height - 4}" />`;
  items.forEach((item, index) => {
    const top = index * rowHeight + 3;
    const y = top + (rowHeight - barHeight) / 2 - 3;
    const barWidth = Math.max(2, (Math.abs(item.value) / max) * halfWidth);
    const up = item.value >= 0;
    const x = up ? zero : zero - barWidth;
    const label = truncateToWidth(item.label, LABEL_FONT, labelWidth);
    const value = signedCompactUsd(item.value);
    markup += `<g class="rank-item tone-${toneOf(item.value)}" tabindex="0" aria-label="${escapeHtml(`${item.label}: ${value}`)}" ${tipAttributes(item.label, value, item.note)}>`;
    markup += `<rect class="chart-hit" x="0" y="${top - 3}" width="${width}" height="${rowHeight}" />`;
    markup += `<text class="chart-label" x="${labelWidth}" y="${y + barHeight / 2 + 4}" text-anchor="end">${escapeHtml(label)}</text>`;
    markup += `<path class="chart-bar" d="${barPath(x, y, barWidth, barHeight, 4, up ? "right" : "left")}" />`;
    markup += `<text class="chart-value" x="${width - 2}" y="${y + barHeight / 2 + 4}" text-anchor="end">${escapeHtml(value)}</text>`;
    markup += `<title>${escapeHtml(`${item.label}: ${value}`)}</title>`;
    markup += `</g>`;
  });
  return `${markup}</svg>`;
}

/**
 * A single 100 % bar. Segments are separated by a 2px gap in the surface colour
 * rather than by a stroke, so no ink is spent on something that is not data.
 */
export function stackedStrip(segments, width, options = {}) {
  const height = options.height || 14;
  const gap = 3;
  const total = segments.reduce((sum, segment) => sum + Math.abs(segment.value), 0) || 1;
  const usable = Math.max(10, width - gap * Math.max(0, segments.length - 1));
  let cursor = 0;
  let markup = svgOpen(width, height, options.label || "Состав");
  segments.forEach((segment, index) => {
    const segmentWidth = Math.max(3, (Math.abs(segment.value) / total) * usable);
    const side = segments.length === 1 ? "both" : index === 0 ? "left" : index === segments.length - 1 ? "right" : "none";
    const radius = side === "none" ? 0 : 4;
    const path = side === "both"
      ? barPath(cursor, 0, segmentWidth, height, radius, "right")
      : barPath(cursor, 0, segmentWidth, height, radius, side === "left" ? "left" : "right");
    const value = segment.display ?? compactUsd(segment.value);
    markup += `<g class="strip-item series-${segment.slot}" tabindex="0" aria-label="${escapeHtml(`${segment.label}: ${value}`)}" ${tipAttributes(segment.label, value, segment.note)}>`;
    markup += `<path class="chart-bar" d="${path}" />`;
    markup += `<title>${escapeHtml(`${segment.label}: ${value}`)}</title>`;
    markup += `</g>`;
    cursor += segmentWidth + gap;
  });
  return `${markup}</svg>`;
}

/** A two-part meter: how the account is split between positions and cash. */
export function splitMeter(segments, width, options = {}) {
  return stackedStrip(segments, width, options);
}

/** Table twin for a chart: every value the chart draws, in plain text. */
export function chartTable(rows, options = {}) {
  const head = options.head || ["Показатель", "Сумма"];
  return `
    <table class="mini-table">
      <thead><tr><th>${escapeHtml(head[0])}</th><th class="numeric">${escapeHtml(head[1])}</th></tr></thead>
      <tbody>
        ${rows.map((row) => `
          <tr class="${row.kind === "total" ? "is-total" : ""}">
            <th scope="row">${escapeHtml(row.label)}</th>
            <td class="numeric ${row.tone || ""}">${escapeHtml(row.value)}</td>
          </tr>`).join("")}
      </tbody>
    </table>
  `;
}
