import { previewDecision, visibleRows } from "./evidence-logic.mjs";

const $ = (id) => document.getElementById(id);
const OUTCOMES = ["pass", "fail", "inconclusive", "production_failed", "pending"];
const LABEL = { pass: "Accepted", fail: "Rejected", inconclusive: "Inconclusive", production_failed: "Production failed", pending: "Pending" };
const SHORT = {
  "software-study": "Software study",
  "reviewer-baseline": "PR reviewer benchmark",
  "producer-bridge": "HTTP round trip",
  "oracle-controls": "Oracle controls",
};
const PHASE_COLORS = ["#7cb2ff", "#3fcbd3", "#b195f7", "#f5a35c", "#ecbd4f", "#3fd294"];
const RECEIPT_FIELDS = [
  ["Execution", "execution_id"], ["Candidate tree", "candidate_tree_sha256"], ["Trial ticket", "trial_ticket_sha256"],
  ["Submission", "submission_sha256"], ["Observation", "observation_sha256"], ["Assessment", "assessment_sha256"],
  ["Recipe", "recipe_sha256"], ["Suite", "suite_sha256"], ["Policy", "policy_sha256"], ["Evaluator", "evaluator_sha256"],
];

let catalog;
let active;
let selectedKey = null;

// ---------- DOM helpers ----------
function h(tag, props, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "style") for (const [prop, v] of Object.entries(value)) node.style.setProperty(prop, v);
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) node.append(kid.nodeType ? kid : String(kid));
  return node;
}
const SVG = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...kids) {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs || {})) if (value != null) node.setAttribute(key, value);
  for (const kid of kids.flat()) if (kid != null) node.append(kid.nodeType ? kid : String(kid));
  return node;
}

// ---------- formatting ----------
const rowKey = (row) => row.execution_id || row.row_id || [row.task_id, row.arm, row.trial, row.attempt_kind].join("/");
const num = (value, digits = 1) => Number(value).toLocaleString("en-US", { maximumFractionDigits: digits });
const secondsOf = (row) => (row.usage && row.usage.latency_ms != null ? row.usage.latency_ms / 1000 : null);
function fmtSeconds(value) {
  if (value == null) return null;
  return (value < 1 ? num(value, 2) : num(value, 1)) + " s";
}
const shortName = (collection) => SHORT[collection.id] || collection.title;
const sentence = (value) => (value ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase() : "");
const ACRONYMS = /\b(api|http|sql|tls|json|id|url|tcp|ui)\b/gi;
const humanize = (id) => sentence(String(id).replace(/[-_]/g, " ")).replace(ACRONYMS, (m) => m.toUpperCase());
const armName = (row) => row.arm_label || row.arm || "Default";
const pill = (outcome) => h("span", { class: "pill o-" + outcome, text: LABEL[outcome] || outcome });
const initialRows = (collection) => collection.rows.filter((row) => row.attempt_kind === "initial");
function countBy(rows, fn) {
  const out = {};
  for (const row of rows) out[fn(row)] = (out[fn(row)] || 0) + 1;
  return out;
}
function shortHash(value) {
  return value.length > 22 ? value.slice(0, 12) + "…" + value.slice(-6) : value;
}
function niceStep(max, target) {
  const raw = max / target;
  const power = 10 ** Math.floor(Math.log10(raw));
  const unit = raw / power;
  return (unit <= 1 ? 1 : unit <= 2 ? 2 : unit <= 2.5 ? 2.5 : unit <= 5 ? 5 : 10) * power;
}
function niceMax(max) {
  if (!(max > 0)) return 1;
  const step = niceStep(max, 5);
  return Math.ceil(max / step) * step;
}

// ---------- tooltip ----------
const tooltip = $("tooltip");
function showTip(event, title, lines, outcome) {
  tooltip.replaceChildren(h("strong", { text: title }), ...lines.map((line) => h("div", { text: line })), outcome ? pill(outcome) : null);
  tooltip.hidden = false;
  moveTip(event);
}
function moveTip(event) {
  if (tooltip.hidden) return;
  let x = event.clientX;
  let y = event.clientY;
  if (x == null || (x === 0 && y === 0)) {
    const box = event.target.getBoundingClientRect();
    x = box.left + box.width / 2;
    y = box.top;
  }
  const width = tooltip.offsetWidth;
  const height = tooltip.offsetHeight;
  tooltip.style.left = Math.min(window.innerWidth - width - 12, Math.max(12, x - width / 2)) + "px";
  tooltip.style.top = (y - height - 14 < 8 ? y + 18 : y - height - 14) + "px";
}
const hideTip = () => { tooltip.hidden = true; };
function tipFor(row) {
  const seconds = fmtSeconds(secondsOf(row));
  return [row.task_id, [row.family + " · trial " + row.trial, armName(row), seconds].filter(Boolean), row.outcome];
}
function bindTip(node, row) {
  node.addEventListener("pointerenter", (event) => showTip(event, ...tipFor(row)));
  node.addEventListener("pointermove", moveTip);
  node.addEventListener("pointerleave", hideTip);
  node.addEventListener("focus", (event) => showTip(event, ...tipFor(row)));
  node.addEventListener("blur", hideTip);
}

// ---------- overview ----------
function renderOverview() {
  const totals = {};
  let total = 0;
  const groups = catalog.collections.map((collection) => {
    const rows = [...collection.rows].sort((a, b) => OUTCOMES.indexOf(a.outcome) - OUTCOMES.indexOf(b.outcome));
    total += rows.length;
    const cells = rows.map((row) => {
      totals[row.outcome] = (totals[row.outcome] || 0) + 1;
      const cell = h("button", {
        type: "button", class: "cell o-" + row.outcome, "data-key": rowKey(row),
        "aria-label": shortName(collection) + ": " + row.task_id + ", trial " + row.trial + ", " + (LABEL[row.outcome] || row.outcome),
        onclick: () => openRow(collection.id, row, true),
      });
      bindTip(cell, row);
      return cell;
    });
    return h("div", { class: "waffle-group" },
      h("div", { class: "waffle-head" }, h("span", { text: shortName(collection) }), h("b", { text: String(rows.length) })),
      h("div", { class: "waffle" }, cells));
  });
  $("overview").replaceChildren(...groups);
  $("overview-legend").replaceChildren(...OUTCOMES.filter((o) => totals[o]).map((o) =>
    h("li", { class: "o-" + o }, h("span", { class: "swatch" }), LABEL[o], h("b", { text: String(totals[o]) }))));
  const checks = catalog.collections.reduce((sum, c) => sum + c.rows.reduce((n, row) => n + (row.checks ? row.checks.length : 0), 0), 0);
  const tasks = new Set(catalog.collections.flatMap((c) => c.rows.map((row) => row.task_id.split(" / ")[0])));
  $("hero-stats").replaceChildren(...[["Checks run", checks], ["Distinct tasks", tasks.size], ["Collections", catalog.collections.length]]
    .map(([label, value]) => h("div", {}, h("dt", { text: label }), h("dd", { text: num(value, 0) }))));
  const heading = $("hero-title");
  heading.replaceChildren(h("span", { class: "num", text: String(total) }), " recorded attempts, with the checks behind each verdict.");
}

// ---------- tabs ----------
function renderTabs() {
  $("tabs").replaceChildren(...catalog.collections.map((collection) => {
    const counts = countBy(collection.rows, (row) => row.outcome);
    const lead = collection.metrics[0];
    const stack = h("div", { class: "stack", "aria-hidden": "true" },
      OUTCOMES.filter((o) => counts[o]).map((o) => h("span", { class: "o-" + o, style: { flex: String(counts[o]) } })));
    return h("button", {
      type: "button", role: "tab", class: "tab", id: "tab-" + collection.id, "aria-selected": "false", "aria-controls": "collection",
      onclick: () => selectCollection(collection.id, true),
    },
      h("span", { class: "tab-name", text: shortName(collection) }),
      lead ? h("strong", { class: "tab-value", text: lead.value }) : null,
      h("span", { class: "tab-meta", text: (lead ? lead.label + " \u00b7 " : "") + collection.rows.length + " attempts" }),
      stack);
  }));
}

// ---------- collection ----------
function selectCollection(id, updateUrl) {
  const next = catalog.collections.find((collection) => collection.id === id);
  if (!next) return;
  active = next;
  selectedKey = null;
  for (const tab of $("tabs").children) tab.setAttribute("aria-selected", String(tab.id === "tab-" + id));
  if (updateUrl) {
    const url = new URL(location.href);
    url.searchParams.set("collection", id);
    history.replaceState(null, "", url);
  }
  renderCollection();
}

function renderCollection() {
  $("kind").textContent = sentence(active.kind_label);
  $("collection-title").textContent = active.title;
  $("description").textContent = active.description;
  $("revision").textContent = active.revision_label || "";
  $("inference").textContent = active.inference || "";
  $("report-link").href = active.report;
  $("download").href = active.download;
  $("latency-heading").textContent = active.latency_label || "Time";
  $("metrics").replaceChildren(...active.metrics.map(metricTile));
  renderArms();
  renderReasons();
  renderMatrix();
  renderTiming();
  $("outcome").value = "all";
  $("attempt").value = "initial";
  $("search").value = "";
  setupPolicy();
  renderRows();
}

function metricTile(metric) {
  const fraction = /^\s*(\d+(?:\.\d+)?)\s*\/\s*(\d+(?:\.\d+)?)/.exec(metric.value);
  const verdict = metric.value === "FAIL" ? " is-fail" : metric.value === "PASS" ? " is-pass" : "";
  const share = fraction && Number(fraction[2]) > 0 ? Math.min(100, (Number(fraction[1]) / Number(fraction[2])) * 100) : null;
  return h("div", { class: "metric" },
    h("div", { class: "metric-label", text: metric.label }),
    h("div", { class: "metric-value" + verdict + (metric.value.length > 9 ? " is-long" : ""), text: metric.value }),
    share != null ? h("div", { class: "meter", "aria-hidden": "true" }, h("span", { style: { width: share + "%" } })) : null,
    h("div", { class: "metric-note", text: metric.note }));
}

function armGroups(rows) {
  const order = [];
  const groups = new Map();
  for (const row of rows) {
    if (!groups.has(row.arm)) {
      groups.set(row.arm, []);
      order.push(row.arm);
    }
    groups.get(row.arm).push(row);
  }
  const catalogArms = active.arms || [];
  const describe = (rowsForArm) => {
    const label = armName(rowsForArm[0]);
    const match = catalogArms.find((arm) => {
      const a = arm.label.toLowerCase();
      const b = label.toLowerCase();
      return a.includes(b) || b.includes(a);
    });
    return { label: match ? match.label : sentence(label), note: match ? match.note : null };
  };
  const ranked = order.map((arm) => ({ arm, rows: groups.get(arm), ...describe(groups.get(arm)) }));
  if (catalogArms.length) ranked.sort((a, b) => catalogArms.findIndex((x) => x.label === a.label) - catalogArms.findIndex((x) => x.label === b.label));
  return ranked;
}

function renderArms() {
  const rows = initialRows(active);
  const groups = armGroups(rows);
  $("arms-meta").textContent = rows.length + " first attempts";
  renderByTrial(rows);
  $("arms").replaceChildren(...groups.map((group) => {
    const counts = countBy(group.rows, (row) => row.outcome);
    const total = group.rows.length;
    const bar = h("div", { class: "arm-bar" }, OUTCOMES.filter((o) => counts[o]).map((o) => {
      const segment = h("span", { class: "o-" + o, style: { flex: String(counts[o]) }, text: counts[o] / total >= 0.08 ? String(counts[o]) : "" });
      segment.addEventListener("pointerenter", (event) => showTip(event, group.label, [counts[o] + " of " + total + " attempts"], o));
      segment.addEventListener("pointermove", moveTip);
      segment.addEventListener("pointerleave", hideTip);
      return segment;
    }));
    return h("div", { class: "arm" },
      h("div", { class: "arm-top" }, h("strong", { text: group.label }), h("span", { text: (counts.pass || 0) + " / " + total + " accepted" })),
      bar,
      group.note ? h("small", { text: group.note }) : null);
  }));
}

function renderByTrial(rows) {
  const trials = [...new Set(rows.map((row) => row.trial))].sort((a, b) => a - b);
  const box = $("by-trial");
  if (trials.length < 2) {
    box.replaceChildren();
    return;
  }
  box.replaceChildren(h("p", { class: "cs-label", text: "By trial round, all policies" }), ...trials.map((trial) => {
    const subset = rows.filter((row) => row.trial === trial);
    const counts = countBy(subset, (row) => row.outcome);
    return h("div", { class: "trial-row" },
      h("span", { class: "trial-name", text: "Trial " + trial }),
      h("div", { class: "stack tall", "aria-hidden": "true" }, OUTCOMES.filter((o) => counts[o]).map((o) => h("span", { class: "o-" + o, style: { flex: String(counts[o]) } }))),
      h("b", { text: (counts.pass || 0) + " / " + subset.length }));
  }));
}

function reasonLabel(reason) {
  let label = reason.trim().replace(/^\d+\s+/, "").replace(/_/g, " ");
  label = label.replace(/^failed check: /i, "Failed check: ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function renderReasons() {
  const rows = initialRows(active).filter((row) => row.outcome !== "pass");
  const reasons = new Map();
  for (const row of rows) {
    const list = row.reasons && row.reasons.length ? row.reasons : ["No reason recorded"];
    for (const raw of new Set(list.map(reasonLabel))) {
      const entry = reasons.get(raw) || { label: raw, count: 0, outcome: row.outcome };
      entry.count += 1;
      reasons.set(raw, entry);
    }
  }
  $("reasons-meta").textContent = rows.length + " of " + initialRows(active).length + " attempts";
  if (!rows.length) {
    $("reasons").replaceChildren(h("p", { class: "empty-note", text: "Every first attempt in this collection was accepted." }));
    renderChecksSummary();
    return;
  }
  renderChecksSummary();
  const sorted = [...reasons.values()].sort((a, b) => b.count - a.count);
  const max = sorted[0].count;
  $("reasons").replaceChildren(...sorted.map((entry) =>
    h("div", { class: "reason o-" + entry.outcome },
      h("div", { class: "reason-top" }, h("span", { text: entry.label }), h("b", { text: String(entry.count) })),
      h("div", { class: "reason-bar" }, h("span", { style: { width: (entry.count / max) * 100 + "%" } })))));
}

function renderChecksSummary() {
  let total = 0;
  let passed = 0;
  const failed = new Map();
  for (const row of initialRows(active)) {
    for (const check of row.checks || []) {
      total += 1;
      if (check.passed) passed += 1;
      else failed.set(check.id, (failed.get(check.id) || 0) + 1);
    }
  }
  const box = $("checks-summary");
  if (!total) {
    box.replaceChildren();
    return;
  }
  const top = [...failed.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const maxFail = top.length ? top[0][1] : 1;
  box.replaceChildren(
    h("div", { class: "cs-head" }, h("span", { text: "Independent checks on first attempts" }), h("b", { text: passed + " / " + total + " passed" })),
    h("div", { class: "cs-meter", "aria-hidden": "true" }, h("span", { class: "o-pass", style: { flex: String(passed) } }), total - passed ? h("span", { class: "o-fail", style: { flex: String(total - passed) } }) : null),
    top.length
      ? h("div", { class: "cs-failed" }, h("p", { class: "cs-label", text: "Most frequent failed checks" }), top.map(([id, count]) =>
        h("div", { class: "reason o-fail" },
          h("div", { class: "reason-top" }, h("span", { text: humanize(id) }), h("b", { text: String(count) })),
          h("div", { class: "reason-bar" }, h("span", { style: { width: (count / maxFail) * 100 + "%" } })))))
      : h("p", { class: "cs-label", text: "No independent check failed on a first attempt." }));
}

function renderMatrix() {
  const rows = initialRows(active);
  const tasks = [...new Set(rows.map((row) => row.task_id))].sort();
  const arms = armGroups(rows);
  const trials = [...new Set(rows.map((row) => row.trial))].sort((a, b) => a - b);
  const paired = tasks.some((task) => new Set(rows.filter((row) => row.task_id === task).map((row) => row.arm)).size > 1);
  const columns = paired ? arms.map((arm) => ({ key: arm.arm, label: arm.label })) : [{ key: null, label: null }];
  const index = new Map(rows.map((row) => [row.task_id + "|" + (paired ? row.arm : "") + "|" + row.trial, row]));
  const assisted = active.rows.filter((row) => row.attempt_kind !== "initial").length;
  $("matrix-meta").textContent = tasks.length + " tasks · " + trials.length + (trials.length === 1 ? " trial" : " trials") + (assisted ? " · " + assisted + " assisted in table" : "");
  const template = ["auto"];
  columns.forEach((_, i) => {
    if (i) template.push("14px");
    trials.forEach(() => template.push("minmax(26px, auto)"));
  });
  const timed = rows.some((row) => secondsOf(row) != null);
  const wide = tasks.length > 10 || !timed;
  $("matrix-card").className = "card " + (wide ? "span-12" : "span-6");
  $("timing-card").className = "card " + (tasks.length > 10 ? "span-12" : "span-6");
  $("timing-card").hidden = !timed;
  const chunk = tasks.length > 10 ? Math.ceil(tasks.length / 2) : tasks.length;
  const blocks = [];
  for (let start = 0; start < tasks.length; start += chunk) blocks.push(matrixBlock(tasks.slice(start, start + chunk), { paired, columns, trials, index, template }));
  $("matrix").replaceChildren(...blocks);
  const present = countBy(rows, (row) => row.outcome);
  $("matrix-legend").replaceChildren(...OUTCOMES.filter((o) => present[o]).map((o) =>
    h("li", { class: "o-" + o }, h("span", { class: "swatch" }), LABEL[o], h("b", { text: String(present[o]) }))));
  markSelection();
}

function matrixBlock(tasks, { paired, columns, trials, index, template }) {
  const grid = h("div", { class: "matrix" });
  grid.style.gridTemplateColumns = template.join(" ");
  const cells = [];
  if (paired) {
    cells.push(h("span"));
    columns.forEach((column, i) => {
      if (i) cells.push(h("span"));
      cells.push(h("span", { class: "m-arm", style: { "grid-column": "span " + trials.length }, text: column.label }));
    });
  }
  cells.push(h("span"));
  columns.forEach((_, i) => {
    if (i) cells.push(h("span"));
    trials.forEach((trial) => cells.push(h("span", { class: "m-trial", text: "T" + trial })));
  });
  for (const task of tasks) {
    cells.push(h("span", { class: "m-task", title: task, text: task }));
    columns.forEach((column, i) => {
      if (i) cells.push(h("span"));
      for (const trial of trials) {
        const row = index.get(task + "|" + (paired ? column.key : "") + "|" + trial);
        if (!row) {
          cells.push(h("span", { class: "m-gap", "aria-hidden": "true" }));
          continue;
        }
        const cell = h("button", {
          type: "button", class: "cell o-" + row.outcome, "data-key": rowKey(row),
          "aria-label": task + ", " + (column.label ? column.label + ", " : "") + "trial " + trial + ", " + (LABEL[row.outcome] || row.outcome),
          onclick: () => openRow(active.id, row, true),
        });
        bindTip(cell, row);
        cells.push(cell);
      }
    });
  }
  grid.replaceChildren(...cells);
  return grid;
}

// ---------- strip plot ----------
function stripPlot(container, groups, options) {
  const width = Math.max(260, container.clientWidth || 520);
  const pad = { left: 6, right: 18, top: 6 };
  const band = 58;
  const axisH = 30;
  const height = pad.top + groups.length * band + axisH;
  const max = options.max;
  const x = (value) => pad.left + (Math.min(value, max) / max) * (width - pad.left - pad.right);
  const svg = s("svg", { class: "plot", viewBox: "0 0 " + width + " " + height, width, height, role: "img", "aria-label": options.label });
  const step = niceStep(max, width < 420 ? 3 : 5);
  for (let tick = 0; tick <= max + 1e-9; tick += step) {
    const tx = x(tick);
    svg.append(s("line", { class: "p-grid", x1: tx, x2: tx, y1: pad.top, y2: height - axisH }));
    svg.append(s("text", { x: tx, y: height - 10, "text-anchor": tick === 0 ? "start" : "middle" }, options.tickLabel(tick)));
  }
  if (options.limit != null) {
    svg.append(s("rect", { class: "p-over", x: x(options.limit), y: pad.top, width: Math.max(0, width - pad.right - x(options.limit)), height: height - axisH - pad.top }));
  }
  groups.forEach((group, gi) => {
    const top = pad.top + gi * band;
    svg.append(s("text", { class: "p-label", x: pad.left, y: top + 16 }, group.label));
    if (group.median != null) {
      svg.append(s("text", { class: "p-median-label", x: width - pad.right, y: top + 16, "text-anchor": "end" }, "median " + options.valueLabel(group.median)));
    }
    const mid = top + 38;
    svg.append(s("line", { class: "p-axis", x1: pad.left, x2: width - pad.right, y1: mid, y2: mid }));
    if (group.median != null) svg.append(s("line", { class: "p-median", x1: x(group.median), x2: x(group.median), y1: mid - 13, y2: mid + 13 }));
    group.points.forEach((point, i) => {
      const jitter = ((i * 7) % 5 - 2) * 3.2;
      const dot = s("circle", {
        class: "p-dot" + (rowKey(point.row) === selectedKey ? " is-selected" : ""), "data-key": rowKey(point.row),
        cx: x(point.value), cy: mid + jitter, r: 5.5, fill: "var(--" + point.outcome + ")", tabindex: "0",
        "aria-label": point.row.task_id + ", trial " + point.row.trial + ", " + options.valueLabel(point.value),
      });
      dot.addEventListener("pointerenter", (event) => showTip(event, point.row.task_id, [point.row.family + " · trial " + point.row.trial, options.valueLabel(point.value)], point.outcome));
      dot.addEventListener("pointermove", moveTip);
      dot.addEventListener("pointerleave", hideTip);
      dot.addEventListener("click", () => openRow(active.id, point.row, true));
      dot.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") openRow(active.id, point.row, true); });
      svg.append(dot);
    });
  });
  if (options.limit != null) {
    const lx = x(options.limit);
    svg.append(s("line", { class: "p-limit", x1: lx, x2: lx, y1: pad.top - 2, y2: height - axisH }));
  }
  container.replaceChildren(svg);
}

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function renderTiming() {
  const rows = initialRows(active);
  const label = active.latency_label || "Time";
  $("timing-title").textContent = label;
  const measured = rows.filter((row) => secondsOf(row) != null);
  $("timing-meta").textContent = measured.length + " / " + rows.length + " measured";
  if (!measured.length) {
    $("timing").replaceChildren(h("p", { class: "empty-note", text: "These fixed controls have no recorded timing." }));
    $("slowest").replaceChildren();
    return;
  }
  const groups = armGroups(measured).map((group) => {
    const values = group.rows.map(secondsOf);
    return { label: group.label, median: median(values), points: group.rows.map((row) => ({ row, value: secondsOf(row), outcome: row.outcome })) };
  });
  const max = niceMax(Math.max(...measured.map(secondsOf)));
  const slowest = [...measured].sort((a, b) => secondsOf(b) - secondsOf(a)).slice(0, $("timing-card").classList.contains("span-12") ? 5 : 3);
  const top = secondsOf(slowest[0]);
  $("slowest").replaceChildren(h("p", { class: "cs-label", text: "Slowest first attempts" }), ...slowest.map((row) =>
    h("button", { type: "button", class: "slow-row o-" + row.outcome, "data-key": rowKey(row), onclick: () => openRow(active.id, row, true) },
      h("span", { class: "slow-name" }, row.task_id, h("small", { text: armName(row) + " \u00b7 trial " + row.trial })),
      h("span", { class: "slow-bar", "aria-hidden": "true" }, h("span", { style: { width: (secondsOf(row) / top) * 100 + "%" } })),
      h("b", { text: fmtSeconds(secondsOf(row)) }))));
  stripPlot($("timing"), groups, {
    max, label: label + " by policy",
    tickLabel: (tick) => num(tick, 2) + "s",
    valueLabel: fmtSeconds,
  });
}

// ---------- policy replay ----------
const POLICY_UNITS = { latency_ms: "seconds", total_tokens: "tokens", cost_usd: "USD", none: "" };
function policyValue(row, metric) {
  const usage = row.usage || {};
  if (usage.provenance !== "independently_observed") return null;
  if (metric === "latency_ms") return usage.latency_ms == null ? null : usage.latency_ms / 1000;
  return usage[metric] == null ? null : usage[metric];
}

function setupPolicy() {
  const section = $("policy-section");
  section.hidden = !active.policy_replay;
  if (!active.policy_replay) return;
  $("policy-metric").value = "latency_ms";
  configureLimit(true);
  renderPolicy();
}

function configureLimit(reset) {
  const metric = $("policy-metric").value;
  const range = $("policy-range");
  const input = $("policy-limit");
  const values = initialRows(active).map((row) => policyValue(row, metric)).filter((v) => v != null);
  const disabled = metric === "none" || !values.length;
  const max = metric === "none" ? 1 : niceMax(Math.max(0, ...values));
  const step = metric === "latency_ms" ? 0.5 : metric === "total_tokens" ? Math.max(1, Math.round(max / 200)) : 0.01;
  range.max = String(max);
  range.step = String(step);
  range.disabled = disabled;
  input.disabled = metric === "none";
  input.step = metric === "total_tokens" ? "1" : "any";
  $("policy-unit").textContent = POLICY_UNITS[metric];
  if (reset) {
    range.value = String(max);
    input.value = String(max);
  }
}

function renderPolicy() {
  if (!active.policy_replay) return;
  const metric = $("policy-metric").value;
  const amount = Number($("policy-limit").value);
  const preview = $("policy-preview");
  const plot = $("policy-plot");
  const invalid = metric !== "none" && (!Number.isFinite(amount) || amount < 0 || (metric === "latency_ms" && amount === 0) || (metric === "total_tokens" && !Number.isInteger(amount)));
  if (invalid) {
    preview.replaceChildren(h("p", { class: "policy-error", text: "Enter a positive time, a whole token count, or a cost of zero or more." }));
    return;
  }
  const limits = metric === "none" ? {} : { [metric]: metric === "latency_ms" ? amount * 1000 : amount };
  const rows = initialRows(active);
  const decided = rows.map((row) => ({ row, outcome: previewDecision(row, limits), base: previewDecision(row, {}) }));
  const counts = countBy(decided, (d) => d.outcome);
  const base = countBy(decided, (d) => d.base);
  preview.replaceChildren(...["pass", "fail", "inconclusive"].map((outcome) => {
    const delta = (counts[outcome] || 0) - (base[outcome] || 0);
    return h("div", { class: "result o-" + outcome },
      h("span", { text: LABEL[outcome] + " in preview" }),
      h("strong", { text: String(counts[outcome] || 0) }),
      h("em", { text: delta === 0 ? "no change" : (delta > 0 ? "+" : "−") + Math.abs(delta) + " vs. checks only" }));
  }));
  const measured = decided.filter((d) => policyValue(d.row, metric) != null);
  const missing = rows.length - measured.length;
  if (metric === "none") {
    plot.replaceChildren(h("p", { class: "empty-note", text: "Only behavior checks apply. Pick a resource to add a limit." }));
  } else if (!measured.length) {
    plot.replaceChildren(h("p", { class: "empty-note", text: "No attempt in this study has an independent " + (metric === "cost_usd" ? "cost" : "token") + " measurement, so every preview is inconclusive." }));
  } else {
    const groups = armGroups(measured.map((d) => d.row)).map((group) => ({
      label: group.label,
      median: null,
      points: group.rows.map((row) => ({ row, value: policyValue(row, metric), outcome: decided.find((d) => d.row === row).outcome })),
    }));
    const max = Number($("policy-range").max);
    const fmt = metric === "latency_ms" ? (v) => num(v, 1) + " s" : metric === "total_tokens" ? (v) => num(v, 0) + " tokens" : (v) => "$" + num(v, 4);
    stripPlot(plot, groups, {
      max, limit: Math.min(amount, max), label: "Saved measurements against the limit",
      tickLabel: metric === "latency_ms" ? (t) => num(t, 1) + "s" : metric === "total_tokens" ? (t) => num(t, 0) : (t) => "$" + num(t, 2),
      valueLabel: fmt,
    });
  }
  $("policy-note").textContent = metric === "none"
    ? "The preview matches the recorded behavior checks."
    : measured.length + " of " + rows.length + " attempts have an independent measurement. " + (missing ? "The other " + missing + " have none, so no limit can accept them. " : "") + "Dots right of the line exceed the limit.";
}

// ---------- trial table ----------
function renderRows() {
  const rows = visibleRows(active.rows, { outcome: $("outcome").value, attempt: $("attempt").value, search: $("search").value });
  const maxSeconds = Math.max(0, ...active.rows.map((row) => secondsOf(row) || 0));
  $("row-count").textContent = rows.length + " of " + active.rows.length + " attempts";
  $("empty").hidden = rows.length > 0;
  $("rows").replaceChildren(...rows.map((row) => {
    const seconds = secondsOf(row);
    const tr = h("tr", { "data-key": rowKey(row), onclick: () => selectRow(row, false) });
    tr.append(
      h("td", {}, h("button", { type: "button", class: "row-button", onclick: (event) => { event.stopPropagation(); selectRow(row, true); } },
        row.task_id, h("small", {}, row.family + " \u00b7 trial " + row.trial + (row.attempt_kind !== "initial" ? " \u00b7 assisted" : ""), h("span", { class: "m-only", text: " \u00b7 " + armName(row) })))),
      h("td", { text: armName(row) }),
      h("td", {}, pill(row.outcome)),
      h("td", {}, seconds == null ? h("span", { class: "not-measured", text: "not measured" })
        : h("div", { class: "time-cell o-" + row.outcome }, h("span", { text: fmtSeconds(seconds) }),
          h("span", { class: "time-bar", "aria-hidden": "true" }, h("span", { style: { width: (maxSeconds ? (seconds / maxSeconds) * 100 : 0) + "%" } })))));
    return tr;
  }));
  const chosen = rows.find((row) => rowKey(row) === selectedKey) || rows.find((row) => row.outcome !== "pass") || rows[0];
  if (chosen) selectRow(chosen, false);
  else $("detail").replaceChildren(h("p", { class: "kicker", text: "Trial receipt" }), h("h3", { text: "No matching attempts" }), h("p", { class: "receipt-sub", text: "Adjust the filters to inspect another attempt." }));
}

function markSelection() {
  for (const node of document.querySelectorAll("[data-key]")) {
    const on = node.dataset.key === selectedKey;
    if (node.tagName === "TR" || node.classList.contains("cell") || node.classList.contains("p-dot") || node.classList.contains("slow-row")) node.classList.toggle("is-selected", on);
  }
}

function openRow(collectionId, row, scroll) {
  if (!active || active.id !== collectionId) selectCollection(collectionId, true);
  const kind = row.attempt_kind === "initial" ? "initial" : "all";
  if ($("attempt").value !== "all" && $("attempt").value !== row.attempt_kind) $("attempt").value = kind;
  if ($("outcome").value !== "all" && $("outcome").value !== row.outcome) $("outcome").value = "all";
  selectedKey = rowKey(row);
  renderRows();
  if (scroll) $("trials").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

function selectRow(row, scrollPanel) {
  selectedKey = rowKey(row);
  markSelection();
  const selectedRow = document.querySelector('#rows tr.is-selected');
  if (selectedRow) {
    const scroller = selectedRow.closest(".table-scroll");
    const top = selectedRow.offsetTop;
    if (top < scroller.scrollTop + 40 || top > scroller.scrollTop + scroller.clientHeight - 60) scroller.scrollTop = top - 80;
  }
  renderReceipt(row);
  if (scrollPanel && matchMedia("(max-width: 1080px)").matches) $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

function stat(label, value) {
  return h("div", { class: "stat" }, h("span", { text: label }), value == null ? h("strong", { class: "not-measured", text: "not measured" }) : h("strong", { text: value }));
}

function renderReceipt(row) {
  const panel = $("detail");
  const usage = row.usage || {};
  const reason = row.reasons && row.reasons.length ? row.reasons.map(reasonLabel).join(". ") + "."
    : row.outcome === "pass" ? "Every required check matched."
    : row.outcome === "production_failed" ? "The producer did not return an assessable candidate."
    : row.outcome === "pending" ? "This reserved trial has not finished."
    : "The available evidence did not establish acceptance.";
  const parts = [
    h("div", { class: "receipt-top" }, h("p", { class: "kicker", text: row.attempt_kind === "initial" ? "Trial receipt" : "Assisted correction" }), pill(row.outcome)),
    h("h3", { text: row.task_id }),
    h("p", { class: "receipt-sub", text: row.family + " · trial " + row.trial + " · " + armName(row) }),
    h("p", { class: "receipt-reason o-" + row.outcome, text: reason }),
    h("div", { class: "stats" },
      stat(active.latency_label || "Time", fmtSeconds(secondsOf(row))),
      stat("Tokens", usage.total_tokens == null ? null : num(usage.total_tokens, 0)),
      stat("Cost (USD)", usage.cost_usd == null ? null : "$" + num(usage.cost_usd, 4))),
  ];
  if (usage.provenance) parts.push(h("p", { class: "provenance", text: "Measurement: " + usage.provenance.replace(/_/g, " ") + "." }));
  const checks = row.checks || [];
  if (checks.length) {
    const passed = checks.filter((check) => check.passed).length;
    parts.push(h("div", { class: "block" },
      h("div", { class: "block-head" }, h("h4", { text: "Independent checks" }), h("span", { text: passed + " / " + checks.length + " passed" })),
      h("ul", { class: "checks" }, checks.map((check) => {
        const item = h("li", { class: "check" + (check.passed ? "" : " failed") },
          h("span", { class: "check-icon", "aria-label": check.passed ? "Passed" : "Failed", text: check.passed ? "✓" : "×" }),
          h("strong", { text: check.description || humanize(check.id) }),
          check.reason ? h("p", { text: check.reason }) : null);
        if (check.expected_state !== undefined || check.expected_responses !== undefined) {
          item.append(h("details", {}, h("summary", { text: "Expected vs. observed" }),
            h("pre", { text: JSON.stringify({ expected_responses: check.expected_responses, observed_responses: check.observed_responses, expected_state: check.expected_state, observed_state: check.observed_state }, null, 2) })));
        }
        return item;
      }))));
  }
  if (row.phases && row.phases.length) {
    const total = row.phases.reduce((sum, phase) => sum + (phase.duration_seconds || 0), 0);
    parts.push(h("div", { class: "block" },
      h("div", { class: "block-head" }, h("h4", { text: "Production stages" }), h("span", { text: fmtSeconds(total) + " total" })),
      h("div", { class: "phase-bar", "aria-hidden": "true" }, row.phases.map((phase, i) => phase.duration_seconds == null
        ? h("span", { class: "unresolved", title: phase.stage + ": " + phase.status })
        : h("span", { style: { flex: String(Math.max(phase.duration_seconds, total * 0.015)), "--c": PHASE_COLORS[i % PHASE_COLORS.length] }, title: phase.stage }))),
      h("ul", { class: "phase-list" }, row.phases.map((phase, i) => h("li", {},
        h("i", { class: phase.duration_seconds == null ? "unresolved" : "", style: { "--c": PHASE_COLORS[i % PHASE_COLORS.length] } }),
        h("span", { text: phase.stage + " · " + phase.status + (phase.model_requests != null ? " · " + phase.model_requests + " requests" : "") }),
        h("span", { text: phase.duration_seconds == null ? "no time" : fmtSeconds(phase.duration_seconds) }))))));
  }
  if (row.reported_accounting && row.reported_accounting.model_requests != null) {
    parts.push(h("p", { class: "provenance", text: "Producer-reported: " + row.reported_accounting.model_requests + " model requests, " + num(row.reported_accounting.total_tokens || 0, 0) + " tokens." }));
  }
  if (row.note) parts.push(h("p", { class: "note-callout", text: row.note }));
  const chain = RECEIPT_FIELDS.filter(([, key]) => row[key]);
  if (chain.length) {
    parts.push(h("div", { class: "block" },
      h("div", { class: "block-head" }, h("h4", { text: "Receipt chain" }), h("span", { text: chain.length + " identities" })),
      h("ul", { class: "chain" }, chain.map(([label, key]) => h("li", {},
        h("div", {}, h("span", { text: label }), h("code", { title: row[key], text: shortHash(row[key]) })),
        h("button", { type: "button", class: "copy", "aria-label": "Copy " + label.toLowerCase(), onclick: (event) => copy(row[key], event.currentTarget), text: "Copy" }))))));
  }
  panel.replaceChildren(...parts);
}

async function copy(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Select";
  }
  setTimeout(() => { button.textContent = "Copy"; }, 1400);
}

// ---------- boot ----------
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (!active) return;
    renderTiming();
    renderPolicy();
    markSelection();
  }, 120);
});

try {
  const response = await fetch("evidence/index.json", { cache: "no-cache" });
  if (!response.ok) throw new Error("Evidence is currently unavailable.");
  catalog = await response.json();
  await Promise.all(catalog.collections.map(async (collection) => {
    const parts = await Promise.all(collection.rows_files.map(async (path) => {
      const part = await fetch(path);
      if (!part.ok) throw new Error("A recorded evidence file is unavailable.");
      return part.json();
    }));
    collection.rows = parts.flat();
  }));
  $("published").textContent = "Recorded " + catalog.recorded_at.replace(" to ", " → ");
  renderOverview();
  renderTabs();
  for (const id of ["outcome", "attempt", "search"]) $(id).addEventListener(id === "search" ? "input" : "change", renderRows);
  $("policy-metric").addEventListener("change", () => { configureLimit(true); renderPolicy(); });
  $("policy-range").addEventListener("input", () => { $("policy-limit").value = $("policy-range").value; renderPolicy(); });
  $("policy-limit").addEventListener("input", () => {
    const value = Number($("policy-limit").value);
    if (Number.isFinite(value)) $("policy-range").value = String(value);
    renderPolicy();
  });
  const requested = new URLSearchParams(location.search).get("collection");
  selectCollection(catalog.collections.some((c) => c.id === requested) ? requested : catalog.collections[0].id, false);
} catch (error) {
  $("status").textContent = error.message;
  $("published").textContent = "Evidence unavailable";
}
