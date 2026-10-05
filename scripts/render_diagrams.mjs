#!/usr/bin/env node
// Renders the architecture diagrams in docs/ from the layouts below.
// Usage: node scripts/render_diagrams.mjs
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DOCS = join(dirname(fileURLToPath(import.meta.url)), "..", "docs");

const C = {
  bg: "#0d1016",
  panel: "#141922",
  stroke: "#2a3242",
  frame: "#2f3848",
  text: "#e8ebf1",
  muted: "#98a1b1",
  faint: "#6b7486",
  edge: "#5f6a7f",
  lit: "#7cb2ff",
  input: "#7cb2ff",
  target: "#f5a35c",
  output: "#3fcbd3",
  telemetry: "#b195f7",
  reject: "#f2646f",
  pass: "#3fd294",
  fail: "#f2646f",
  warn: "#ecbd4f",
  gate: "#e8ecf3",
  gateInk: "#0d1016",
  gateMuted: "#465063",
};
const FONT = "'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif";
const MONO = "'IBM Plex Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace";
const TAG = { input: C.input, hidden: C.input, target: C.target, step: C.muted, gate: C.gateMuted, output: C.output,
  telemetry: C.telemetry, trigger: C.muted, runtime: C.muted, deny: C.reject, decision: C.gateMuted, record: C.output };

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const n = (v) => Math.round(v * 10) / 10;

function text(x, y, value, cls, extra = "") {
  return '<text class="' + cls + '" x="' + n(x) + '" y="' + n(y) + '"' + extra + ">" + esc(value) + "</text>";
}

function node(d) {
  const inverted = d.kind === "gate" || d.kind === "decision";
  const pad = 18;
  const out = [];
  out.push('<g class="dg-node dg-' + d.kind + '" data-id="' + d.id + '" tabindex="0">');
  out.push('<rect class="dg-box" x="' + d.x + '" y="' + d.y + '" width="' + d.w + '" height="' + d.h + '" rx="10"/>');
  let y = d.y + 25;
  if (d.tag) {
    out.push(text(d.x + pad, y, d.tag.toUpperCase(), "dg-tag", ' fill="' + (TAG[d.kind] || C.muted) + '"'));
    y += 25;
  } else {
    y += 6;
  }
  out.push(text(d.x + pad, y, d.title, d.titleMono ? "dg-title dg-mono-title" : "dg-title"));
  y += 24;
  for (const line of d.lines || []) {
    const item = typeof line === "string" ? { t: line } : line;
    if (item.parts) {
      const spans = item.parts.map((p) => '<tspan fill="' + p.f + '">' + esc(p.t) + "</tspan>").join("");
      out.push('<text class="dg-code" x="' + n(d.x + pad) + '" y="' + n(y) + '" xml:space="preserve">' + spans + "</text>");
      y += item.step || 17;
      continue;
    }
    out.push(text(d.x + pad, y, item.t, item.mono ? "dg-detail dg-mono" : "dg-detail"));
    y += item.step || 21;
  }
  if (d.chips) {
    let cx = d.x + pad;
    let cy = y - 12;
    for (const chip of d.chips) {
      const w = chip.t.length * 7 + 18;
      if (d.chipsStacked && chip !== d.chips[0]) {
        cx = d.x + pad;
        cy += 28;
      }
      out.push('<rect x="' + n(cx) + '" y="' + n(cy) + '" width="' + w + '" height="22" rx="6" fill="' + chip.c + '" fill-opacity="' + (inverted ? 0.16 : 0.14) + '" stroke="' + chip.c + '" stroke-opacity="0.55"/>');
      out.push(text(cx + 9, cy + 15, chip.t, "dg-chip", ' fill="' + (inverted ? chip.ink || chip.c : chip.c) + '"'));
      cx += w + 8;
    }
  }
  if (d.inner) out.push(d.inner);
  out.push("</g>");
  return out.join("");
}

function roundedPath(pts, r = 10) {
  let d = "M" + n(pts[0][0]) + " " + n(pts[0][1]);
  for (let i = 1; i < pts.length - 1; i++) {
    const [x0, y0] = pts[i - 1];
    const [x1, y1] = pts[i];
    const [x2, y2] = pts[i + 1];
    const l1 = Math.hypot(x1 - x0, y1 - y0);
    const l2 = Math.hypot(x2 - x1, y2 - y1);
    const rr = Math.min(r, l1 / 2, l2 / 2);
    const ax = x1 - ((x1 - x0) / l1) * rr;
    const ay = y1 - ((y1 - y0) / l1) * rr;
    const bx = x1 + ((x2 - x1) / l2) * rr;
    const by = y1 + ((y2 - y1) / l2) * rr;
    d += " L" + n(ax) + " " + n(ay) + " Q" + n(x1) + " " + n(y1) + " " + n(bx) + " " + n(by);
  }
  const last = pts[pts.length - 1];
  return d + " L" + n(last[0]) + " " + n(last[1]);
}

function edge(key, e) {
  const kind = e.kind || "flow";
  const out = ['<g class="dg-edge dg-edge-' + kind + '" data-from="' + [].concat(e.from).join(" ") + '" data-to="' + e.to + '">'];
  out.push('<path class="dg-line" d="' + roundedPath(e.pts) + '" marker-end="url(#' + key + "-arrow-" + kind + ')"/>');
  if (e.label) {
    const l = e.label;
    out.push(text(l.x, l.y, l.t, "dg-edge-label", l.anchor ? ' text-anchor="' + l.anchor + '"' : ""));
  }
  out.push("</g>");
  return out.join("");
}

function frame(f) {
  return '<g class="dg-frame"><rect x="' + f.x + '" y="' + f.y + '" width="' + f.w + '" height="' + f.h + '" rx="14"/>' +
    (f.label ? text(f.label.x, f.label.y, f.label.t.toUpperCase(), "dg-frame-label") : "") + "</g>";
}

const EDGE_COLORS = { flow: C.edge, retry: C.muted, telemetry: C.telemetry, reject: C.reject, lit: C.lit };

function render(spec) {
  const { key, w, h, title, desc } = spec;
  const markers = Object.entries(EDGE_COLORS).map(([kind, color]) =>
    '<marker id="' + key + "-arrow-" + kind + '" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto"><path d="M0 1 L9 5 L0 9 Z" fill="' + color + '"/></marker>').join("");
  const style = [
    ".dg text{font-family:" + FONT + ";}",
    ".dg .dg-bg{fill:" + C.bg + ";}",
    ".dg .dg-box{fill:" + C.panel + ";stroke:" + C.stroke + ";stroke-width:1.2;}",
    ".dg .dg-gate .dg-box,.dg .dg-decision .dg-box{fill:" + C.gate + ";stroke:" + C.gate + ";}",
    ".dg .dg-tag{font-family:" + MONO + ";font-size:11px;font-weight:600;letter-spacing:.08em;}",
    ".dg .dg-title{font-size:16px;font-weight:600;fill:" + C.text + ";letter-spacing:-.005em;}",
    ".dg .dg-mono-title{font-family:" + MONO + ";font-size:15.5px;}",
    ".dg .dg-detail{font-size:13.5px;fill:" + C.muted + ";}",
    ".dg .dg-mono{font-family:" + MONO + ";font-size:12.5px;fill:#b7c0cf;}",
    ".dg .dg-gate .dg-title,.dg .dg-decision .dg-title{fill:" + C.gateInk + ";}",
    ".dg .dg-gate .dg-detail,.dg .dg-decision .dg-detail{fill:" + C.gateMuted + ";}",
    ".dg .dg-gate .dg-mono,.dg .dg-decision .dg-mono{fill:#2c3443;}",
    ".dg .dg-chip{font-family:" + MONO + ";font-size:11px;font-weight:600;}",
    ".dg .dg-line{fill:none;stroke:" + C.edge + ";stroke-width:1.6;}",
    ".dg .dg-edge-retry .dg-line{stroke:" + C.muted + ";stroke-dasharray:5 5;}",
    ".dg .dg-edge-telemetry .dg-line{stroke:" + C.telemetry + ";stroke-dasharray:5 5;}",
    ".dg .dg-edge-reject .dg-line{stroke:" + C.reject + ";stroke-dasharray:5 5;}",
    ".dg .dg-edge-label{font-family:" + MONO + ";font-size:11px;fill:" + C.muted + ";paint-order:stroke;stroke:" + C.bg + ";stroke-width:5px;stroke-linejoin:round;}",
    ".dg .dg-frame rect{fill:#ffffff;fill-opacity:.018;stroke:" + C.frame + ";stroke-width:1.2;stroke-dasharray:6 6;}",
    ".dg .dg-frame-label{font-family:" + MONO + ";font-size:11px;font-weight:600;letter-spacing:.1em;fill:" + C.faint + ";}",
    ".dg .dg-note{font-size:13px;fill:" + C.faint + ";}",
    ".dg .dg-code{font-family:" + MONO + ";font-size:12px;}",
    ".dg .dg-check{font-size:13.5px;fill:#2c3443;}",
    ".dg .dg-band-title{font-size:14.5px;font-weight:600;fill:" + C.text + ";}",
  ].join("");
  const body = [];
  body.push('<rect class="dg-bg" width="' + w + '" height="' + h + '" rx="18"/>');
  for (const f of spec.frames || []) body.push(frame(f));
  for (const e of spec.edges || []) body.push(edge(key, e));
  for (const d of spec.nodes || []) body.push(node(d));
  for (const extra of spec.extras || []) body.push(extra);
  return '<svg xmlns="http://www.w3.org/2000/svg" class="dg" data-diagram="' + key + '" viewBox="0 0 ' + w + " " + h + '" width="' + w + '" height="' + h + '" role="img" aria-labelledby="' + key + "-title " + key + '-desc">\n' +
    '<title id="' + key + '-title">' + esc(title) + "</title>\n" +
    '<desc id="' + key + '-desc">' + esc(desc) + "</desc>\n" +
    "<defs><style>" + style + "</style>" + markers + "</defs>\n" +
    body.join("\n") + "\n</svg>\n";
}

// ---------- Evaluation platform ----------
function platform() {
  const col = [304, 582, 860, 1138];
  const cw = 238;
  const cx = (i) => col[i] + cw / 2;
  const inY = 40, inH = 156;
  const stepY = 276, stepH = 164, stepMid = stepY + 82;
  const frameY = 252, frameB = 524;
  const outY = 580, outH = 112;
  const bandY = 728, bandH = 92;
  const nodes = [
    { id: "corpus", kind: "input", x: col[0], y: inY, w: cw, h: inH, tag: "Input", title: "Reviewer corpus v1.1.0",
      lines: ["20 golden diffs", "13 faulty, 7 clean", "raw diff or task snapshot"] },
    { id: "target", kind: "target", x: col[1], y: inY, w: cw, h: inH, tag: "Target under test", title: "One harness, three targets",
      lines: ["pull-request reviewer", "coding agent in a k3s pod", "already-produced workspace"] },
    { id: "expected", kind: "hidden", x: col[2], y: inY, w: cw, h: inH, tag: "Hidden input", title: "Expected findings",
      lines: ["file, category, severity", "changed-line range", "optional reproducers"] },
    { id: "thresholds", kind: "hidden", x: col[3], y: inY, w: cw, h: inH, tag: "Hidden input", title: "Release thresholds",
      lines: ["0 infrastructure errors", "100% security-blocker recall", "≥95% clean accuracy", "100% case stability"] },
    { id: "trigger", kind: "trigger", x: 40, y: stepY, w: 204, h: stepH, tag: "Trigger", title: "Start a run",
      lines: [{ t: "./review-stack eval", mono: true }, { t: "nightly CronJob", mono: true }, { t: "agent-eval CLI", mono: true }, { t: "CI pipeline", mono: true }] },
    { id: "bind", kind: "step", x: col[0], y: stepY, w: cw, h: stepH, tag: "Step 01", title: "Bind exact input",
      lines: ["hash the diff or snapshot", "hide goldens and thresholds", "fail closed on bad artifacts"] },
    { id: "execute", kind: "step", x: col[1], y: stepY, w: cw, h: stepH, tag: "Step 02", title: "Run the target",
      lines: ["bounded process or k3s pod", "allowlisted environment", "timeout + process cleanup", "first attempt kept separately"] },
    { id: "verify", kind: "step", x: col[2], y: stepY, w: cw, h: stepH, tag: "Step 03", title: "Verify and score",
      lines: ["strict JSON + digest checks", "finding F1 + block decision", "hidden tests and scanners", "judge can’t loosen goldens"] },
    { id: "gate", kind: "gate", x: col[3], y: stepY, w: cw, h: stepH, tag: "Step 04", title: "Release gate",
      lines: ["every trial in the cohort,", "checked against thresholds"],
      chips: [{ t: "PASS", c: "#13915a", ink: "#0d7a4a" }, { t: "FAIL", c: "#d63b49", ink: "#c02a38" }] },
    { id: "telemetry", kind: "telemetry", x: col[0], y: outY, w: col[1] + cw - col[0], h: outH, tag: "Telemetry",
      title: "OpenTelemetry → Collector → Phoenix",
      lines: ["scores, outcomes, latency, attempts and counts", "the collector strips content, endpoints and authorization"] },
    { id: "report", kind: "output", x: col[2], y: outY, w: col[3] + cw - col[2], h: outH, tag: "Durable output",
      title: "JSON report + versioned baseline",
      lines: ["every trial and correction stays auditable", "content-minimized record, safe to publish"] },
  ];
  const edges = [
    ...[0, 1, 2, 3].map((i) => ({ from: nodes[i].id, to: ["bind", "execute", "verify", "gate"][i], pts: [[cx(i), inY + inH], [cx(i), stepY]] })),
    { from: "trigger", to: "bind", pts: [[244, stepMid], [col[0], stepMid]] },
    { from: "bind", to: "execute", pts: [[col[0] + cw, stepMid], [col[1], stepMid]] },
    { from: "execute", to: "verify", pts: [[col[1] + cw, stepMid], [col[2], stepMid]] },
    { from: "verify", to: "gate", pts: [[col[2] + cw, stepMid], [col[3], stepMid]] },
    { from: "verify", to: "execute", kind: "retry", pts: [[col[2] + 64, stepY + stepH], [col[2] + 64, stepY + stepH + 34], [col[1] + cw - 64, stepY + stepH + 34], [col[1] + cw - 64, stepY + stepH]],
      label: { t: "valid rejection only: one critique-guided retry, first result kept", x: col[2] - 20, y: stepY + stepH + 58, anchor: "middle" } },
    { from: ["bind", "execute", "verify", "gate"], to: "telemetry", kind: "telemetry", pts: [[cx(0), frameB], [cx(0), outY]],
      label: { t: "spans + scores", x: cx(0) + 12, y: frameB + 32 } },
    { from: "gate", to: "report", pts: [[cx(3), stepY + stepH], [cx(3), outY]] },
  ];
  const legendX = 40, legendY = inY;
  const legendRow = (i, kind, label) => {
    const y = legendY + 56 + i * 26;
    const color = EDGE_COLORS[kind];
    const dash = kind === "flow" ? "" : ' stroke-dasharray="5 5"';
    return '<path d="M' + (legendX + 18) + " " + y + " H" + (legendX + 52) + '" stroke="' + color + '" stroke-width="1.6" fill="none"' + dash + ' marker-end="url(#platform-arrow-' + kind + ')"/>' +
      text(legendX + 64, y + 4, label, "dg-detail");
  };
  const extras = [
    '<g class="dg-legend"><rect x="' + legendX + '" y="' + legendY + '" width="204" height="' + inH + '" rx="10" fill="none" stroke="' + C.stroke + '" stroke-width="1.2"/>' +
      text(legendX + 18, legendY + 25, "LEGEND", "dg-tag", ' fill="' + C.faint + '"') +
      legendRow(0, "flow", "data flow") + legendRow(1, "retry", "retry path") + legendRow(2, "telemetry", "telemetry") +
      '<rect x="' + (legendX + 18) + '" y="' + (legendY + 125) + '" width="34" height="14" rx="4" fill="' + C.gate + '"/>' +
      text(legendX + 64, legendY + 137, "decision", "dg-detail") + "</g>",
    '<g class="dg-band"><rect x="40" y="' + bandY + '" width="1336" height="' + bandH + '" rx="10" fill="#ffffff" fill-opacity=".025" stroke="' + C.stroke + '" stroke-width="1.2"/>' +
      text(58, bandY + 34, "RUNTIME", "dg-tag", ' fill="' + C.faint + '"') +
      text(58, bandY + 60, "Local k3s", "dg-band-title") +
      [["Deployment", "keeps the PR worker, telemetry and dashboard up"], ["CronJob", "nightly evaluations run once, save a report, exit"], ["Persistent volumes", "saved reports survive pod restarts"]]
        .map(([t, d], i) => text(col[0] + i * 358, bandY + 38, t, "dg-band-title") + text(col[0] + i * 358, bandY + 60, d, "dg-detail")).join("") + "</g>",
  ];
  return render({
    key: "platform", w: 1416, h: 860,
    title: "Agent Eval platform architecture",
    desc: "Versioned inputs feed a four-step harness: bind the exact input, run the target, verify and score with hidden expectations, then gate the cohort against hidden thresholds. A valid rejection allows one retry while keeping the first result. Telemetry leaves through a content-stripping collector, and the gate writes a JSON report and versioned baseline. Everything runs on local k3s.",
    frames: [{ x: 280, y: frameY, w: 1096, h: frameB - frameY, label: { t: "Evaluation harness", x: col[0], y: frameB - 16 } }],
    nodes, edges, extras,
  });
}

// ---------- Coding-agent evaluation ----------
function coding() {
  const A = { x: 40, w: 380 }, B = { x: 524, w: 480 }, Cx = 1100, Cw = 232, D = { x: 1388, w: 192 };
  const top = 64, bottom = 576;
  const podY = 216, podH = 80, podMid = podY + podH / 2;
  const gradeY = 320, gradeH = 120, podsY = gradeY + 40, podsH = 68, gradeMid = podsY + podsH / 2;
  const inspY = 464, inspH = 88, inspMid = inspY + inspH / 2;
  const subX = B.x + 36, evalX = B.x + B.w - 36 - 156;
  const nodes = [
    { id: "task", kind: "input", x: A.x + 20, y: 112, w: A.w - 40, h: 80, tag: "Input", title: "Versioned task",
      lines: ["prompt, starter code, provider credential"] },
    { id: "pod", kind: "target", x: A.x + 20, y: podY, w: A.w - 40, h: podH, tag: "Agent pod", title: "Claude Code or Codex",
      lines: ["edits the workspace inside its pod"] },
    { id: "teardown", kind: "step", x: A.x + 20, y: gradeY, w: A.w - 40, h: inspY + inspH - gradeY, tag: "After exit or timeout", title: "Clean teardown",
      lines: ["1  stop remaining agent processes", "2  require three clean process scans", "3  copy the produced workspace"],
      chips: [{ t: "\u2713 scan 1", c: C.pass }, { t: "\u2713 scan 2", c: C.pass }, { t: "\u2713 scan 3", c: C.pass }], chipsStacked: false },
    { id: "usage", kind: "step", x: B.x + 20, y: podY, w: B.w - 40, h: podH, tag: "Usage + process", title: "Provider log and timing",
      lines: ["provider JSONL, wall time, exit code, timeout"] },
    { id: "submission", kind: "step", x: subX, y: podsY, w: 156, h: podsH, title: "Submission pod", lines: ["produced code only"] },
    { id: "evaluator", kind: "step", x: evalX, y: podsY, w: 156, h: podsH, title: "Evaluator pod", lines: ["hidden tests"] },
    { id: "inspect", kind: "step", x: B.x + 20, y: inspY, w: B.w - 40, h: inspH, tag: "Static inspection", title: "Workspace inspection",
      lines: ["diff size · Ruff · Semgrep · Gitleaks · Trivy · judge"] },
    { id: "policy", kind: "decision", x: Cx, y: 112, w: Cw, h: inspY + inspH - 112, tag: "Decision", title: "Acceptance policy",
      lines: ["joins all required evidence;", "fails closed if any is missing"] },
    { id: "outcome", kind: "output", x: D.x, y: 112, w: D.w, h: 176, tag: "Outcome", title: "Explicit outcome", lines: [],
      chips: [{ t: "accepted", c: C.pass }, { t: "rejected", c: C.fail }, { t: "infra_error", c: C.warn }], chipsStacked: true },
    { id: "record", kind: "record", x: D.x, y: 336, w: D.w, h: 124, tag: "Record", title: "results.json", titleMono: true,
      lines: [{ t: "metrics.db", mono: true }, "kept for every trial"] },
  ];
  const gapMid = (A.x + A.w + B.x) / 2;
  const edges = [
    { from: "task", to: "pod", pts: [[A.x + A.w / 2, 192], [A.x + A.w / 2, podY]] },
    { from: "pod", to: "teardown", pts: [[A.x + A.w / 2, podY + podH], [A.x + A.w / 2, gradeY]] },
    { from: "pod", to: "usage", pts: [[A.x + A.w - 20, podMid], [B.x + 20, podMid]], label: { t: "provider JSONL", x: gapMid, y: podMid - 10, anchor: "middle" } },
    { from: "teardown", to: "submission", pts: [[A.x + A.w - 20, gradeMid], [subX, gradeMid]], label: { t: "workspace", x: gapMid, y: gradeMid - 10, anchor: "middle" } },
    { from: "teardown", to: "inspect", pts: [[A.x + A.w - 20, inspMid], [B.x + 20, inspMid]], label: { t: "workspace", x: gapMid, y: inspMid - 10, anchor: "middle" } },
    { from: "evaluator", to: "submission", pts: [[evalX, gradeMid], [subX + 156, gradeMid]], label: { t: "one TCP port", x: (subX + 156 + evalX) / 2, y: gradeMid + 20, anchor: "middle" } },
    { from: "usage", to: "policy", pts: [[B.x + B.w - 20, podMid], [Cx, podMid]] },
    { from: "evaluator", to: "policy", pts: [[evalX + 156, gradeMid], [Cx, gradeMid]] },
    { from: "inspect", to: "policy", pts: [[B.x + B.w - 20, inspMid], [Cx, inspMid]] },
    { from: "policy", to: "outcome", pts: [[Cx + Cw, 200], [D.x, 200]] },
    { from: "outcome", to: "record", pts: [[D.x + D.w / 2, 288], [D.x + D.w / 2, 336]] },
  ];
  const policyNode = nodes.find((item) => item.id === "policy");
  const check = (y, label) => '<text class="dg-check" x="' + (Cx + 18) + '" y="' + (y + 4) + '"><tspan fill="#13915a" font-weight="700">✓</tspan>  ' + esc(label) + "</text>";
  const extras = [
    text(B.x + 36, gradeY + 26, "ISOLATED BLACK-BOX GRADING", "dg-frame-label"),
    text(B.x + 20, 140, "Three sources the agent cannot influence.", "dg-detail"),
  ];
  policyNode.inner = check(podMid, "usage + process evidence") + check(gradeMid, "hidden test results") + check(inspMid, "inspection findings");
  return render({
    key: "coding", w: D.x + D.w + 60, h: bottom + 40,
    title: "Coding-agent evaluation",
    desc: "A versioned task runs in an agent pod. After a clean teardown, the provider log, isolated black-box grading and workspace inspection supply independent evidence to the acceptance policy, which records an explicit outcome in results.json and metrics.db.",
    frames: [
      { x: A.x, y: top, w: A.w, h: bottom - top, label: { t: "01  Execute", x: A.x + 20, y: top + 28 } },
      { x: B.x, y: top, w: B.w, h: bottom - top, label: { t: "02  Collect independent evidence", x: B.x + 20, y: top + 28 } },
      { x: B.x + 20, y: gradeY, w: B.w - 40, h: gradeH, label: null },
      { x: Cx - 20, y: top, w: D.x + D.w + 20 - (Cx - 20), h: bottom - top, label: { t: "03  Decide and record", x: Cx, y: top + 28 } },
    ],
    nodes, edges, extras,
  });
}

// ---------- Governed execution ----------
function governance() {
  const bw = 188, gap = 48, x0 = 40, y = 72, bh = 132, mid = y + 62;
  const xs = [0, 1, 2, 3, 4, 5].map((i) => x0 + i * (bw + gap));
  const c = (i) => xs[i] + bw / 2;
  const specs = [
    ["request", "step", "01 Define", "Request + policy", ["actor, task, model", "limits + registries", "allowed identities"]],
    ["preflight", "gate", "02 Admit", "Preflight gate", ["checks request, policy", "and registered", "identities"]],
    ["snapshot", "step", "03 Freeze", "Private snapshot", ["exact copy of the task", "tree, for this run only"]],
    ["recheck", "gate", "04 Recheck", "Identity recheck", ["recomputes task, image,", "recipe and scanner", "identities"]],
    ["run", "target", "05 Run", "Exact execution", ["approved image", "+ approved recipe"]],
    ["verify", "output", "06 Verify", "Observed result", ["evidence + limits", "→ final outcome"]],
  ];
  const nodes = specs.map(([id, kind, tag, title, lines], i) => ({ id, kind, x: xs[i], y, w: bw, h: bh, tag, title, lines }));
  const denyW = 300, denyX = c(2) - denyW / 2, denyY = 268, denyH = 64, denyMid = denyY + 32;
  nodes.push({ id: "deny", kind: "deny", x: denyX, y: denyY, w: denyW, h: denyH, tag: "Denied", title: "Stop and record the denial", lines: [] });
  const edges = [];
  for (let i = 0; i < 5; i++) {
    const e = { from: specs[i][0], to: specs[i + 1][0], pts: [[xs[i] + bw, mid], [xs[i + 1], mid]] };
    if (i === 1) e.label = { t: "YES", x: xs[i] + bw + gap / 2, y: mid - 10, anchor: "middle" };
    if (i === 3) e.label = { t: "MATCH", x: xs[i] + bw + gap / 2, y: mid - 10, anchor: "middle" };
    edges.push(e);
  }
  edges.push({ from: "preflight", to: "deny", kind: "reject", pts: [[c(1), y + bh], [c(1), denyMid], [denyX, denyMid]], label: { t: "NO", x: c(1) + 12, y: y + bh + 38 } });
  edges.push({ from: "recheck", to: "deny", kind: "reject", pts: [[c(3), y + bh], [c(3), denyMid], [denyX + denyW, denyMid]], label: { t: "MISMATCH", x: c(3) + 12, y: y + bh + 38 } });
  const extras = [text(c(2), denyY + denyH + 44, "Preflight denial happens before cluster setup, image work, credential loading or any model call.", "dg-note", ' text-anchor="middle"')];
  return render({
    key: "governance", w: x0 * 2 + 6 * bw + 5 * gap, h: 420,
    title: "Governed execution",
    desc: "A request is checked against policy and registries before any side effect. An admitted request gets a private task snapshot, then its execution identity is recomputed before the exact image and recipe run. A failed check at either gate stops the run and records the denial.",
    nodes, edges, extras,
  });
}

// ---------- Evidence and metrics ----------
function metrics() {
  const w = 284, gap = 72, x = [40, 40 + w + gap, 40 + 2 * (w + gap), 40 + 3 * (w + gap)];
  const top = 64, h = 340;
  const rows = [{ y: top, h: 96 }, { y: top + 124, h: 88 }, { y: top + 252, h: 88 }];
  const mid = (r) => r.y + r.h / 2;
  const K = "#2456c9", S = "#0e7a4c", N = "#b4441c", P = "#465063";
  const kv = (k, v, vf, last) => ({ parts: [{ t: '  "' + k + '": ', f: K }, { t: v, f: vf }, { t: last ? "" : ",", f: P }] });
  const dot = (label, color) => ({ parts: [{ t: "●  ", f: color }, { t: label, f: C.muted }], step: 24 });
  const nodes = [
    { id: "sources", kind: "input", x: x[0], y: top, w, h: 236, tag: "Raw evidence", title: "Independent sources",
      lines: [dot("provider JSONL", C.input), dot("process timing", C.input), dot("JUnit + coverage", C.pass), dot("diff + scanner results", C.target),
        dot("judge results", C.telemetry), dot("governance + provenance", C.output)] },
    { id: "results", kind: "decision", x: x[1], y: top, w, h, tag: "Canonical record", title: "results.json", titleMono: true,
      lines: [{ t: "complete, bounded run record;", step: 18 }, { t: "explicit nulls for missing values", step: 28 },
        { parts: [{ t: "{", f: P }] }, kv("task_id", '"example-todo-api"', S), kv("agent", '"oracle"', S), kv("correctness", "{…}", P),
        kv("scans", "{…}", P), kv("judge", "{…}", P), kv("assurance", "null", N), kv("outcome", "{…}", P), kv("provenance", "{…}", P, true),
        { parts: [{ t: "}", f: P }] }] },
    { id: "db", kind: "output", x: x[2], y: rows[0].y, w, h: rows[0].h, tag: "Query projection", title: "metrics.db", titleMono: true,
      lines: ["normalized across completed runs"] },
    { id: "verifyrun", kind: "step", x: x[2], y: rows[1].y, w, h: rows[1].h, tag: "Verification", title: "verify-run", titleMono: true,
      lines: ["recomputes and cross-checks"] },
    { id: "otel", kind: "telemetry", x: x[2], y: rows[2].y, w, h: rows[2].h, tag: "Optional export", title: "OpenTelemetry",
      lines: ["content-minimized and lossy"] },
    { id: "report", kind: "output", x: x[3], y: rows[0].y, w, h: rows[0].h, tag: "Consumers", title: "compare + report", titleMono: true,
      lines: ["pass@k, trends, benchmark views"] },
  ];
  const edges = [
    { from: "sources", to: "results", pts: [[x[0] + w, top + 118], [x[1], top + 118]] },
    { from: "results", to: "db", pts: [[x[1] + w, mid(rows[0])], [x[2], mid(rows[0])]] },
    { from: "results", to: "verifyrun", pts: [[x[1] + w, mid(rows[1])], [x[2], mid(rows[1])]] },
    { from: "results", to: "otel", kind: "telemetry", pts: [[x[1] + w, mid(rows[2])], [x[2], mid(rows[2])]] },
    { from: "db", to: "report", pts: [[x[2] + w, mid(rows[0])], [x[3], mid(rows[0])]] },
  ];
  return render({
    key: "metrics", w: 40 * 2 + 4 * w + 3 * gap, h: top + h + 48,
    title: "Evidence and metrics",
    desc: "Independent sources are preserved in results.json, the canonical run record. metrics.db is a query projection used by compare and report, verify-run recomputes and cross-checks the record, and optional OpenTelemetry export is content-minimized and lossy.",
    nodes, edges,
  });
}

const outputs = {
  "local-review-platform.svg": platform(),
  "coding-agent-evaluation.svg": coding(),
  "governed-run.svg": governance(),
  "metrics-flow.svg": metrics(),
};
for (const [file, svg] of Object.entries(outputs)) {
  writeFileSync(join(DOCS, file), svg);
  console.log("wrote docs/" + file);
}
