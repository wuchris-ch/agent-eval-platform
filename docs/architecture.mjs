(() => {
  "use strict";

  const stage = document.getElementById("stage");
  const toolbar = stage.querySelector(".toolbar");
  const canvas = document.getElementById("canvas");
  const zoomLevel = document.getElementById("zoom-level");
  const items = [...document.querySelectorAll(".diagram-item")];
  const notes = [...document.querySelectorAll(".reading ol")];
  const pointers = new Map();
  const cache = new Map();
  const state = { scale: 1, x: 0, y: 0, fit: 1, w: 1200, h: 800, drag: null, pinch: null, gesture: null };
  let svg = null;
  let edges = [];
  let pinned = null;
  let loadToken = 0;

  const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
  const minScale = () => Math.min(0.2, state.fit * 0.5);

  function render() {
    canvas.style.transform = "translate(" + state.x + "px, " + state.y + "px) scale(" + state.scale + ")";
    zoomLevel.textContent = Math.round(state.scale * 100) + "%";
  }

  const stacked = window.matchMedia("(max-width: 1080px)");
  function sizeStage() {
    if (!stacked.matches) {
      stage.style.removeProperty("--stage-h");
      return;
    }
    const width = stage.getBoundingClientRect().width;
    const height = Math.round(Math.min(window.innerHeight * 0.72, Math.max(280, width * (state.h / state.w) + toolbar.offsetHeight + 44)));
    stage.style.setProperty("--stage-h", height + "px");
  }

  function fit() {
    sizeStage();
    const box = stage.getBoundingClientRect();
    const pad = box.width < 680 ? 14 : 36;
    const top = stacked.matches ? toolbar.offsetHeight + 24 : pad;
    state.fit = Math.min((box.width - pad * 2) / state.w, (box.height - top - pad) / state.h, 1.4);
    state.scale = state.fit;
    state.x = (box.width - state.w * state.scale) / 2;
    state.y = top + (box.height - top - pad - state.h * state.scale) / 2;
    render();
  }

  function zoomAt(clientX, clientY, next) {
    const box = stage.getBoundingClientRect();
    const px = clientX - box.left;
    const py = clientY - box.top;
    const wx = (px - state.x) / state.scale;
    const wy = (py - state.y) / state.scale;
    state.scale = clamp(next, minScale(), 5);
    state.x = px - wx * state.scale;
    state.y = py - wy * state.scale;
    render();
  }

  function zoomCenter(factor) {
    const box = stage.getBoundingClientRect();
    zoomAt(box.left + box.width / 2, box.top + box.height / 2, state.scale * factor);
  }

  // ----- tracing -----
  function trace(id) {
    if (!svg) return;
    const nodes = new Set([id]);
    const lit = new Set();
    let frontier = [id];
    while (frontier.length) {
      const next = [];
      for (const edge of edges) {
        if (lit.has(edge) || !edge.from.some((f) => frontier.includes(f))) continue;
        lit.add(edge);
        if (!nodes.has(edge.to)) {
          nodes.add(edge.to);
          next.push(edge.to);
        }
      }
      frontier = next;
    }
    const upstream = new Set([id]);
    frontier = [id];
    while (frontier.length) {
      const next = [];
      for (const edge of edges) {
        if (!frontier.includes(edge.to)) continue;
        lit.add(edge);
        for (const source of edge.from) {
          if (upstream.has(source)) continue;
          upstream.add(source);
          nodes.add(source);
          next.push(source);
        }
      }
      frontier = next;
    }
    svg.classList.add("is-tracing");
    for (const node of svg.querySelectorAll(".dg-node")) {
      node.classList.toggle("is-lit", nodes.has(node.dataset.id));
      node.classList.toggle("is-focus", node.dataset.id === id);
    }
    for (const edge of edges) {
      const on = lit.has(edge);
      edge.el.classList.toggle("is-lit", on);
      if (edge.kind === "flow") edge.path.setAttribute("marker-end", on ? edge.litMarker : edge.marker);
    }
  }

  function clearTrace() {
    if (!svg) return;
    svg.classList.remove("is-tracing");
    for (const node of svg.querySelectorAll(".dg-node")) node.classList.remove("is-lit", "is-focus");
    for (const edge of edges) {
      edge.el.classList.remove("is-lit");
      edge.path.setAttribute("marker-end", edge.marker);
    }
  }

  function setupTracing() {
    pinned = null;
    const title = svg.querySelector("title");
    if (title) {
      svg.setAttribute("aria-label", title.textContent);
      title.remove();
    }
    svg.removeAttribute("aria-labelledby");
    svg.setAttribute("role", "group");
    const key = svg.dataset.diagram;
    edges = [...svg.querySelectorAll(".dg-edge")].map((el) => {
      const path = el.querySelector(".dg-line");
      const kind = (el.getAttribute("class").match(/dg-edge-(\w+)/) || [])[1] || "flow";
      return { el, path, kind, from: el.dataset.from.split(" "), to: el.dataset.to, marker: path.getAttribute("marker-end"), litMarker: "url(#" + key + "-arrow-lit)" };
    });
    for (const node of svg.querySelectorAll(".dg-node")) {
      node.setAttribute("role", "button");
      const title = node.querySelector(".dg-title");
      node.setAttribute("aria-label", "Trace " + (title ? title.textContent : node.dataset.id));
      node.addEventListener("pointerenter", (event) => { if (!pinned && event.pointerType === "mouse" && !state.drag?.moved) trace(node.dataset.id); });
      node.addEventListener("pointerleave", () => { if (!pinned && !state.drag?.moved) clearTrace(); });
      node.addEventListener("focus", () => { if (!pinned) trace(node.dataset.id); });
      node.addEventListener("blur", () => { if (!pinned) clearTrace(); });
      node.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          togglePin(node.dataset.id);
        }
      });
    }
  }

  function togglePin(id) {
    if (pinned === id || !id) {
      pinned = null;
      clearTrace();
    } else {
      pinned = id;
      trace(id);
    }
  }

  // ----- loading -----
  async function select(item, updateUrl) {
    if (!item) return;
    const token = ++loadToken;
    for (const candidate of items) candidate.setAttribute("aria-current", String(candidate === item));
    for (const list of notes) list.hidden = list.dataset.for !== item.dataset.diagram;
    if (updateUrl) {
      const url = new URL(location.href);
      url.searchParams.set("diagram", item.dataset.diagram);
      history.replaceState(null, "", url);
    }
    const src = item.dataset.src;
    try {
      let markup = cache.get(src);
      if (!markup) {
        const response = await fetch(src);
        if (!response.ok) throw new Error("Diagram unavailable");
        markup = await response.text();
        cache.set(src, markup);
      }
      if (token !== loadToken) return;
      canvas.innerHTML = markup;
      svg = canvas.querySelector("svg");
      state.w = Number(svg.getAttribute("width")) || 1200;
      state.h = Number(svg.getAttribute("height")) || 800;
      setupTracing();
      fit();
    } catch {
      if (token !== loadToken) return;
      svg = null;
      edges = [];
      const img = new Image();
      img.alt = item.querySelector("strong").textContent + " diagram";
      img.draggable = false;
      img.onload = () => { state.w = img.naturalWidth; state.h = img.naturalHeight; fit(); };
      img.src = src;
      canvas.replaceChildren(img);
    }
  }

  for (const item of items) item.addEventListener("click", () => select(item, true));

  // ----- pointer input -----
  stage.addEventListener("wheel", (event) => {
    event.preventDefault();
    const speed = event.deltaMode === 1 ? 0.05 : 0.0016;
    zoomAt(event.clientX, event.clientY, state.scale * Math.exp(-event.deltaY * speed));
  }, { passive: false });

  stage.addEventListener("dblclick", (event) => {
    if (event.target.closest(".toolbar")) return;
    zoomAt(event.clientX, event.clientY, state.scale * 1.6);
  });

  stage.addEventListener("gesturestart", (event) => { event.preventDefault(); state.gesture = state.scale; });
  stage.addEventListener("gesturechange", (event) => {
    event.preventDefault();
    if (state.gesture != null) zoomAt(event.clientX, event.clientY, state.gesture * event.scale);
  });
  stage.addEventListener("gestureend", () => { state.gesture = null; });

  stage.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || event.target.closest(".toolbar")) return;
    stage.setPointerCapture(event.pointerId);
    pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
    if (pointers.size === 1) {
      state.drag = { px: event.clientX, py: event.clientY, x: state.x, y: state.y, moved: false };
    } else if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      const box = stage.getBoundingClientRect();
      const mx = (a.x + b.x) / 2 - box.left;
      const my = (a.y + b.y) / 2 - box.top;
      state.pinch = { d: Math.hypot(b.x - a.x, b.y - a.y), scale: state.scale, wx: (mx - state.x) / state.scale, wy: (my - state.y) / state.scale };
      if (state.drag) state.drag.moved = true;
    }
  });

  stage.addEventListener("pointermove", (event) => {
    if (!pointers.has(event.pointerId)) return;
    pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
    if (pointers.size === 2 && state.pinch) {
      const [a, b] = [...pointers.values()];
      const box = stage.getBoundingClientRect();
      const mx = (a.x + b.x) / 2 - box.left;
      const my = (a.y + b.y) / 2 - box.top;
      state.scale = clamp(state.pinch.scale * Math.hypot(b.x - a.x, b.y - a.y) / Math.max(1, state.pinch.d), minScale(), 5);
      state.x = mx - state.pinch.wx * state.scale;
      state.y = my - state.pinch.wy * state.scale;
      render();
    } else if (pointers.size === 1 && state.drag) {
      const dx = event.clientX - state.drag.px;
      const dy = event.clientY - state.drag.py;
      if (!state.drag.moved && Math.hypot(dx, dy) > 4) {
        state.drag.moved = true;
        stage.classList.add("is-dragging");
      }
      if (state.drag.moved) {
        state.x = state.drag.x + dx;
        state.y = state.drag.y + dy;
        render();
      }
    }
  });

  function release(event) {
    if (!pointers.has(event.pointerId)) return;
    pointers.delete(event.pointerId);
    state.pinch = null;
    if (pointers.size === 0) {
      const tap = state.drag && !state.drag.moved && event.type === "pointerup";
      state.drag = null;
      stage.classList.remove("is-dragging");
      if (tap) {
        const hit = document.elementFromPoint(event.clientX, event.clientY);
        const node = hit && hit.closest(".dg-node");
        togglePin(node ? node.dataset.id : null);
      }
    } else if (pointers.size === 1) {
      const [rest] = [...pointers.values()];
      state.drag = { px: rest.x, py: rest.y, x: state.x, y: state.y, moved: true };
    }
  }
  stage.addEventListener("pointerup", release);
  stage.addEventListener("pointercancel", release);

  // ----- controls -----
  document.querySelector('[data-action="zoom-in"]').addEventListener("click", () => zoomCenter(1.25));
  document.querySelector('[data-action="zoom-out"]').addEventListener("click", () => zoomCenter(0.8));
  document.querySelector('[data-action="fit"]').addEventListener("click", fit);
  const fullscreenButton = document.querySelector('[data-action="fullscreen"]');
  fullscreenButton.addEventListener("click", async () => {
    if (document.fullscreenElement) await document.exitFullscreen();
    else if (stage.requestFullscreen) await stage.requestFullscreen();
  });
  document.addEventListener("fullscreenchange", () => {
    fullscreenButton.textContent = document.fullscreenElement ? "Exit full screen" : "Full screen";
    setTimeout(fit, 60);
  });
  window.addEventListener("keydown", (event) => {
    if (event.target.closest && event.target.closest("input, select, textarea")) return;
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === "+" || event.key === "=") zoomCenter(1.25);
    else if (event.key === "-") zoomCenter(0.8);
    else if (event.key === "0") fit();
    else if (event.key === "Escape") togglePin(null);
  });
  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(fit, 100);
  });

  const requested = new URLSearchParams(location.search).get("diagram");
  select(items.find((item) => item.dataset.diagram === requested) || items[0], false);
})();
