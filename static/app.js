"use strict";

// ---------------------------------------------------------------- helpers
const state = { snap: null, snaps: [], topo: null, cy: null };
const $ = (sel, el = document) => el.querySelector(sel);
const view = () => $("#view");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path) {
  const r = await fetch(`/api/${encodeURIComponent(state.snap)}${path}`);
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(body.detail || r.statusText);
  }
  return r.json();
}

// Write calls. `path` is absolute (/api/...) so it also covers snapshot-level endpoints.
async function send(method, path, body) {
  const r = await fetch(path, { method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || r.statusText));
  return data;
}
const snapApi = (p) => `/api/${encodeURIComponent(state.snap)}${p}`;

function toast(msg, bad = false) {
  const t = document.createElement("div");
  t.className = `toast${bad ? " bad" : ""}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

async function topology() {
  if (!state.topo) state.topo = await api("/topology");
  return state.topo;
}

function store(key, val) {
  try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch { return null; }
}

const ISSUE = {
  FORWARD_UNREACHABLE: { title: "Forward path broken", cls: "b-crit" },
  REVERSE_UNREACHABLE: { title: "Return path broken", cls: "b-crit" },
  POLICY_DENY: { title: "Blocked: no rule allows it", cls: "b-bad" },
  EXPLICIT_DENY: { title: "Blocked by a deny rule", cls: "b-info" },
  ASYMMETRIC_BYPASS: { title: "Asymmetric: reply bypasses firewall", cls: "b-crit" },
  ASYMMETRIC_NO_SESSION: { title: "Asymmetric: reply hits firewall with no session", cls: "b-crit" },
};
const issueBadge = (k) => `<span class="badge ${(ISSUE[k] || {}).cls || "b-info"}">${esc((ISSUE[k] || {}).title || k)}</span>`;
const roleBadge = (role) => `<span class="badge ${role === "firewall" ? "b-fw" : role === "switch" ? "b-switch" : "b-router"}">${esc(role)}</span>`;
const sevBadge = (s) => `<span class="badge ${{ high: "b-crit", medium: "b-bad", low: "b-warn", info: "b-info" }[s]}">${esc(s)}</span>`;

function parseHash() {
  const h = location.hash.replace(/^#\/?/, "");
  const [pathPart, query = ""] = h.split("?");
  const [page = "map", ...rest] = pathPart.split("/");
  return { page: page || "map", arg: decodeURIComponent(rest.join("/")), params: new URLSearchParams(query) };
}

function loading(msg = "Loading...") { view().innerHTML = `<div class="empty">${esc(msg)}</div>`; }
function fail(e) { view().innerHTML = `<div class="err">${esc(e.message || e)}</div>`; }

// ---------------------------------------------------------------- map
function subnetPositions(topo) {
  const devs = topo.nodes.filter((n) => n.kind !== "subnet");
  const placed = devs.filter((n) => Array.isArray(n.pos));
  if (!placed.length) return null; // nothing positioned yet: let the auto layout do it
  const pos = {};
  placed.forEach((n) => (pos[n.id] = { x: n.pos[0], y: n.pos[1] }));
  // Devices without a saved position (e.g. just added) go next to a positioned neighbor, else in a row below.
  const neighbors = (id) => topo.edges.filter((e) => e.source === id || e.target === id).map((e) => (e.source === id ? e.target : e.source));
  let rowX = Math.min(...placed.map((n) => n.pos[0]));
  const rowY = Math.max(...placed.map((n) => n.pos[1])) + 200;
  devs.filter((n) => !pos[n.id]).forEach((n, k) => {
    const anchor = neighbors(n.id).find((id) => pos[id]);
    if (anchor) pos[n.id] = { x: pos[anchor].x + 170, y: pos[anchor].y + 140 + 40 * k };
    else { pos[n.id] = { x: rowX, y: rowY }; rowX += 180; }
  });
  const cx = devs.reduce((a, n) => a + pos[n.id].x, 0) / devs.length;
  const cy = devs.reduce((a, n) => a + pos[n.id].y, 0) / devs.length;
  const perDev = {};
  topo.nodes.filter((n) => n.kind === "subnet").forEach((n) => {
    const p = pos[n.attached_to];
    let dx = p.x - cx, dy = p.y - cy;
    const len = Math.hypot(dx, dy) || 1;
    if (Math.hypot(dx, dy) < 1) { dx = 0; dy = 1; } else { dx /= len; dy /= len; }
    const k = (perDev[n.attached_to] = (perDev[n.attached_to] || 0) + 1) - 1;
    const ang = (k % 2 ? 1 : -1) * Math.ceil(k / 2) * 0.6;
    const rx = dx * Math.cos(ang) - dy * Math.sin(ang), ry = dx * Math.sin(ang) + dy * Math.cos(ang);
    pos[n.id] = { x: p.x + rx * 130, y: p.y + ry * 110 };
  });
  return pos;
}

function renderMap(container, topo, onTap) {
  const els = [
    ...topo.nodes.map((n) => ({
      data: { id: n.id, kind: n.kind, label: n.kind === "subnet" ? n.label : `${n.id}\n${n.vendor}` },
    })),
    ...topo.edges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target, subnet: e.subnet } })),
  ];
  const pos = subnetPositions(topo);
  const cy = cytoscape({
    container, elements: els, wheelSensitivity: 0.2, minZoom: 0.3, maxZoom: 2.5,
    layout: pos ? { name: "preset", positions: (n) => pos[n.id()], padding: 40 }
                : { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 110, padding: 40 },
    style: [
      { selector: "node", style: {
        label: "data(label)", "text-wrap": "wrap", "font-family": "Inter, sans-serif", "font-size": 11,
        "text-valign": "bottom", "text-margin-y": 6, color: "#17202c", "border-width": 0, "transition-property": "opacity, border-width",
      } },
      { selector: "node[kind='router']", style: { shape: "ellipse", width: 44, height: 44, "background-color": "#2563eb" } },
      { selector: "node[kind='firewall']", style: { shape: "round-rectangle", width: 50, height: 38, "background-color": "#e11d48" } },
      { selector: "node[kind='switch']", style: { shape: "rectangle", width: 44, height: 30, "background-color": "#0891b2" } },
      { selector: "node[kind='subnet']", style: {
        shape: "round-rectangle", "background-color": "#eef2f6", "border-width": 1, "border-color": "#c3ccd8",
        width: "label", height: 22, padding: 8, "text-valign": "center", "text-margin-y": 0,
        "font-family": "JetBrains Mono, monospace", "font-size": 10, color: "#475569",
      } },
      { selector: "edge", style: { width: 2, "line-color": "#c3ccd8", "curve-style": "bezier" } },
      { selector: ".dim", style: { opacity: 0.22 } },
      { selector: "edge.fwd", style: { width: 5, "line-color": "#0d9488", opacity: 1, "z-index": 10 } },
      { selector: "edge.rev", style: { width: 4, "line-color": "#d97706", "line-style": "dashed", opacity: 1, "z-index": 9 } },
      { selector: "edge.fwd.rev", style: { "line-color": "#7c3aed", "line-style": "solid" } },
      { selector: "node.on", style: { "border-width": 4, "border-color": "#0d9488", opacity: 1 } },
      { selector: "node.stop", style: { "border-width": 5, "border-color": "#b91c1c", opacity: 1 } },
      { selector: "node:selected", style: { "border-width": 4, "border-color": "#0e1726" } },
    ],
  });
  if (onTap) cy.on("tap", "node", (ev) => onTap(ev.target.data()));
  // The container can change size after first paint (fonts, grid reflow); keep the graph fitted.
  let last = "";
  const ro = new ResizeObserver(() => {
    const size = `${container.clientWidth}x${container.clientHeight}`;
    if (size === last || cy.destroyed()) return;
    last = size;
    cy.resize();
    cy.fit(undefined, 40);
  });
  ro.observe(container);
  cy.on("destroy", () => ro.disconnect());
  return cy;
}

function highlight(cy, paths) {
  cy.elements().removeClass("dim fwd rev on stop");
  if (!paths.length) return;
  cy.elements().addClass("dim");
  for (const { path, cls } of paths) {
    path.edges.forEach((id) => cy.getElementById(id).removeClass("dim").addClass(cls));
    path.hops.forEach((h) => cy.getElementById(h.device).removeClass("dim").addClass("on"));
    path.edges.forEach((id) => {
      const e = cy.getElementById(id);
      if (e.nonempty()) e.connectedNodes().removeClass("dim");
    });
    if (!path.delivered && path.hops.length) cy.getElementById(path.hops[path.hops.length - 1].device).addClass("stop");
  }
}

const legend = `<div class="legend">
  <span><i style="background:#2563eb;border-radius:50%"></i>Router</span>
  <span><i style="background:#0891b2;border-radius:0"></i>Switch</span>
  <span><i style="background:#e11d48"></i>Firewall</span>
  <span><i style="background:#eef2f6;border:1px solid #c3ccd8"></i>Subnet</span>
</div>`;

async function pageMap() {
  loading();
  const topo = await topology();
  const devs = topo.nodes.filter((n) => n.kind !== "subnet");
  if (!devs.length) {
    view().innerHTML = `<div class="page-head"><div><h1>Network Map</h1></div></div>
      <div class="panel empty">This snapshot has no devices yet.<br><br><a class="btn" href="#/device-new">Add device</a></div>`;
    return;
  }
  view().innerHTML = `
    <div class="page-head"><div><h1>Network Map</h1><div class="muted">Topology computed from device configs: devices sharing a subnet are linked. Drag devices to rearrange; the layout is saved.</div></div>
      <a class="btn" href="#/device-new">+ Add device</a></div>
    <div class="stats">
      <div class="stat"><b>${devs.length}</b><span>Devices</span></div>
      <div class="stat"><b>${devs.filter((n) => n.kind === "firewall").length}</b><span>Firewalls</span></div>
      <div class="stat"><b>${devs.filter((n) => n.kind === "router").length}</b><span>Routers</span></div>
      <div class="stat"><b>${topo.edges.filter((e) => !e.target.startsWith("net:")).length}</b><span>L3 links</span></div>
      <div class="stat"><b>${topo.nodes.length - devs.length}</b><span>Edge subnets</span></div>
      <div class="stat"><b>${new Set(devs.map((n) => n.vendor)).size}</b><span>Vendors</span></div>
    </div>
    <div class="map-wrap">
      <div class="map" id="map">${legend}</div>
      <div class="panel side-panel" id="side"><div class="muted">Select a device or subnet on the map.</div></div>
    </div>`;
  state.cy = renderMap($("#map"), topo, showNode);
  state.cy.on("dragfree", "node", async () => {
    const positions = {};
    state.cy.nodes().filter((n) => n.data("kind") !== "subnet").forEach((n) => {
      const p = n.position();
      positions[n.id()] = [p.x, p.y];
    });
    try {
      await send("PUT", snapApi("/layout"), { positions });
      topo.nodes.forEach((n) => { if (positions[n.id]) n.pos = positions[n.id]; });
    } catch (e) { toast(`Layout not saved: ${e.message}`, true); }
  });
}

async function showNode(d) {
  const side = $("#side");
  if (d.kind === "subnet") {
    const net = d.label;
    const host = hostIn(net);
    const node = state.topo.nodes.find((n) => n.id === d.id);
    side.innerHTML = `<h2 class="mono">${esc(net)}</h2>
      <dl class="kv"><dt>Type</dt><dd>Edge subnet</dd><dt>Gateway</dt><dd><a href="#/device/${encodeURIComponent(node.attached_to)}">${esc(node.attached_to)}</a></dd><dt>Sample host</dt><dd class="mono">${host}</dd></dl>
      <h3>Path search</h3>
      <div class="toolbar">
        <button class="ghost" id="asSrc">Use as source</button>
        <button class="ghost" id="asDst">Use as destination</button>
      </div>`;
    $("#asSrc").onclick = () => { store("nt.src", host); location.hash = "#/path"; };
    $("#asDst").onclick = () => { store("nt.dst", host); location.hash = "#/path"; };
    return;
  }
  side.innerHTML = `<div class="muted">Loading ${esc(d.id)}...</div>`;
  const dev = await api(`/devices/${encodeURIComponent(d.id)}`);
  side.innerHTML = `<h2>${esc(dev.name)} ${roleBadge(dev.role)}</h2>
    <dl class="kv">
      <dt>Vendor</dt><dd class="mono">${esc(dev.vendor)}</dd>
      <dt>Site</dt><dd>${esc(dev.site || "-")}</dd>
      <dt>Interfaces</dt><dd>${dev.interfaces.filter((i) => i.enabled).length} up / ${dev.interfaces.length}</dd>
      <dt>Routes</dt><dd>${dev.routes.filter((r) => r.installed).length} installed</dd>
      ${dev.role === "firewall" ? `<dt>Rules</dt><dd>${dev.policies.length} (${dev.policies.filter((p) => !p.enabled).length} disabled)</dd>` : ""}
      <dt>Not modeled</dt><dd>${dev.unsupported.length ? `<span class="badge b-warn">${dev.unsupported.length} items</span>` : "none"}</dd>
    </dl>
    <h3>Neighbors</h3>
    <table><tbody>${dev.interfaces.filter((i) => i.neighbor).map((i) => `<tr><td class="mono">${esc(i.name)}</td><td>${esc(i.neighbor)}</td></tr>`).join("")}</tbody></table>
    <p><a class="btn" href="#/device/${encodeURIComponent(dev.name)}">Open device</a></p>`;
}

function hostIn(cidr) {
  const [ip, len] = cidr.split("/");
  const size = 2 ** (32 - Number(len));
  const n = ip.split(".").map(Number).reduce((a, o) => a * 256 + o, 0) + (size <= 2 ? 0 : Math.min(10, size - 2));
  return [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".");
}

// ---------------------------------------------------------------- path search
async function pagePath(params) {
  const q = {
    src: params.get("src") || store("nt.src") || "",
    dst: params.get("dst") || store("nt.dst") || "",
    protocol: params.get("protocol") || "tcp",
    port: params.get("port") ?? "443",
  };
  view().innerHTML = `
    <div class="page-head"><div><h1>Path Search</h1><div class="muted">Trace a flow hop by hop, check every firewall on the way, and verify the return path.</div></div></div>
    <form class="query" id="pq">
      <label>Source IP<input class="ip" name="src" value="${esc(q.src)}" placeholder="10.1.10.50" required></label>
      <label>Destination IP<input class="ip" name="dst" value="${esc(q.dst)}" placeholder="10.2.20.10" required></label>
      <label>Protocol<select name="protocol">${["tcp", "udp", "icmp"].map((p) => `<option ${p === q.protocol ? "selected" : ""}>${p}</option>`).join("")}</select></label>
      <label>Dest port<input class="port" name="port" value="${esc(q.port)}" placeholder="443"></label>
      <button type="submit">Search</button>
    </form>
    <div class="presets" id="presets"></div>
    <div id="result"></div>`;

  $("#pq").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const p = new URLSearchParams({ src: f.get("src").trim(), dst: f.get("dst").trim(), protocol: f.get("protocol") });
    if (f.get("protocol") !== "icmp" && f.get("port").trim()) p.set("port", f.get("port").trim());
    location.hash = `#/path?${p}`;
  };
  $("#pq [name=protocol]").onchange = (e) => { $("#pq [name=port]").disabled = e.target.value === "icmp"; };

  api("/checks").then((c) => {
    if (!c.flows.length) return;
    $("#presets").innerHTML = `<span class="muted" style="align-self:center;font-size:12px">Saved flows:</span>` +
      c.flows.map((f, i) => `<button type="button" data-i="${i}">${esc(f.name)}</button>`).join("");
    $("#presets").onclick = (e) => {
      const f = c.flows[e.target.dataset.i];
      if (!f) return;
      const p = new URLSearchParams({ src: f.src, dst: f.dst, protocol: f.protocol });
      if (f.port != null) p.set("port", f.port);
      location.hash = `#/path?${p}`;
    };
  }).catch(() => {});

  if (!params.get("src") || !params.get("dst")) {
    $("#result").innerHTML = `<div class="panel empty">Enter a flow, pick a saved flow, or choose a subnet on the Network Map.</div>`;
    return;
  }
  store("nt.src", q.src); store("nt.dst", q.dst);
  $("#result").innerHTML = `<div class="empty">Computing paths...</div>`;
  let rep;
  try {
    rep = await api(`/path?${params}`);
  } catch (e) {
    $("#result").innerHTML = `<div class="err">${esc(e.message)}</div>`;
    return;
  }
  const topo = await topology();
  renderPathResult(rep, topo);
}

function renderPathResult(rep, topo) {
  const sel = { dir: "both", f: 0, r: 0 };
  $("#result").innerHTML = `
    <div class="grid2">
      <div class="panel">
        <div class="toolbar">
          <div class="seg" id="dirseg">
            <button data-d="fwd">Forward</button><button data-d="rev">Return</button><button data-d="both">Both</button>
          </div>
          <span id="ecmp"></span>
          <span class="muted" style="margin-left:auto;font-size:12px">
            <span style="color:#0d9488">&#9644;</span> forward &nbsp;
            <span style="color:#d97706">&#9476;</span> return &nbsp;
            <span style="color:#7c3aed">&#9644;</span> both
          </span>
        </div>
        <div class="map small" id="pmap">${legend}</div>
      </div>
      <div>
        ${verdict(rep)}
        ${rep.notes.map((n) => `<div class="panel muted" style="margin-bottom:14px;padding:10px 14px">&#9432; ${esc(n)}</div>`).join("")}
        ${rep.issues.length ? `<div class="panel" style="margin-bottom:14px"><h2>Findings</h2>${rep.issues.map((i) => `
          <div class="issue k-${i.kind}"><div>${issueBadge(i.kind)} <b>${esc(i.device || "")}</b></div><p>${esc(i.message)}</p></div>`).join("")}</div>` : ""}
        <div class="panel" style="margin-bottom:14px">
          <div class="tabs" id="hoptabs"></div>
          <div id="hops"></div>
        </div>
        ${recommendation(rep)}
      </div>
    </div>`;

  const cy = renderMap($("#pmap"), topo);
  const draw = () => {
    document.querySelectorAll("#dirseg button").forEach((b) => b.classList.toggle("active", b.dataset.d === sel.dir));
    const ps = [];
    if (sel.dir !== "rev" && rep.forward[sel.f]) ps.push({ path: rep.forward[sel.f], cls: "fwd" });
    if (sel.dir !== "fwd" && rep.reverse[sel.r]) ps.push({ path: rep.reverse[sel.r], cls: "rev" });
    highlight(cy, ps);
    const showRev = sel.dir === "rev";
    const list = showRev ? rep.reverse : rep.forward;
    const idx = showRev ? sel.r : sel.f;
    $("#ecmp").innerHTML = list.length > 1
      ? `<span class="seg">${list.map((_, i) => `<button data-p="${i}" class="${i === idx ? "active" : ""}">Path ${i + 1}</button>`).join("")}</span> <span class="badge b-info">${list.length} ECMP paths</span>`
      : "";
    $("#hoptabs").innerHTML = `<button class="${!showRev ? "active" : ""}" data-t="fwd">Forward hops<span class="count">${rep.forward[sel.f]?.hops.length ?? 0}</span></button>
      <button class="${showRev ? "active" : ""}" data-t="rev">Return hops<span class="count">${rep.reverse[sel.r]?.hops.length ?? 0}</span></button>`;
    $("#hops").innerHTML = hopTimeline(list[idx], rep, showRev);
  };
  $("#dirseg").onclick = (e) => { if (e.target.dataset.d) { sel.dir = e.target.dataset.d; draw(); } };
  $("#hoptabs").onclick = (e) => { if (e.target.dataset.t) { sel.dir = e.target.dataset.t; draw(); } };
  $("#ecmp").onclick = (e) => {
    if (e.target.dataset.p == null) return;
    if (sel.dir === "rev") sel.r = +e.target.dataset.p; else sel.f = +e.target.dataset.p;
    draw();
  };
  document.querySelectorAll(".code-wrap button").forEach((b) => {
    b.onclick = () => { navigator.clipboard?.writeText(b.nextElementSibling.textContent); b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1200); };
  });
  draw();
}

function verdict(rep) {
  if (rep.ok && rep.notes.length) return `<div class="verdict ok">&#10004; Flow is allowed and leaves the network <small>${esc(rep.flow.text)}</small></div>`;
  if (rep.ok) return `<div class="verdict ok">&#10004; Flow works in both directions <small>${esc(rep.flow.text)}</small></div>`;
  return `<div class="verdict bad">&#10006; ${rep.issues.length} issue${rep.issues.length > 1 ? "s" : ""} found <small>${esc(rep.flow.text)}</small></div>`;
}

const STATUS = {
  delivered: "Delivered", no_route: "Dropped: no route", loop: "Routing loop",
  leaves_model: "Leaves modeled network", no_ingress: "No first-hop device", too_long: "Too many hops",
};

function hopTimeline(path, rep, isReturn) {
  if (!path) return `<div class="muted">No path.</div>`;
  const src = isReturn ? rep.flow.dst : rep.flow.src;
  const dst = isReturn ? rep.flow.src : rep.flow.dst;
  const out = [`<div class="endpoint">&#9675; ${esc(src)}</div><div class="hops">`];
  path.hops.forEach((h, i) => {
    const last = i === path.hops.length - 1;
    let pol = "";
    if (h.is_firewall && !isReturn && h.out_interface) {
      const c = rep.checks.find((c) => c.device === h.device && c.in_zone === h.in_zone && c.out_zone === h.out_zone);
      if (c) pol = `<div class="pol"><span class="badge ${c.action === "allow" ? "b-ok" : "b-crit"}">${c.action.toUpperCase()}</span> rule <span class="mono">${esc(c.rule || "<default deny>")}</span></div>`;
    } else if (h.is_firewall && isReturn) {
      pol = `<div class="pol muted">Return traffic: needs the session created by the forward flow</div>`;
    }
    const color = h.is_firewall ? "#e11d48" : "#2563eb";
    const fail = last && !path.delivered && path.status !== "leaves_model" ? `<div class="pol"><span class="badge b-crit">${esc(STATUS[path.status] || path.status)}</span> ${esc(path.detail)}</div>` : "";
    out.push(`<div class="hop"><div class="rail"><div class="dot" style="background:${color}">${i + 1}</div><div class="line"></div></div>
      <div class="body">
        <div class="title"><a href="#/device/${encodeURIComponent(h.device)}">${esc(h.device)}</a> <span class="vendor">${esc(h.vendor)}</span></div>
        <div class="ifs">in ${esc(h.in_interface || "-")}${h.in_zone && h.is_firewall ? ` (${esc(h.in_zone)})` : ""} &rarr; out ${esc(h.out_interface || "-")}${h.out_zone && h.is_firewall ? ` (${esc(h.out_zone)})` : ""}</div>
        ${pol}${fail}
      </div></div>`);
  });
  out.push(`</div>`);
  if (path.delivered) out.push(`<div class="endpoint">&#9679; ${esc(dst)} <span class="badge b-ok">delivered</span></div>`);
  if (path.status === "leaves_model") out.push(`<div class="endpoint">&#8599; ${esc(dst)} <span class="badge b-info">exits modeled network</span> ${esc(path.detail)}</div>`);
  if (!path.hops.length) out.push(`<div class="err">${esc(STATUS[path.status] || path.status)}: ${esc(path.detail)}</div>`);
  return out.join("");
}

function recommendation(rep) {
  const rec = rep.recommendation;
  if (!rec || rep.ok) return "";
  if (rec.blockers.length) {
    return `<div class="panel"><h2>Automatic fix</h2>
      <p class="muted" style="margin-top:0">No firewall rule proposed. These problems cannot be solved by adding policy and need a person to fix them:</p>
      <ul>${rec.blockers.map((b) => `<li>${esc(b)}</li>`).join("")}</ul></div>`;
  }
  return `<div class="panel"><h2>Proposed change</h2>
    <div style="margin-bottom:10px">${rec.validated
      ? `<span class="badge b-ok">&#10004; Validated in twin</span> <span class="muted">With these rules applied to a copy of the model, the flow passes both ways.</span>`
      : `<span class="badge b-crit">Validation failed</span> <span class="muted">${esc((rec.after_issues || []).join(", "))}</span>`}</div>
    ${rec.rules.map((r) => `
      <h3>${esc(r.device)} &middot; ${esc(r.vendor)} &middot; ${esc(r.src_zone)} &rarr; ${esc(r.dst_zone)}</h3>
      <div class="code-wrap"><button type="button">Copy</button><pre class="code">${esc(r.rendered)}</pre></div>`).join("")}
  </div>`;
}

// ---------------------------------------------------------------- inventory & device
async function pageInventory() {
  loading();
  const devs = await api("/devices");
  if (!devs.length) {
    view().innerHTML = `<div class="page-head"><div><h1>Inventory</h1></div></div>
      <div class="panel empty">No devices in this snapshot yet. Add one by pasting or uploading its config.<br><br><a class="btn" href="#/device-new">+ Add device</a></div>`;
    return;
  }
  view().innerHTML = `
    <div class="page-head"><div><h1>Inventory</h1><div class="muted">${devs.length} devices parsed from the snapshot's saved configs.</div></div>
      <a class="btn" href="#/device-new">+ Add device</a></div>
    <div class="panel" style="padding:0">
      <table><thead><tr><th>Device</th><th>Role</th><th>Vendor</th><th>Site</th><th>Interfaces</th><th>Installed routes</th><th>Security rules</th><th>Not modeled</th></tr></thead>
      <tbody>${devs.map((d) => `<tr class="clickable" data-d="${esc(d.name)}">
        <td><b>${esc(d.name)}</b></td><td>${roleBadge(d.role)}</td><td class="vendor">${esc(d.vendor)}</td><td>${esc(d.site || "-")}</td>
        <td>${d.up_interfaces} up / ${d.interfaces}</td><td>${d.routes}</td><td>${d.role === "firewall" ? d.policies : "-"}</td>
        <td>${d.unsupported ? `<span class="badge b-warn">${d.unsupported}</span>` : `<span class="muted">0</span>`}</td></tr>`).join("")}</tbody></table>
    </div>`;
  view().querySelector("tbody").onclick = (e) => {
    const tr = e.target.closest("tr");
    if (tr) location.hash = `#/device/${encodeURIComponent(tr.dataset.d)}`;
  };
}

async function pageDevice(name, params) {
  loading();
  const d = await api(`/devices/${encodeURIComponent(name)}`);
  const tabs = [
    ["interfaces", "Interfaces", d.interfaces.length],
    ["routes", "Routing table", d.routes.length],
    ...(d.role === "firewall" ? [["policies", "Security rules", d.policies.length], ["objects", "Objects", d.addresses.length + d.services.length]] : []),
    ["notes", "Not modeled & warnings", d.unsupported.length + d.warnings.length],
    ["raw", "Raw config", null],
  ];
  let tab = params.get("tab") || "interfaces";
  view().innerHTML = `
    <div class="page-head"><div>
      <div class="muted" style="margin-bottom:4px"><a href="#/inventory">Inventory</a> / ${esc(d.name)}</div>
      <h1>${esc(d.name)} ${roleBadge(d.role)}</h1>
      <div class="muted"><span class="vendor">${esc(d.vendor)}</span> &middot; site ${esc(d.site || "-")} &middot; source <span class="mono">${esc(d.source_file)}</span>${d.role === "firewall" ? ` &middot; default action <b>${esc(d.default_action)}</b>` : ""}</div>
    </div>
    <div class="toolbar" style="margin:0">
      <a class="btn ghost" href="#/device-edit/${encodeURIComponent(d.name)}">Edit config</a>
      <button class="danger" id="rmdev">Remove</button>
    </div></div>
    <div class="panel"><div class="tabs" id="dtabs">${tabs.map(([k, l, n]) => `<button data-t="${k}">${l}${n != null ? `<span class="count">${n}</span>` : ""}</button>`).join("")}</div><div id="dbody"></div></div>`;

  const body = {
    interfaces: () => table(["Interface", "IP address", "Zone", "VRF", "Status", "Neighbor", "Description"], d.interfaces.map((i) => [
      `<span class="mono">${esc(i.name)}</span>`, `<span class="mono">${esc(i.ip || "-")}</span>`, esc(i.zone || "-"), esc(i.vrf),
      i.enabled ? `<span class="badge b-ok">up</span>` : `<span class="badge b-crit">admin down</span>`, esc(i.neighbor || "-"), esc(i.description)])),
    routes: () => (d.rib_source === "state"
      ? `<div class="panel muted" style="margin-bottom:12px;padding:10px 14px">&#9432; Routes come from the device's collected routing table
          (<span class="mono">${esc(d.routes_files.join(", "))}</span>), so OSPF/BGP/EIGRP results are included.
          ${d.routing_protocols.length ? `Routing protocols in the config: <span class="mono">${esc(d.routing_protocols.join("; "))}</span>.` : ""}</div>`
      : `<div class="panel muted" style="margin-bottom:12px;padding:10px 14px">&#9432; Routes come from the config (static routes only). Import a routing table to include dynamic routes.</div>`)
      + table(["Prefix", "Next hop", "Interface", "Protocol", "AD", "VRF", "State"], d.routes.map((r) => [
      `<span class="mono">${esc(r.prefix)}</span>`, `<span class="mono">${esc(r.next_hop || "-")}</span>`, `<span class="mono">${esc(r.interface || "-")}</span>`,
      esc(r.protocol), r.admin_distance, esc(r.vrf), r.installed ? `<span class="badge b-ok">installed</span>` : `<span class="badge b-crit">not installed</span>`]),
      d.routes.map((r) => (r.installed ? "" : "notinstalled"))),
    policies: () => table(["#", "Name", "From", "To", "Source", "Destination", "Service", "Action"], [
      ...d.policies.map((p, i) => [i + 1, `<b>${esc(p.name)}</b>${p.enabled ? "" : ` <span class="badge b-info">disabled</span>`}`,
        esc(p.src_zones.join(", ")), esc(p.dst_zones.join(", ")), esc(p.src_addrs.join(", ")), esc(p.dst_addrs.join(", ")), esc(p.services.join(", ")),
        `<span class="badge ${p.action === "allow" ? "b-ok" : "b-crit"}">${p.action}</span>`]),
      ["", `<i class="muted">implicit</i>`, "any", "any", "any", "any", "any", `<span class="badge ${d.default_action === "allow" ? "b-ok" : "b-crit"}">${d.default_action}</span>`],
    ], d.policies.map((p) => (p.enabled ? "" : "disabled"))),
    objects: () => `<h3 style="margin-top:0">Addresses</h3>` + table(["Name", "Resolves to"], d.addresses.map((a) => [`<b>${esc(a.name)}</b>`, `<span class="mono">${esc(a.prefixes.join(", ") || "(nothing)")}</span>`])) +
      `<h3>Services</h3>` + table(["Name", "Protocol / ports"], d.services.map((s) => [`<b>${esc(s.name)}</b>`, `<span class="mono">${esc(s.entries.map((e) => `${e.protocol}/${e.ports}`).join(", "))}</span>`])),
    notes: () => (d.unsupported.length + d.warnings.length === 0 ? `<div class="muted">Everything in this config is modeled.</div>` : "") +
      (d.unsupported.length ? `<h3 style="margin-top:0">Seen in config but not modeled</h3><p class="muted">The engine ignores these. Results that depend on them may be wrong.</p><ul>${d.unsupported.map((u) => `<li class="mono">${esc(u)}</li>`).join("")}</ul>` : "") +
      (d.warnings.length ? `<h3>Routing warnings</h3><ul>${d.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""),
    raw: () => `<pre class="code">${esc(d.raw)}</pre>`,
  };
  const draw = () => {
    document.querySelectorAll("#dtabs button").forEach((b) => b.classList.toggle("active", b.dataset.t === tab));
    $("#dbody").innerHTML = (body[tab] || body.interfaces)();
  };
  $("#dtabs").onclick = (e) => { const b = e.target.closest("button"); if (b) { tab = b.dataset.t; draw(); } };
  $("#rmdev").onclick = async () => {
    if (!confirm(`Remove ${d.name} from snapshot "${state.snap}"?\n\nIts config file is moved to the _removed folder, not deleted.`)) return;
    try {
      await send("DELETE", snapApi(`/devices/${encodeURIComponent(d.name)}`));
      state.topo = null;
      toast(`${d.name} removed`);
      location.hash = "#/inventory";
    } catch (e) { toast(e.message, true); }
  };
  draw();
}

// ---------------------------------------------------------------- add / edit device
async function pageDeviceForm(editName) {
  loading();
  const vendors = await send("GET", "/api/vendors");
  const existing = editName ? await api(`/devices/${encodeURIComponent(editName)}`) : null;
  view().innerHTML = `
    <div class="page-head"><div>
      <div class="muted" style="margin-bottom:4px"><a href="#/inventory">Inventory</a> / ${editName ? `<a href="#/device/${encodeURIComponent(editName)}">${esc(editName)}</a> / Edit config` : "Add device"}</div>
      <h1>${editName ? `Edit ${esc(editName)}` : "Add device"}</h1>
      <div class="muted">Paste or upload the device's running config. It is parsed and checked against the rest of the network before anything is saved.</div>
    </div></div>
    <div class="grid2">
      <div class="panel">
        <div class="query" style="margin-bottom:12px">
          <label>Vendor<select id="fvendor" ${editName ? "disabled" : ""}>${vendors.map((v) =>
            `<option value="${v.id}" ${existing?.vendor === v.id ? "selected" : ""}>${esc(v.label)} (${v.role})</option>`).join("")}</select></label>
          <label>Site<input id="fsite" value="${esc(existing?.site || "")}" placeholder="e.g. Branch 5"></label>
        </div>
        <div class="toolbar">
          <label class="btn ghost" style="cursor:pointer">Upload file<input type="file" id="ffile" hidden></label>
          ${editName ? "" : `<button type="button" class="ghost" id="fexample">Load example</button>`}
          <span class="muted" id="fstatus" style="font-size:12px"></span>
        </div>
        <textarea id="fconfig" spellcheck="false" placeholder="Paste config here...">${esc(existing?.raw || "")}</textarea>
        <div class="toolbar" style="margin-top:12px">
          <button type="button" id="fcheck">Check config</button>
          <button type="button" id="fsave" disabled>${editName ? "Save changes" : "Add to network"}</button>
          <a class="btn ghost" href="${editName ? `#/device/${encodeURIComponent(editName)}` : "#/inventory"}">Cancel</a>
        </div>
      </div>
      <div class="panel" id="fpreview"><div class="muted">Click <b>Check config</b> to see what was parsed, what it connects to, and which saved flows it changes.</div></div>
    </div>`;

  const cfg = $("#fconfig");
  let checked = null; // config text that passed the last check
  const dirty = () => { $("#fsave").disabled = checked === null || cfg.value !== checked; };
  cfg.oninput = dirty;
  $("#fvendor").onchange = () => { checked = null; dirty(); };
  $("#ffile").onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    cfg.value = await f.text();
    $("#fstatus").textContent = `Loaded ${f.name} (${f.size} bytes)`;
    checked = null; dirty();
  };
  if ($("#fexample")) $("#fexample").onclick = () => {
    cfg.value = vendors.find((v) => v.id === $("#fvendor").value).example;
    checked = null; dirty();
  };

  $("#fcheck").onclick = async () => {
    $("#fpreview").innerHTML = `<div class="muted">Checking...</div>`;
    try {
      const p = await send("POST", snapApi("/devices/preview"), { vendor: $("#fvendor").value, config: cfg.value, replacing: editName });
      checked = cfg.value;
      $("#fpreview").innerHTML = renderPreview(p, editName);
    } catch (e) {
      checked = null;
      $("#fpreview").innerHTML = `<div class="err">${esc(e.message)}</div>`;
    }
    dirty();
  };

  $("#fsave").onclick = async () => {
    $("#fsave").disabled = true;
    try {
      const body = { vendor: $("#fvendor").value, config: cfg.value, site: $("#fsite").value.trim() };
      const r = editName
        ? await send("PUT", snapApi(`/devices/${encodeURIComponent(editName)}`), body)
        : await send("POST", snapApi("/devices"), body);
      state.topo = null;
      toast(editName ? `${r.name} updated` : `${r.name} added to ${state.snap}`);
      location.hash = `#/device/${encodeURIComponent(r.name)}`;
    } catch (e) {
      toast(e.message, true);
      $("#fsave").disabled = false;
    }
  };
}

function renderPreview(p, editName) {
  const renamed = editName && p.name !== editName ? `<div class="err" style="margin-bottom:10px">Hostname changes from ${esc(editName)} to ${esc(p.name)}.</div>` : "";
  const links = p.links.length
    ? table(["Interface", "Subnet", "Connects to"], p.links.map((l) => [`<span class="mono">${esc(l.interface)}</span>`, `<span class="mono">${esc(l.subnet)}</span>`,
        l.to === "LAN" ? `<span class="muted">LAN (no other device)</span>` : `<b>${esc(l.to)}</b> <span class="mono muted">${esc(l.to_interface)}</span>`]))
    : "";
  const isolated = !p.links.some((l) => l.to !== "LAN");
  return `${renamed}
    <div class="verdict ok" style="margin-bottom:12px">&#10004; Parsed ${esc(p.name)} ${roleBadge(p.role)} <small>${p.interfaces.length} interfaces &middot; ${p.routes.length} static routes${p.role === "firewall" ? ` &middot; ${p.policies.length} rules` : ""}</small></div>
    ${isolated ? `<div class="issue"><div><span class="badge b-warn">Not connected</span></div><p>No interface shares a subnet with an existing device, so it will sit on its own on the map. Check the link addressing against its neighbor.</p></div>` : ""}
    <h3>Links</h3>${links || `<div class="muted">No addressed interfaces.</div>`}
    ${p.warnings.length ? `<h3>Warnings</h3>${p.warnings.map((w) => `<div class="issue"><p style="margin:0;color:var(--text)">${esc(w)}</p></div>`).join("")}` : ""}
    ${p.unsupported.length ? `<h3>Not modeled</h3><ul>${p.unsupported.map((u) => `<li class="mono">${esc(u)}</li>`).join("")}</ul>` : ""}
    <h3>Impact on saved flows</h3>
    ${p.impact.length
      ? table(["Flow", "Before", "After"], p.impact.map((i) => [`<b>${esc(i.name)}</b><div class="mono muted">${esc(i.flow)}</div>`,
          i.before.length ? i.before.map(issueBadge).join(" ") : `<span class="badge b-ok">works</span>`,
          i.after.length ? i.after.map(issueBadge).join(" ") : `<span class="badge b-ok">works</span>`]))
      : `<div class="muted">No saved flow changes its result.</div>`}`;
}

// ---------------------------------------------------------------- new snapshot
function pageSnapshotNew() {
  view().innerHTML = `
    <div class="page-head"><div><h1>New snapshot</h1><div class="muted">A snapshot is one network: a set of device configs plus saved flows. Start empty or copy an existing one to experiment safely.</div></div></div>
    <div class="panel" style="max-width:560px">
      <form id="snf" class="query" style="flex-direction:column;align-items:stretch">
        <label>Name<input name="name" required pattern="[a-z0-9][a-z0-9_\\-]{0,40}" placeholder="e.g. my-network" title="lowercase letters, digits, - and _"></label>
        <label>Description<input name="description" placeholder="optional"></label>
        <label>Start from<select name="copy_from"><option value="">Empty network</option>${state.snaps.map((s) =>
          `<option value="${esc(s.name)}">Copy of ${esc(s.name)} (${s.devices} devices)</option>`).join("")}</select></label>
        <div><button>Create snapshot</button></div>
      </form>
    </div>`;
  $("#snf").onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      const r = await send("POST", "/api/snapshots", { name: f.get("name"), description: f.get("description"), copy_from: f.get("copy_from") || null });
      await loadSnapshots(r.name);
      toast(`Snapshot ${r.name} created`);
      location.hash = "#/inventory";
    } catch (err) { toast(err.message, true); }
  };
}

function table(head, rows, rowCls = []) {
  return `<div style="overflow-x:auto"><table><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${
    rows.map((r, i) => `<tr class="${rowCls[i] || ""}">${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")
  }</tbody></table></div>`;
}

// ---------------------------------------------------------------- verification
async function pageVerify() {
  loading("Running checks...");
  const c = await api("/checks");
  const bySev = (s) => c.findings.filter((f) => f.severity === s).length;
  const real = c.flows.filter((f) => f.observed);
  const realTile = real.length
    ? `<div class="stat"><b style="color:${real.every((f) => f.agrees) ? "var(--ok)" : "var(--crit)"}">${real.filter((f) => f.agrees).length} / ${real.length}</b><span>Match real traffic tests</span></div>`
    : "";
  const obsBadge = (f) => !f.observed ? `<span class="muted">-</span>`
    : `<span class="badge ${f.observed === "allowed" ? "b-ok" : "b-info"}">${f.observed}</span> ${f.agrees ? `<span class="badge b-ok" title="NetTwin predicted the same">&#10004; twin agrees</span>` : `<span class="badge b-crit" title="NetTwin predicted ${f.predicted}">&#10006; twin says ${f.predicted}</span>`}`;
  view().innerHTML = `
    <div class="page-head"><div><h1>Verification</h1><div class="muted">Saved flows re-run against this snapshot, plus network-wide findings.${real.length ? " Flows marked <b>observed</b> were really sent through the lab devices; the twin's prediction is scored against them." : ""}</div></div></div>
    <div class="stats">
      ${realTile}
      <div class="stat"><b>${c.flows.length}</b><span>Saved flows</span></div>
      <div class="stat"><b style="color:var(--ok)">${c.flows.filter((f) => f.ok).length}</b><span>Working end to end</span></div>
      <div class="stat"><b style="color:var(--crit)">${c.flows.filter((f) => !f.ok).length}</b><span>With issues</span></div>
      <div class="stat"><b>${c.flows.filter((f) => f.matches).length} / ${c.flows.length}</b><span>Match baseline</span></div>
      <div class="stat"><b style="color:var(--crit)">${bySev("high")}</b><span>High findings</span></div>
    </div>
    <div class="panel" style="padding:0;margin-bottom:16px">
      <table><thead><tr><th>Flow</th><th>Traffic</th><th>Result</th>${real.length ? "<th>Observed in lab</th>" : ""}<th>Baseline</th><th></th></tr></thead><tbody>
      ${c.flows.map((f) => {
        const p = new URLSearchParams({ src: f.src, dst: f.dst, protocol: f.protocol });
        if (f.port != null) p.set("port", f.port);
        return `<tr><td><b>${esc(f.name)}</b></td><td class="mono">${esc(f.flow)}</td>
          <td>${f.ok ? `<span class="badge b-ok">works</span>` : f.issues.map(issueBadge).join(" ")}</td>
          ${real.length ? `<td>${obsBadge(f)}</td>` : ""}
          <td>${f.expect == null ? `<span class="muted">-</span>` : f.matches ? `<span class="badge b-ok">matches</span>` : `<span class="badge b-crit">changed</span>`}</td>
          <td><a href="#/path?${p}">Trace &rarr;</a></td></tr>`;
      }).join("")}
      </tbody></table>
    </div>
    <div class="panel" style="padding:0">
      <div style="padding:14px 16px 0"><h2>Network findings</h2></div>
      <table><thead><tr><th>Severity</th><th>Device</th><th>Category</th><th>Detail</th></tr></thead><tbody>
      ${c.findings.map((f) => `<tr><td>${sevBadge(f.severity)}</td><td><a href="#/device/${encodeURIComponent(f.device)}">${esc(f.device)}</a></td><td>${esc(f.category)}</td><td>${esc(f.message)}</td></tr>`).join("")}
      </tbody></table>
    </div>`;
}

// ---------------------------------------------------------------- search
async function pageSearch(params) {
  const q = params.get("q") || "";
  $("#gq").value = q;
  view().innerHTML = `
    <div class="page-head"><div><h1>Search</h1><div class="muted">An IP shows who owns it, which subnet holds it, which objects match it, and every device's route to it.</div></div></div>
    <form class="query" id="sq"><label>Query<input name="q" value="${esc(q)}" style="width:320px" placeholder="10.3.30.10 or FW1 or users"></label><button>Search</button></form>
    <div id="sres"></div>`;
  $("#sq").onsubmit = (e) => { e.preventDefault(); location.hash = `#/search?q=${encodeURIComponent(new FormData(e.target).get("q"))}`; };
  if (!q) { $("#sres").innerHTML = `<div class="panel empty">Type an IP address, device, interface, object or rule name.</div>`; return; }
  const r = await api(`/search?q=${encodeURIComponent(q)}`);
  if (!r.hits.length) { $("#sres").innerHTML = `<div class="panel empty">No matches for "${esc(q)}".</div>`; return; }
  $("#sres").innerHTML = `<div class="panel" style="padding:0">` + table(["Type", "Device", "Detail"],
    r.hits.map((h) => [`<span class="badge b-info">${esc(h.type)}</span>`, `<a href="#/device/${encodeURIComponent(h.device)}">${esc(h.device)}</a>`, `<span class="mono">${esc(h.detail)}</span>`])) + `</div>`;
}

// ---------------------------------------------------------------- router & boot
// Renders are async; two overlapping ones (e.g. snapshot change + hash change) would write into
// each other's DOM. Run one at a time and re-run once at the end if another was requested.
let routing = false, rerouteRequested = false;
async function route() {
  if (routing) { rerouteRequested = true; return; }
  routing = true;
  try {
    do { rerouteRequested = false; await renderPage(); } while (rerouteRequested);
  } finally {
    routing = false;
  }
}

async function renderPage() {
  const { page, arg, params } = parseHash();
  const navFor = page.startsWith("device") ? "inventory" : page;
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === navFor));
  if (state.cy) { state.cy.destroy(); state.cy = null; }
  try {
    if (page === "path") await pagePath(params);
    else if (page === "inventory") await pageInventory();
    else if (page === "device") await pageDevice(arg, params);
    else if (page === "device-new") await pageDeviceForm(null);
    else if (page === "device-edit") await pageDeviceForm(arg);
    else if (page === "snapshot-new") pageSnapshotNew();
    else if (page === "verify") await pageVerify();
    else if (page === "search") await pageSearch(params);
    else await pageMap();
  } catch (e) {
    fail(e);
  }
}

const snapMeta = () => { $("#snapmeta").textContent = state.snaps.find((s) => s.name === state.snap)?.description || ""; };

async function loadSnapshots(select) {
  state.snaps = await send("GET", "/api/snapshots");
  const want = select || store("nt.snap");
  state.snap = state.snaps.some((s) => s.name === want) ? want : state.snaps[0]?.name;
  store("nt.snap", state.snap);
  state.topo = null;
  $("#snapshot").innerHTML = state.snaps.map((s) =>
    `<option value="${esc(s.name)}" ${s.name === state.snap ? "selected" : ""}>${esc(s.name)} (${s.devices} devices)</option>`).join("");
  snapMeta();
}

async function boot() {
  await loadSnapshots();
  const sel = $("#snapshot");
  sel.onchange = () => {
    state.snap = sel.value; state.topo = null; store("nt.snap", state.snap); snapMeta();
    // Device names differ per snapshot, so a device page can't carry over.
    if (parseHash().page.startsWith("device")) location.hash = "#/inventory"; else route();
  };
  // Device counts in the selector go stale after edits; refresh them on every navigation.
  window.addEventListener("hashchange", () => loadSnapshots(state.snap).catch(() => {}));
  $("#globalsearch").onsubmit = (e) => { e.preventDefault(); location.hash = `#/search?q=${encodeURIComponent($("#gq").value)}`; };
  window.addEventListener("hashchange", route);
  route();
}

boot().catch(fail);
