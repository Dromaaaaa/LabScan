"use strict";

const state = {
  tools: [],
  selected: { kind: null, id: null },   // { kind: "scan" | "pipeline", id }
  pollTimer: null,
  openOnly: true,
};

const $ = (sel) => document.querySelector(sel);

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `Erreur HTTP ${res.status}`);
  return body;
}

function fmtDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

function duration(a, b) {
  if (!a || !b) return "";
  const s = Math.max(0, (new Date(b) - new Date(a)) / 1000);
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

const STATUS_LABEL = {
  queued: "en file", running: "en cours", done: "terminé",
  error: "erreur", interrupted: "interrompu",
};

/* ---------- Formulaire ---------- */

function fillPresets() {
  const tool = state.tools.find((t) => t.name === $("#tool").value);
  $("#preset").innerHTML = Object.entries(tool?.presets ?? {})
    .map(([k, label]) => `<option value="${esc(k)}">${esc(label)}</option>`)
    .join("");
  $("#ports-field").style.display = tool?.name === "nmap" ? "" : "none";
}

async function loadTools() {
  state.tools = await api("/api/tools");
  $("#tool").innerHTML = state.tools
    .map((t) => `<option value="${esc(t.name)}" ${t.available ? "" : "disabled"}>
      ${esc(t.name)}${t.available ? "" : " (non installé)"}</option>`)
    .join("");
  const firstAvailable = state.tools.find((t) => t.available);
  if (firstAvailable) $("#tool").value = firstAvailable.name;
  fillPresets();
}

async function loadScope() {
  const scope = await api("/api/scope");
  const items = [...scope.cidrs, ...scope.hosts];
  $("#scope").innerHTML = `<span>scope</span>` +
    items.map((s) => `<span class="chip">${esc(s)}</span>`).join("");
}

async function submitScan(ev) {
  ev.preventDefault();
  const msg = $("#form-msg");
  const btn = $("#launch");
  msg.className = "form-msg";
  msg.textContent = "";
  btn.disabled = true;

  try {
    const payload = {
      tool: $("#tool").value,
      preset: $("#preset").value,
      target: $("#target").value.trim(),
      ports: $("#ports").value.trim() || null,
    };
    const { id } = await api("/api/scans", { method: "POST", body: JSON.stringify(payload) });
    msg.className = "form-msg ok";
    msg.textContent = `Scan #${id} lancé`;
    await loadHistory();
    selectItem("scan", id);
  } catch (err) {
    msg.className = "form-msg error";
    msg.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
}

async function submitChain() {
  const msg = $("#form-msg");
  const btn = $("#chain");
  msg.className = "form-msg";
  msg.textContent = "";
  btn.disabled = true;
  try {
    const target = $("#target").value.trim();
    if (!target) throw new Error("Renseigne une cible");
    const { id } = await api("/api/pipelines", { method: "POST", body: JSON.stringify({ target }) });
    msg.className = "form-msg ok";
    msg.textContent = `Chaîne #${id} lancée`;
    await loadHistory();
    selectItem("pipeline", id);
  } catch (err) {
    msg.className = "form-msg error";
    msg.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
}

/* ---------- Historique ---------- */

function isActive(kind, id) {
  return state.selected.kind === kind && state.selected.id === id;
}

async function loadHistory() {
  const [scans, pipelines] = await Promise.all([api("/api/scans"), api("/api/pipelines")]);
  const items = [
    ...pipelines.map((p) => ({ kind: "pipeline", ...p })),
    ...scans.map((s) => ({ kind: "scan", ...s })),
  ].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));

  $("#history").innerHTML = items.length
    ? items.map((it) => it.kind === "pipeline" ? `
      <li data-kind="pipeline" data-id="${it.id}" class="st-${esc(it.status)} ${isActive("pipeline", it.id) ? "active" : ""}">
        <span class="dot"></span>
        <span class="h-target">${esc(it.target)}
          <div class="h-meta">chaîne · ${it.steps} étapes · ${fmtDate(it.created_at)}</div>
        </span>
        <span class="chip chip-chain">⛓ #${it.id}</span>
      </li>` : `
      <li data-kind="scan" data-id="${it.id}" class="st-${esc(it.status)} ${isActive("scan", it.id) ? "active" : ""}">
        <span class="dot"></span>
        <span class="h-target">${esc(it.target)}
          <div class="h-meta">${esc(it.tool)} · ${esc(it.preset)} · ${fmtDate(it.created_at)}</div>
        </span>
        <span class="chip">#${it.id}</span>
      </li>`).join("")
    : `<li class="h-meta" style="cursor:default">Aucun scan pour l'instant</li>`;
  return items;
}

/* ---------- Rendu des résultats ---------- */

function renderNmap(parsed) {
  const sum = parsed.summary ?? {};
  const hosts = (parsed.hosts ?? []).filter((h) => h.status === "up" || h.ports.length);

  const stats = `
    <div class="stats">
      <div class="stat"><div class="stat-value">${sum.hosts_up ?? 0}/${sum.hosts_total ?? 0}</div><div class="stat-label">hôtes up</div></div>
      <div class="stat"><div class="stat-value">${sum.open_ports ?? 0}</div><div class="stat-label">ports ouverts</div></div>
      <div class="stat"><div class="stat-value">${sum.elapsed ? Number(sum.elapsed).toFixed(1) + " s" : "n/a"}</div><div class="stat-label">durée nmap</div></div>
    </div>`;

  const toolbar = `
    <label class="toolbar">
      <input type="checkbox" id="open-only" ${state.openOnly ? "checked" : ""}>
      Afficher uniquement les ports ouverts
    </label>`;

  if (!hosts.length) {
    return stats + `<div class="card"><div class="card-note">Aucun hôte actif trouvé.</div></div>`;
  }

  const cards = hosts.map((h) => {
    const ports = h.ports.filter((p) => !state.openOnly || p.state === "open");
    const meta = [
      ...h.hostnames.map((n) => `<span class="chip">${esc(n)}</span>`),
      h.mac ? `<span class="chip">${esc(h.mac)}${h.vendor ? " · " + esc(h.vendor) : ""}</span>` : "",
      ...h.os.slice(0, 1).map((o) => `<span class="chip">${esc(o.name)} (${o.accuracy}%)</span>`),
    ].join("");

    const rows = ports.map((p) => {
      const version = [p.product, p.version, p.extrainfo].filter(Boolean).join(" ");
      const scripts = p.scripts.map((s) => `
        <details class="script"><summary>${esc(s.id)}</summary><pre>${esc(s.output)}</pre></details>`).join("");
      return `
        <tr>
          <td>${p.port}/${esc(p.protocol)}</td>
          <td class="state state-${esc(p.state)}">${esc(p.state)}</td>
          <td>${esc(p.service ?? "")}</td>
          <td class="version">${esc(version)}${scripts}</td>
        </tr>`;
    }).join("");

    const hostScripts = h.host_scripts.map((s) => `
      <details class="script" style="padding:0 14px 10px"><summary>${esc(s.id)}</summary><pre>${esc(s.output)}</pre></details>`).join("");

    const body = ports.length
      ? `<table><thead><tr><th>Port</th><th>État</th><th>Service</th><th>Version / scripts</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="card-note">${h.ports.length ? "Aucun port ouvert (décocher le filtre pour tout voir)." : "Hôte actif, pas de scan de ports dans ce profil."}</div>`;

    return `
      <article class="card">
        <header class="card-head">
          <span class="card-title">${esc(h.ipv4 || h.ipv6 || "?")}</span>
          <span class="card-meta">${meta}</span>
        </header>
        <div class="card-body">${body}${hostScripts}</div>
      </article>`;
  }).join("");

  return stats + toolbar + cards;
}

function renderWhatweb(parsed) {
  const sites = parsed.sites ?? [];
  if (!sites.length) return `<div class="card"><div class="card-note">Aucune technologie identifiée.</div></div>`;
  return sites.map((s) => `
    <article class="card">
      <header class="card-head">
        <span class="card-title">${esc(s.url)}</span>
        <span class="card-meta"><span class="chip">HTTP ${esc(s.http_status ?? "?")}</span></span>
      </header>
      <div class="tech-list">
        ${s.technologies.map((t) => `
          <span class="tech">${esc(t.name)}${t.details.length ? ` <span class="tech-detail">${esc(t.details.join(", "))}</span>` : ""}</span>`).join("")}
      </div>
    </article>`).join("");
}

function renderGobuster(parsed) {
  const found = parsed.found ?? [];
  if (!found.length) return `<div class="card"><div class="card-note">Aucun chemin trouvé avec cette liste.</div></div>`;
  const rows = found.map((f) => `
    <tr>
      <td>${esc(f.path)}</td>
      <td class="state state-${f.status < 400 ? "open" : "filtered"}">${f.status}</td>
      <td class="version">${f.size != null ? f.size + " o" : ""}</td>
      <td class="version">${esc(f.redirect ?? "")}</td>
    </tr>`).join("");
  return `
    <div class="stats"><div class="stat"><div class="stat-value">${found.length}</div><div class="stat-label">chemins trouvés</div></div></div>
    <article class="card">
      <header class="card-head"><span class="card-title">Contenus découverts</span></header>
      <table><thead><tr><th>Chemin</th><th>Statut</th><th>Taille</th><th>Redirige vers</th></tr></thead><tbody>${rows}</tbody></table>
    </article>`;
}

function renderNikto(parsed) {
  const findings = parsed.findings ?? [];
  const head = parsed.server
    ? `<div class="stats"><div class="stat"><div class="stat-value" style="font-size:13px">${esc(parsed.server)}</div><div class="stat-label">serveur</div></div>
       <div class="stat"><div class="stat-value">${findings.length}</div><div class="stat-label">observations</div></div></div>`
    : "";
  if (!findings.length) return head + `<div class="card"><div class="card-note">Aucune observation remontée.</div></div>`;
  return head + `
    <article class="card">
      <header class="card-head"><span class="card-title">Observations nikto</span></header>
      <div class="card-body">${findings.map((f) => `<div class="finding">${esc(f)}</div>`).join("")}</div>
    </article>`;
}

function renderNuclei(parsed) {
  const findings = parsed.findings ?? [];
  const sev = parsed.by_severity ?? {};
  const order = ["critical", "high", "medium", "low", "info"];
  const stats = `<div class="stats">${order.filter((s) => sev[s]).map((s) => `
    <div class="stat"><div class="stat-value sev-${s}">${sev[s]}</div><div class="stat-label">${s}</div></div>`).join("")
    || `<div class="stat"><div class="stat-value">0</div><div class="stat-label">détection</div></div>`}</div>`;
  if (!findings.length) return stats + `<div class="card"><div class="card-note">Aucune détection.</div></div>`;
  const rows = findings.map((f) => `
    <tr>
      <td><span class="sev-badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td>${esc(f.name ?? f.template)}<div class="h-meta">${esc(f.template)}</div></td>
      <td class="version">${esc(f.matched_at ?? "")}</td>
    </tr>`).join("");
  return stats + `
    <article class="card">
      <header class="card-head"><span class="card-title">Détections nuclei</span></header>
      <table><thead><tr><th>Sévérité</th><th>Template</th><th>Cible</th></tr></thead><tbody>${rows}</tbody></table>
    </article>`;
}

function renderHarvester(parsed) {
  const emails = parsed.emails ?? [];
  const hosts = parsed.hosts ?? [];
  const block = (title, items) => items.length ? `
    <article class="card">
      <header class="card-head"><span class="card-title">${title}</span><span class="chip">${items.length}</span></header>
      <div class="card-body">${items.map((i) => `<div class="finding">${esc(i)}</div>`).join("")}</div>
    </article>` : "";
  if (!emails.length && !hosts.length) return `<div class="card"><div class="card-note">Aucun résultat (sources publiques épuisées ou réseau indisponible).</div></div>`;
  return block("Emails", emails) + block("Sous-domaines / hôtes", hosts);
}

const RENDERERS = {
  nmap: renderNmap,
  whatweb: renderWhatweb,
  gobuster: renderGobuster,
  nikto: renderNikto,
  nuclei: renderNuclei,
  theharvester: renderHarvester,
};

function renderScan(scan) {
  const r = scan.result;
  const running = scan.status === "queued" || scan.status === "running";

  let body = "";
  if (running) {
    body = `<div class="running-box">Scan ${STATUS_LABEL[scan.status]}…</div>`;
  } else if (r) {
    const renderer = RENDERERS[scan.tool];
    body =
      (r.error ? `<div class="alert">${esc(r.error)}</div>` : "") +
      `<div class="cmd">${esc(r.command.join(" "))}</div>` +
      (renderer ? renderer(r.parsed ?? {}) : `<pre>${esc(JSON.stringify(r.parsed, null, 2))}</pre>`) +
      `<details class="raw"><summary>Sortie brute</summary><pre>${esc(r.raw_output)}</pre></details>`;
  } else {
    body = `<div class="alert">Scan ${esc(STATUS_LABEL[scan.status] ?? scan.status)}, aucun résultat enregistré.</div>`;
  }

  $("#content").innerHTML = `
    <div class="result-head">
      <div>
        <h1 class="result-title">${esc(scan.target)}</h1>
        <div class="result-sub">
          #${scan.id} · ${esc(scan.tool)} · ${esc(scan.preset)} ·
          ${esc(STATUS_LABEL[scan.status] ?? scan.status)} · ${fmtDate(scan.created_at)}
          ${scan.finished_at && r ? " · " + duration(r.started_at, r.finished_at) : ""}
        </div>
      </div>
      <div class="actions">
        ${!running ? `<a class="btn-ghost" href="/api/scans/${scan.id}/pdf" target="_blank" rel="noopener">PDF</a>` : ""}
        ${!running ? `<a class="btn-ghost" href="/api/scans/${scan.id}/export">JSON</a>` : ""}
        <button class="btn-ghost" id="rescan">Relancer</button>
        ${!running ? `<button class="btn-ghost" id="delete">Supprimer</button>` : ""}
      </div>
    </div>
    ${body}`;

  $("#open-only")?.addEventListener("change", (e) => {
    state.openOnly = e.target.checked;
    renderScan(scan);
  });
  $("#delete")?.addEventListener("click", () => deleteScan(scan.id));
  $("#rescan").addEventListener("click", () => {
    $("#tool").value = scan.tool;
    fillPresets();
    $("#preset").value = scan.preset;
    $("#target").value = scan.target;
    $("#ports").value = scan.options?.ports ?? "";
    $("#scan-form").requestSubmit();
  });
}

/* ---------- Chaînes ---------- */

const STEP_LABEL = { nmap: "Découverte des services (nmap)" };

function renderPipeline(pipeline) {
  const scans = pipeline.scans ?? [];
  const running = pipeline.status === "queued" || pipeline.status === "running";
  const done = scans.filter((s) => s.status === "done" || s.status === "error").length;

  const sections = scans.map((s) => {
    const r = s.result;
    const renderer = RENDERERS[s.tool];
    const inner = s.status === "queued" || s.status === "running"
      ? `<div class="running-box">${esc(STATUS_LABEL[s.status])}…</div>`
      : r
        ? (r.error ? `<div class="alert">${esc(r.error)}</div>` : "") +
          `<div class="cmd">${esc(r.command.join(" "))}</div>` +
          (renderer ? renderer(r.parsed ?? {}) : "")
        : `<div class="card-note">Aucun résultat.</div>`;
    return `
      <section class="step">
        <h2 class="step-title"><span class="chip">${esc(s.tool)}</span> ${esc(s.target)}</h2>
        ${inner}
      </section>`;
  }).join("");

  $("#content").innerHTML = `
    <div class="result-head">
      <div>
        <h1 class="result-title">⛓ ${esc(pipeline.target)}</h1>
        <div class="result-sub">
          Chaîne #${pipeline.id} · ${esc(STATUS_LABEL[pipeline.status] ?? pipeline.status)} ·
          ${done}/${scans.length} étapes · ${fmtDate(pipeline.created_at)}
        </div>
      </div>
      <div class="actions">
        ${!running ? `<a class="btn-ghost" href="/api/pipelines/${pipeline.id}/pdf" target="_blank" rel="noopener">PDF</a>` : ""}
        <button class="btn-ghost" id="rechain">Relancer</button>
        ${!running ? `<button class="btn-ghost" id="delete-chain">Supprimer</button>` : ""}
      </div>
    </div>
    ${running && !scans.length ? `<div class="running-box">Démarrage de la chaîne…</div>` : ""}
    ${sections}`;

  $("#delete-chain")?.addEventListener("click", () => deletePipeline(pipeline.id));
  $("#rechain").addEventListener("click", () => {
    $("#target").value = pipeline.target;
    submitChain();
  });
}

/* ---------- Sélection et polling ---------- */

async function selectItem(kind, id) {
  clearTimeout(state.pollTimer);
  state.selected = { kind, id };
  document.querySelectorAll("#history li").forEach((li) =>
    li.classList.toggle("active", li.dataset.kind === kind && Number(li.dataset.id) === id));

  try {
    const path = kind === "pipeline" ? `/api/pipelines/${id}` : `/api/scans/${id}`;
    const item = await api(path);
    if (!isActive(kind, id)) return;
    (kind === "pipeline" ? renderPipeline : renderScan)(item);
    if (item.status === "queued" || item.status === "running") {
      state.pollTimer = setTimeout(async () => {
        await loadHistory();
        selectItem(kind, id);
      }, 2000);
    }
  } catch (err) {
    $("#content").innerHTML = `<div class="alert">${esc(err.message)}</div>`;
  }
}

async function deleteScan(id) {
  await api(`/api/scans/${id}`, { method: "DELETE" });
  afterDelete("Scan supprimé");
}

async function deletePipeline(id) {
  await api(`/api/pipelines/${id}`, { method: "DELETE" });
  afterDelete("Chaîne supprimée");
}

function afterDelete(label) {
  state.selected = { kind: null, id: null };
  $("#content").innerHTML = `<div class="empty"><p class="empty-title">${label}</p></div>`;
  loadHistory();
}

/* ---------- Démarrage ---------- */

$("#tool").addEventListener("change", fillPresets);
$("#scan-form").addEventListener("submit", submitScan);
$("#chain").addEventListener("click", submitChain);
$("#history").addEventListener("click", (e) => {
  const li = e.target.closest("li[data-id]");
  if (li) selectItem(li.dataset.kind, Number(li.dataset.id));
});

Promise.all([loadTools(), loadScope(), loadHistory()]).catch((err) => {
  $("#content").innerHTML = `<div class="alert">API injoignable : ${esc(err.message)}</div>`;
});
