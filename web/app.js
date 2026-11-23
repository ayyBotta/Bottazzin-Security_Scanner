"use strict";

const LEVEL_COLORS = {
  BASSO: "--lvl-basso", MODERATO: "--lvl-moderato", ELEVATO: "--lvl-elevato",
  ALTO: "--lvl-alto", CRITICO: "--lvl-critico",
};
const SEVERITY_COLORS = {
  CRITICA: "--sev-critica", ALTA: "--sev-alta", MEDIA: "--sev-media",
  BASSA: "--sev-bassa", INFO: "--sev-info",
};
const VERDICT_COLORS = {
  UFFICIALE: "--lvl-basso", LEGITTIMO: "--lvl-basso", "NON SOSPETTO": "--lvl-moderato",
  SOSPETTO: "--lvl-elevato", LOOKALIKE: "--lvl-critico",
};
const SEVERITY_ORDER =["CRITICA", "ALTA", "MEDIA", "BASSA", "INFO"];
const HISTORY_KEY = "secscan.history";
const GAUGE_LENGTH = 2 * Math.PI * 52;

const $ = (id) => document.getElementById(id);
const cssVar = (name) => `var(${name})`;

let lastResult = null;
let timer = null;

// ---------------------------------------------------------------- helpers
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "style") Object.assign(node.style, value);
    else if (key.startsWith("--")) node.style.setProperty(key, value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function scoreColor(level) {
  return cssVar(LEVEL_COLORS[level] || "--accent");
}

function fmt(n) {
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}

// ---------------------------------------------------------------- stato UI
function showOnly(section) {
  for (const id of ["loading", "error", "results"]) $(id).hidden = id !== section;
}

function startLoading(domain) {
  $("loading-domain").textContent = domain;
  $("elapsed").textContent = "0";
  const started = Date.now();
  timer = setInterval(() => {
    $("elapsed").textContent = Math.floor((Date.now() - started) / 1000);
  }, 500);
  $("scan-btn").disabled = true;
  $("lookalike").hidden = true;
  showOnly("loading");
}

function stopLoading() {
  clearInterval(timer);
  $("scan-btn").disabled = false;
}

function showError(message) {
  $("error").textContent = message;
  showOnly("error");
}

// ---------------------------------------------------------------- scansione
async function scan(domain) {
  domain = domain.trim();
  if (!domain) return;
  startLoading(domain);
  try {
    const resp = await fetch(`/api/scan?domain=${encodeURIComponent(domain)}`);
    const data = await resp.json().catch(() => ({ error: "Risposta non valida dal server." }));
    if (!resp.ok || data.error) {
      showError(data.error || `Errore ${resp.status}`);
      if (data.lookalike) renderLookalike(data.lookalike);
      return;
    }
    lastResult = data;
    render(data);
    saveHistory(data);
  } catch (e) {
    showError("Impossibile contattare il server. Assicurati che app.py sia in esecuzione.");
  } finally {
    stopLoading();
  }
}

// ---------------------------------------------------------------- render
function render(data) {
  showOnly("results");
  const color = scoreColor(data.risk_level);

  // punteggio
  $("result-domain").textContent = data.domain;
  $("gauge").style.setProperty("--gauge-color", color);
  const gauge = $("gauge-value");
  gauge.style.strokeDashoffset = GAUGE_LENGTH;
  requestAnimationFrame(() => {
    gauge.style.strokeDashoffset = GAUGE_LENGTH * (1 - data.score / 100);
  });
  animateNumber($("score"), data.score);

  const level = $("level");
  level.textContent = data.risk_level;
  level.style.setProperty("--badge-color", color);
  $("level-desc").textContent = data.risk_description;

  $("caps").replaceChildren(...data.caps.map((c) =>
    el("li", {}, `Punteggio limitato a ${c.max_score} per un problema critico: ${c.reason}`)));

  // conteggio per gravita'
  const counts = {};
  for (const f of data.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  $("severity-counts").replaceChildren(...SEVERITY_ORDER.filter((s) => counts[s]).map((s) =>
    el("span", { class: "chip", "--chip-color": cssVar(SEVERITY_COLORS[s]) }, `${counts[s]} ${s.toLowerCase()}`)));

  renderRedirect(data);
  renderBotBlock(data);
  renderChains(data.chains || {});
  renderCategories(data.categories);
  renderFindings(data.findings);
  renderLists(data.passed, data.skipped);
  if (data.lookalike) renderLookalike(data.lookalike);
  $(data.lookalike ? "lookalike" : "results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderBotBlock(data) {
  const card = $("botblock-card");
  card.hidden = !data.bot_block;
  if (!data.bot_block) return;
  $("botblock-text").replaceChildren(
    "Al posto della homepage di ", el("strong", {}, data.domain), " e' arrivata una pagina di blocco o di errore (",
    el("strong", {}, data.bot_block), ").");
}

function renderChains(chains) {
  const entries = Object.entries(chains).filter(([, chain]) => chain.length > 1);
  $("chains-card").hidden = entries.length === 0;
  $("chains").replaceChildren(...entries.map(([label, chain]) =>
    el("p", { class: "chain" }, el("strong", {}, `${label}: `),
      ...chain.flatMap((hop, i) => [i ? " → " : "", el("code", {}, hop.url), ` → ${hop.status}`]))));
}

function renderRedirect(data) {
  const card = $("redirect-card");
  card.hidden = !data.redirect_target;
  if (!data.redirect_target) return;
  $("redirect-text").replaceChildren(
    el("strong", {}, data.domain), " non mostra contenuti propri: rimanda a ",
    el("strong", {}, data.redirect_target), ".");

  const dest = data.destination;
  if (!dest) {
    $("destination").replaceChildren(el("span", { class: "muted" }, "Destinazione non raggiungibile: nessun punteggio."));
    return;
  }
  const open = el("button", { type: "button" }, "Apri l'analisi completa della destinazione");
  open.addEventListener("click", () => { $("domain").value = dest.domain; scan(dest.domain); });
  $("destination").replaceChildren(
    el("div", { class: "destination__score", "--dest-color": scoreColor(dest.risk_level) },
      dest.score, el("small", {}, "/100")),
    el("div", { class: "destination__body" },
      el("strong", {}, `Destinazione: ${dest.domain}`),
      el("div", { class: "muted" }, `Rischio ${dest.risk_level}`, dest.verdict ? ` - ${dest.verdict}` : ""),
      dest.unreliable ? el("div", { class: "muted" }, "Risultato non affidabile: richiesta bloccata") : null,
      dest.tls_legacy ? el("div", { class: "muted small" }, `TLS 1.0/1.1: ${dest.tls_legacy}`) : null,
      dest.top_findings.length
        ? el("ul", {}, ...dest.top_findings.map((f) => el("li", {}, `[${f.severity}] ${f.name}: ${f.detected}`)))
        : null),
    open);
}

function formatAge(la) {
  if (la.age_days == null) return "non disponibile";
  const age = la.age_days >= 365 ? `${Math.floor(la.age_days / 365)} anni` : `${la.age_days} giorni`;
  return `${age} (registrato il ${la.created}, fonte ${la.age_source})`;
}

function renderLookalike(la) {
  const card = $("lookalike");
  card.hidden = false;
  card.style.setProperty("--verdict-color", cssVar(VERDICT_COLORS[la.verdict] || "--accent"));
  $("la-verdict").textContent = la.verdict;
  $("la-description").textContent = la.description;

  const domainCell = $("la-domain");
  domainCell.replaceChildren(la.display);
  if (la.display !== la.domain) domainCell.append(el("span", { class: "puny" }, `punycode: ${la.domain}`));

  const showTarget = la.target && la.verdict !== "UFFICIALE";
  $("la-target-label").hidden = $("la-target").hidden = !showTarget;
  if (showTarget) {
    $("la-target-label").textContent =
      { LEGITTIMO: "Collegato a", "NON SOSPETTO": "Somiglia a" }[la.verdict] || "Imita";
    const rank = la.target_rank ? `, n. ${la.target_rank.toLocaleString("it-IT")} tra i siti piu' visitati` : "";
    const brand = la.brand && la.brand !== la.target ? la.brand : "";
    $("la-target").textContent = `${la.target}${brand || rank ? ` (${[brand, rank.slice(2)].filter(Boolean).join(", ")})` : ""}`;
  }
  $("la-technique").previousElementSibling.hidden = $("la-technique").hidden = !la.technique;
  $("la-technique").textContent = la.technique || "";
  $("la-age").textContent = formatAge(la);
  $("la-rank").textContent = la.tranco_rank
    ? `n. ${la.tranco_rank.toLocaleString("it-IT")} tra i siti piu' visitati al mondo`
    : "fuori dai primi 100.000 siti piu' visitati";

  const claim = la.page_claim;
  $("la-claim-label").hidden = $("la-claim").hidden = !claim;
  if (claim) {
    const labels = {
      ufficiale: ["sito ufficiale confermato", "good"],
      coerente: ["coerente con il dominio", "good"],
      non_corrispondente: [`ma il sito ufficiale e' ${claim.official_domains.slice(0, 3).join(", ")}`, "bad"],
      sconosciuto: [claim.lookup_failed ? "Wikidata non raggiungibile" : "marchio non trovato", ""],
    };
    const [text, tone] = labels[claim.status] || [claim.status, ""];
    const verified = claim.verified_by ? ` (fonte: ${claim.verified_by})` : "";
    $("la-claim").replaceChildren(
      `"${claim.name}" `, el("span", { class: "muted small" }, `da ${claim.source} `), "- ",
      el("span", { class: `claim-status${tone ? ` claim-status--${tone}` : ""}` }, text),
      claim.has_password ? " - la pagina chiede una password" : "",
      verified);
  }
  $("la-sources").replaceChildren(...(la.sources || []).map((s) => el("li", {}, s)));

  $("la-chars-wrap").hidden = la.confusables.length === 0;
  $("la-chars").replaceChildren(...la.confusables.map((c) =>
    el("tr", {},
      el("td", { class: "glyph" }, c.char),
      el("td", {}, `'${c.looks_like}'`),
      el("td", {}, c.codepoint),
      el("td", {}, c.name.toLowerCase()))));

  $("la-reasons").replaceChildren(...la.reasons.map((r) => el("li", {}, r)));
}

function animateNumber(node, target) {
  const start = performance.now();
  const step = (now) => {
    const t = Math.min((now - start) / 900, 1);
    node.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function categoryColor(percent) {
  if (percent >= 85) return cssVar("--lvl-basso");
  if (percent >= 65) return cssVar("--lvl-moderato");
  if (percent >= 45) return cssVar("--lvl-elevato");
  if (percent >= 25) return cssVar("--lvl-alto");
  return cssVar("--lvl-critico");
}

function renderCategories(categories) {
  const rows = categories.map((c) => {
    if (!c.verified) {
      return el("div", { class: "cat" },
        el("span", {}, c.name),
        el("div", { class: "cat__bar" }),
        el("span", { class: "cat__val muted" }, "non verificata",
          c.skip_reasons && c.skip_reasons.length ? el("small", {}, ` (${c.skip_reasons.join(", ")})`) : null));
    }
    const fill = el("div", { class: "cat__fill", "--fill-color": categoryColor(c.percent) });
    requestAnimationFrame(() => { fill.style.width = `${c.percent}%`; });
    return el("div", { class: "cat" },
      el("span", {}, c.name),
      el("div", { class: "cat__bar", role: "img", "aria-label": `${c.name}: ${c.percent}%` }, fill),
      el("span", { class: "cat__val" }, `${c.percent}% `, el("small", {}, `${fmt(c.points)}/${c.max_points}`)));
  });
  $("categories").replaceChildren(...rows);
}

function renderFindings(findings) {
  $("findings-count").textContent = findings.length;
  if (!findings.length) {
    $("findings").replaceChildren(el("p", { class: "empty" }, "Nessun fattore di pericolosita' rilevato."));
    return;
  }
  $("findings").replaceChildren(...findings.map((f) =>
    el("article", { class: "finding", "--sev-color": cssVar(SEVERITY_COLORS[f.severity]) },
      el("div", { class: "finding__head" },
        el("span", { class: "sev" }, f.severity),
        el("span", { class: "finding__name" }, f.name),
        el("span", { class: "finding__cat" }, f.category),
        el("span", { class: "finding__pts" }, `-${fmt(f.lost_points)} punti`)),
      el("dl", {},
        el("dt", {}, "Rilevato"), el("dd", {}, f.detected || "-"),
        f.source_url ? el("dt", {}, "Rilevato su") : null,
        f.source_url ? el("dd", {}, el("code", {}, f.source_url)) : null,
        el("dt", {}, "Perche' e' pericoloso"), el("dd", {}, f.why)))));
}

function renderLists(passed, skipped) {
  $("passed-count").textContent = passed.length;
  $("passed").replaceChildren(...passed.map((c) =>
    el("li", {}, el("span", {}, c.name, el("span", { class: "detail" }, c.detected),
      c.source_url && c.category === "Header" ? el("span", { class: "detail" }, `su ${c.source_url}`) : null))));

  $("skipped-card").hidden = skipped.length === 0;
  $("skipped-count").textContent = skipped.length;
  // raggruppati per motivo, nell'ordine in cui compaiono
  const groups = new Map();
  for (const c of skipped) {
    const key = c.reason_label || "";
    if (!groups.has(key)) groups.set(key, { label: c.reason_label, explanation: c.explanation, checks: [] });
    groups.get(key).checks.push(c);
  }
  $("skipped").replaceChildren(...[...groups.values()].map((g) => {
    const sameDetail = g.checks.length > 1 && g.checks.every((c) => c.reason === g.checks[0].reason);
    return el("div", { class: "skip-group" },
      g.label ? el("h3", {}, "Motivo: ", g.label) : null,
      g.explanation ? el("p", { class: "small" }, g.explanation) : null,
      sameDetail ? el("p", { class: "muted small" }, "Su questo dominio: ", g.checks[0].reason) : null,
      el("ul", { class: "checklist checklist--skipped" }, ...g.checks.map((c) =>
        el("li", {}, el("span", {}, c.name, sameDetail ? null : el("span", { class: "detail" }, c.reason))))));
  }));
}

// ---------------------------------------------------------------- cronologia
function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
  } catch {
    return [];
  }
}

function saveHistory(data) {
  const entry = { domain: data.domain, score: data.score, level: data.risk_level };
  const history = [entry, ...loadHistory().filter((h) => h.domain !== data.domain)].slice(0, 8);
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch { /* storage non disponibile: la cronologia resta solo in memoria */ }
  renderHistory(history);
}

function renderHistory(history = loadHistory()) {
  $("history-section").hidden = history.length === 0;
  $("history").replaceChildren(...history.map((h) => {
    const btn = el("button", { type: "button", "--hist-color": scoreColor(h.level) },
      h.domain, el("b", {}, h.score));
    btn.addEventListener("click", () => { $("domain").value = h.domain; scan(h.domain); });
    return el("li", {}, btn);
  }));
}

// ---------------------------------------------------------------- eventi
$("scan-form").addEventListener("submit", (e) => {
  e.preventDefault();
  scan($("domain").value);
});

$("rescan").addEventListener("click", () => {
  if (lastResult) scan(lastResult.domain);
});

$("download-json").addEventListener("click", () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const link = el("a", { href: URL.createObjectURL(blob), download: `scan-${lastResult.domain}.json` });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
});

renderHistory();
$("domain").focus();
