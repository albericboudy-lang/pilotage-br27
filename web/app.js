// Pilotage BR2027 — application front-end (vanilla, déchiffrement WebCrypto).
// Aucune donnée n'est lisible avant la saisie du mot de passe : le manifeste
// public ne contient que des paramètres cryptographiques.

'use strict';

/* ---------- Constantes ---------- */
// Les états et les colonnes de documents sont lus DYNAMIQUEMENT depuis les données
// (eux-mêmes lus depuis Notion par generate.mjs) — robustes aux changements de schéma.
const PILIERS = ['Prospérité', 'Ordre', 'Fierté'];
// Couleur d'un état (connu → jeton dédié ; inconnu → neutre).
const STATE_VAR = {
  'Travail en cours': '--s-cours', 'Première revue BR': '--s-gt', 'Validation BR': '--s-valid',
  'Finalisation': '--s-final', 'Prêt': '--s-pret', 'Annoncé': '--s-annonce', 'Lancé': '--s-annonce',
};
const stateVar = (e) => STATE_VAR[e] || '--ink-3';
// Affichage : « Annoncé » montré « Lancé » tant que l'option n'est pas renommée dans Notion.
const ETAT_LABEL = { 'Annoncé': 'Lancé' };
const etatLabel = (e) => ETAT_LABEL[e] || e || 'Non classé';
const getStates = () => state.data?.states || [];
const statesDisplay = () => [...getStates()].reverse(); // du plus avancé au moins avancé
const PILIER_VAR = { 'Prospérité': '--p-prosperite', 'Ordre': '--p-ordre', 'Fierté': '--p-fierte' };
const IV_BYTES = 12;

/* ---------- État applicatif ---------- */
const state = {
  manifest: null, key: null, pw: null, data: null,
  filters: { etats: new Set(), piliers: new Set() },
  query: '',
  sort: { key: 'lancement', dir: 1 }, // tri par défaut : par date de lancement, du 1er lancé au dernier
  view: 'liste', // 'liste' | 'pilier'
  lastFocus: null, // élément ayant ouvert le slide-over
};

/* ---------- Mémoire d'interface (session uniquement — jamais de données déchiffrées) ---------- */
const UI_KEY = 'br27-ui2'; // bump : ignore les préférences mémorisées d'avant (nouveau tri par défaut)
function persistUi() {
  try {
    sessionStorage.setItem(UI_KEY, JSON.stringify({
      sort: state.sort, view: state.view, query: state.query,
      etats: [...state.filters.etats], piliers: [...state.filters.piliers],
    }));
  } catch { /* mode privé : on ignore */ }
}
function restoreUi() {
  try {
    const s = JSON.parse(sessionStorage.getItem(UI_KEY) || 'null'); if (!s) return;
    if (s.sort) state.sort = s.sort;
    if (s.view === 'pilier' || s.view === 'liste') state.view = s.view;
    if (s.query) { state.query = s.query; const si = $('#search'); if (si) si.value = s.query; }
    state.filters.etats = new Set(Array.isArray(s.etats) ? s.etats : []);
    state.filters.piliers = new Set(Array.isArray(s.piliers) ? s.piliers : []);
  } catch { /* ignore */ }
}
function clearUi() { try { sessionStorage.removeItem(UI_KEY); } catch { /* ignore */ } }

/* ---------- Utilitaires ---------- */
const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'text') n.textContent = v;
    else if (v != null) n.setAttribute(k, v);
  }
  return n;
};
const icon = (id, cls = 'ic') => `<svg class="${cls}" aria-hidden="true"><use href="#i-${id}"/></svg>`;
const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const deburr = (s) => (s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const A_PRODUIRE_LONG = { EDL: 'Élément de langage', Lettre: 'Lettre', Note: 'Note', Visuel: 'Visuel', Discours: 'Discours', Livret: 'Livret', Tract: 'Tract', Autre: 'Autre' };
const tagHTML = (t) => `<span class="tag" title="${A_PRODUIRE_LONG[t] || t}">${t}</span>`;
const fmtDate = (iso) => { if (!iso) return null; const d = new Date(iso); return Number.isNaN(+d) ? iso : d.toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', year: 'numeric' }); };
const fmtDateTime = (iso) => { const d = new Date(iso); return Number.isNaN(+d) ? iso : d.toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' }) + ' à ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }); };
const fmtSize = (n) => (!n ? '' : n < 1024 ? n + ' o' : n < 1048576 ? (n / 1024).toFixed(0) + ' Ko' : (n / 1048576).toFixed(1) + ' Mo');
function setCssVar(node, name) { if (name) node.style.setProperty('--c', `var(${name})`); }

/* ---------- Crypto (déchiffrement) ---------- */
async function deriveKey(password, saltBytes, iterations) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
async function decryptBytes(key, blob) {
  const iv = blob.subarray(0, IV_BYTES);
  const body = blob.subarray(IV_BYTES); // ciphertext || authTag
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, body));
}
async function fetchEnc(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/* ---------- Amorçage ---------- */
const gate = $('#gate'), gateForm = $('#gate-form'), pwInput = $('#pw'),
  unlockBtn = $('#unlock'), gateError = $('#gate-error'), app = $('#app');

async function boot() {
  try {
    const res = await fetch('manifest.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('manifest indisponible');
    state.manifest = await res.json();
    unlockBtn.disabled = false;
  } catch (e) {
    showGateError('Données momentanément indisponibles (régénération en cours ?).', boot);
    unlockBtn.disabled = true;
  }
  pwInput.focus();
}
function showGateError(msg, retry) {
  gateError.innerHTML = escapeHtml(msg);
  if (retry) {
    const b = el('button', 'btn btn--ghost btn--sm gate__retry', { type: 'button', text: 'Réessayer' });
    b.style.marginTop = '8px';
    b.addEventListener('click', () => { gateError.hidden = true; retry(); });
    gateError.append(document.createElement('br'), b);
  }
  gateError.hidden = false;
}
function setUnlockLabel(txt) { const l = unlockBtn.querySelector('.btn__label'); if (l) l.textContent = txt; }

gateForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  gateError.hidden = true;
  const pw = pwInput.value;
  if (!pw || !state.manifest) return;
  unlockBtn.classList.add('is-loading'); unlockBtn.disabled = true;
  try {
    const m = state.manifest;
    const key = await deriveKey(pw, b64ToBytes(m.salt), m.kdf.iterations);
    // Vérification rapide du mot de passe via le jeton chiffré.
    const probe = new TextDecoder().decode(await decryptBytes(key, b64ToBytes(m.check)));
    if (probe !== 'BR27-OK') throw new Error('bad');
    state.key = key; state.pw = pw;
    setUnlockLabel('Déchiffrement des données…');
    await loadData();
    enterApp();
  } catch (err) {
    showGateError('Mot de passe incorrect. Réessaie.');
    pwInput.select();
  } finally {
    unlockBtn.classList.remove('is-loading'); unlockBtn.disabled = false;
    setUnlockLabel('Accéder au cockpit');
  }
});

async function loadData() {
  const blob = await fetchEnc(state.manifest.data);
  const json = new TextDecoder().decode(await decryptBytes(state.key, blob));
  state.data = JSON.parse(json);
}

function enterApp() {
  document.body.dataset.state = 'unlocked';
  gate.hidden = true; gate.style.display = 'none';
  app.hidden = false;
  restoreUi();           // tri/vue/filtres mémorisés (session)
  renderUpdated();
  renderKpis();
  renderFilters();
  render();
  $('#search').addEventListener('input', (e) => { state.query = e.target.value.trim(); render(); persistUi(); });
  // Séquence d'ouverture (générique d'état-major) — uniquement après que les données sont prêtes.
  app.classList.add('is-entering');
  setTimeout(() => app.classList.remove('is-entering'), 1100);
}

/* ---------- Rendu : horodatage ---------- */
function renderUpdated() {
  const t = state.data.generatedAt;
  const label = 'Dernière mise à jour le ' + fmtDateTime(t);
  const demo = state.data.source === 'fixture' ? ' (données de démonstration)' : '';
  const node = $('#updated');
  node.textContent = label;
  node.title = label + demo;
  const foot = $('#updated-foot');
  if (foot) foot.textContent = label + demo;
}

/* ---------- Rendu : indicateurs (KPI) ---------- */
function countsByState() {
  const c = Object.fromEntries(getStates().map((s) => [s, 0]));
  for (const ch of state.data.chantiers) if (c[ch.etat] != null) c[ch.etat]++;
  return c;
}
function livretKey() {
  return (state.data.docColumns || []).find((c) => /livret/i.test(c.key) || /livret/i.test(c.label))?.key || null;
}

function renderKpis() {
  const counts = countsByState();
  const total = state.data.chantiers.length;
  const wrap = $('#kpis'); wrap.innerHTML = '';

  // Total — non filtrant (clic = tout afficher)
  const t = el('button', 'kpi kpi--total', { type: 'button', title: 'Tous les chantiers' });
  t.innerHTML = `<span class="kpi__n">${total}</span><span class="kpi__label">Chantiers</span>`;
  t.addEventListener('click', () => { state.filters.etats.clear(); syncFilterControls(); render(); });
  wrap.append(t);

  // Un indicateur par état (du plus avancé au moins avancé), cliquable = filtre
  statesDisplay().forEach((s) => {
    const k = el('button', 'kpi', { type: 'button', 'data-etat': s, 'aria-pressed': state.filters.etats.has(s) ? 'true' : 'false' });
    setCssVar(k, stateVar(s));
    k.innerHTML = `<span class="kpi__n">${counts[s]}</span><span class="kpi__label"><span class="kpi__dot"></span>${etatLabel(s)}</span>`;
    k.addEventListener('click', () => toggleFilter('etats', s));
    wrap.append(k);
  });
}

/* ---------- Rendu : filtres ---------- */
function makeChipGroup(label, dim, values, varMap, labelFn) {
  const g = el('div', 'fgroup');
  g.append(el('span', 'fgroup__label', { text: label }));
  values.forEach((v) => {
    const chip = el('button', 'chip', { type: 'button', 'data-dim': dim, 'data-val': v, 'aria-pressed': state.filters[dim].has(v) ? 'true' : 'false' });
    if (varMap) setCssVar(chip, varMap[v]);
    chip.innerHTML = (varMap ? `<span class="chip__dot"></span>` : '') + `<span>${labelFn ? labelFn(v) : v}</span>`;
    chip.addEventListener('click', () => toggleFilter(dim, v));
    g.append(chip);
  });
  return g;
}
function renderFilters() {
  // Commutateur de vue (Liste | Par pilier)
  const vt = $('#view-toggle');
  if (vt) {
    vt.innerHTML = `<button class="vtoggle__btn" type="button" data-view="liste" aria-pressed="${state.view === 'liste'}">${icon('list', 'ic ic--sm')}<span>Liste</span></button>`
      + `<button class="vtoggle__btn" type="button" data-view="pilier" aria-pressed="${state.view === 'pilier'}">${icon('columns', 'ic ic--sm')}<span>Par pilier</span></button>`;
    vt.querySelectorAll('.vtoggle__btn').forEach((b) => b.addEventListener('click', () => setView(b.dataset.view)));
  }
  const groups = $('#filter-groups'); groups.innerHTML = '';
  groups.append(makeChipGroup('Pilier', 'piliers', PILIERS, PILIER_VAR));
  const etatVar = Object.fromEntries(getStates().map((s) => [s, stateVar(s)]));
  groups.append(makeChipGroup('État', 'etats', statesDisplay(), etatVar, etatLabel));
  $('#clear').addEventListener('click', clearFilters);
  syncFilterControls();
}
function toggleFilter(dim, value) {
  const set = state.filters[dim];
  set.has(value) ? set.delete(value) : set.add(value);
  persistUi(); syncFilterControls(); render();
}
function clearFilters() {
  state.filters.etats.clear(); state.filters.piliers.clear();
  state.query = ''; $('#search').value = '';
  persistUi(); syncFilterControls(); render();
}
function syncFilterControls() {
  $('#kpis').querySelectorAll('.kpi[data-etat]').forEach((k) => k.setAttribute('aria-pressed', state.filters.etats.has(k.dataset.etat) ? 'true' : 'false'));
  $('#filter-groups').querySelectorAll('.chip').forEach((chip) => chip.setAttribute('aria-pressed', state.filters[chip.dataset.dim]?.has(chip.dataset.val) ? 'true' : 'false'));
  renderActiveChips();
}
function renderActiveChips() {
  const wrap = $('#active-chips'); wrap.innerHTML = '';
  const add = (dim, value, varName, labelText) => {
    const lbl = labelText || value;
    const a = el('span', 'achip');
    if (varName) { setCssVar(a, varName); a.style.borderColor = `color-mix(in srgb, var(${varName}) 36%, transparent)`; a.style.background = `color-mix(in srgb, var(${varName}) 12%, var(--surface))`; }
    a.innerHTML = `<span>${lbl}</span>`;
    const x = el('button', null, { type: 'button', 'aria-label': `Retirer le filtre ${lbl}` });
    x.innerHTML = icon('x');
    x.addEventListener('click', () => toggleFilter(dim, value));
    a.append(x); wrap.append(a);
  };
  state.filters.etats.forEach((v) => add('etats', v, stateVar(v), etatLabel(v)));
  state.filters.piliers.forEach((v) => add('piliers', v, PILIER_VAR[v]));
  const any = state.filters.etats.size || state.filters.piliers.size || state.query;
  $('#clear').hidden = !any;
}

/* ---------- Filtrage ---------- */
function matches(ch) {
  const f = state.filters;
  if (f.etats.size && !f.etats.has(ch.etat)) return false;
  if (f.piliers.size && !f.piliers.has(ch.pilier)) return false;
  if (state.query) {
    const q = deburr(state.query);
    if (!deburr(ch.chantier).includes(q) && !deburr(ch.prochaineEtape).includes(q)) return false;
  }
  return true;
}

/* ---------- Rail signature ---------- */
function railHTML(etat) {
  const states = getStates();
  const idx = states.indexOf(etat);
  let segs = '';
  for (let i = 0; i < states.length; i++) {
    const cls = idx < 0 ? '' : i < idx ? 'is-on' : i === idx ? 'is-on is-cur' : '';
    segs += `<span class="rail__seg ${cls}"></span>`;
  }
  return segs;
}

/* ---------- Tri ---------- */
const stIdx = (e) => { const i = getStates().indexOf(e); return i < 0 ? -1 : i; }; // ordre workflow
const byStr = (a, b) => (a || '').localeCompare(b || '', 'fr', { sensitivity: 'base' });
const SORTS = {
  chantier: (a, b) => byStr(a.chantier, b.chantier),
  etat: (a, b) => (stIdx(a.etat) - stIdx(b.etat)) || byStr(a.chantier, b.chantier),
  // Par date de lancement ; les chantiers sans date d'annonce passent toujours en bas.
  lancement: (a, b) => {
    const da = a.dateAnnonce, db = b.dateAnnonce;
    if (!da && !db) return byStr(a.chantier, b.chantier);
    if (!da) return 1; if (!db) return -1;
    return byStr(da, db) || byStr(a.chantier, b.chantier);
  },
};
// Colonnes : Chantier + Lancement (date d'annonce) + Avancement + Documents.
function buildColumns() {
  return [
    { key: 'chantier', label: 'Chantier', sortable: true },
    { key: 'lancement', label: 'Lancement', sortable: true },
    { key: 'etat', label: 'Avancement', sortable: true },
    { key: 'documents', label: 'Documents', sortable: false },
  ];
}
function docCount(ch) {
  return (state.data.docColumns || []).reduce((n, col) => n + (ch.documents?.[col.key]?.length || 0), 0);
}

/* Documents : accès direct au livret (1 clic) si unique + bouton « N docs » -> fenêtre. */
function docsAffordanceHTML(ch) {
  const n = docCount(ch);
  if (n === 0) return '<span class="lmuted">—</span>';
  const lk = livretKey();
  const livrets = lk ? (ch.documents?.[lk] || []) : [];
  let html = '<div class="docsaff">';
  if (livrets.length === 1) {
    const d = livrets[0];
    html += `<button class="docchip" type="button" data-id="${d.id}" data-name="${escapeHtml(d.name)}" data-mime="${d.mime}" aria-label="Télécharger le livret de ${escapeHtml(ch.chantier)}" title="Télécharger le livret">${icon('download', 'ic ic--sm')}<span>Livret</span></button>`;
  }
  html += `<button class="docsbtn" type="button" aria-label="Voir les ${n} document(s) de ${escapeHtml(ch.chantier)}">${icon('file', 'ic ic--sm')}<span>${n} doc${n > 1 ? 's' : ''}</span></button>`;
  return html + '</div>';
}
function wireDocsAff(cell, ch) {
  cell.querySelectorAll('.docchip').forEach((b) => b.addEventListener('click', (e) => { e.stopPropagation(); downloadDoc(b); }));
  const ds = cell.querySelector('.docsbtn');
  if (ds) ds.addEventListener('click', (e) => { e.stopPropagation(); openDetail(ch, ds); });
}

/* ---------- Rendu : dispatcher (liste / par pilier) ---------- */
function render() {
  const board = $('#board'); board.innerHTML = '';
  let visible = state.data.chantiers.filter(matches);

  if (visible.length === 0) {
    board.classList.add('is-empty'); board.removeAttribute('data-view');
    const filtresActifs = state.filters.etats.size || state.filters.piliers.size || state.query;
    const e = el('div', 'empty');
    if (state.data.chantiers.length === 0) {
      e.innerHTML = `<h3>Aucun chantier pour l’instant</h3><p>La base ne contient encore aucun chantier. Dès qu’un chantier est saisi dans Notion, il apparaîtra ici à la prochaine régénération.</p>`;
    } else if (filtresActifs) {
      e.innerHTML = `<h3>Aucun chantier ne correspond</h3><p>Aucun chantier ne correspond aux filtres ou à la recherche en cours.</p>`;
      const btn = el('button', 'btn btn--ghost btn--sm', { type: 'button', text: 'Effacer les filtres' });
      btn.style.margin = '0 auto'; btn.addEventListener('click', clearFilters);
      e.append(btn);
    } else {
      e.innerHTML = `<h3>Aucun chantier à afficher</h3><p>Aucun chantier n’est disponible pour le moment.</p>`;
    }
    board.append(e); announce(0); return;
  }
  board.classList.remove('is-empty');
  const cmp = SORTS[state.sort.key] || SORTS.etat;
  visible = [...visible].sort((a, b) => cmp(a, b) * state.sort.dir);

  board.dataset.view = state.view;
  board.append(state.view === 'pilier' ? pilierBoard(visible) : listTable(visible));

  // Stagger d'entrée (plafonné) — purement décoratif, coupé en reduced-motion.
  let i = 0; board.querySelectorAll('.lrow, .pcard').forEach((r) => r.style.setProperty('--i', Math.min(i++, 12)));
  announce(visible.length);
}
function sortBy(key) {
  if (state.sort.key === key) state.sort.dir *= -1;
  else { state.sort.key = key; state.sort.dir = key === 'etat' ? -1 : 1; } // avancement : plus avancé d'abord ; lancement : du 1er au dernier
  persistUi(); render();
}
function setView(v) { if (state.view === v) return; state.view = v; persistUi(); syncViewToggle(); render(); }
function syncViewToggle() {
  document.querySelectorAll('.vtoggle__btn').forEach((b) => b.setAttribute('aria-pressed', b.dataset.view === state.view ? 'true' : 'false'));
}

function listTable(visible) {
  const table = el('div', 'list', { role: 'table', 'aria-label': 'Liste des chantiers' });
  const head = el('div', 'list__head', { role: 'row' });
  buildColumns().forEach((col) => {
    const active = state.sort.key === col.key;
    const cls = `lh lcell--${col.key}${active ? ' is-active is-' + (state.sort.dir === 1 ? 'asc' : 'desc') : ''}`;
    const cell = el(col.sortable ? 'button' : 'div', cls, { role: 'columnheader' });
    if (col.sortable) {
      cell.type = 'button';
      cell.setAttribute('aria-sort', active ? (state.sort.dir === 1 ? 'ascending' : 'descending') : 'none');
      cell.innerHTML = `<span>${col.label}</span><span class="lh__caret" aria-hidden="true"></span>`;
      cell.addEventListener('click', () => sortBy(col.key));
    } else cell.textContent = col.label;
    head.append(cell);
  });
  table.append(head);
  visible.forEach((ch) => table.append(rowEl(ch)));
  return table;
}
function rowEl(ch) {
  const row = el('div', 'lrow', { role: 'row' });
  const sv = stateVar(ch.etat);
  const c1 = el('div', 'lcell lcell--chantier', { role: 'cell' });
  const btn = el('button', 'lrow__open', { type: 'button', 'aria-label': `Ouvrir ${ch.chantier} — ${etatLabel(ch.etat)}` });
  btn.innerHTML = `<span class="lrow__title">${escapeHtml(ch.chantier)}</span><span class="lrow__sub">${ch.pilier ? `<span class="pastille" style="--c:var(${PILIER_VAR[ch.pilier]})">${ch.pilier}</span>` : ''}</span>`;
  c1.append(btn);
  const c2 = el('div', 'lcell lcell--etat', { role: 'cell', 'data-label': 'Avancement' });
  c2.innerHTML = `<span class="etatpill" style="--c:var(${sv})"><span class="etatpill__dot"></span>${etatLabel(ch.etat)}</span><span class="rail" style="--c:var(${sv})" aria-hidden="true">${railHTML(ch.etat)}</span>`;
  const cL = el('div', 'lcell lcell--lancement', { role: 'cell', 'data-label': 'Lancement' });
  cL.innerHTML = ch.dateAnnonce ? `<span class="ldate">${fmtDate(ch.dateAnnonce)}</span>` : '<span class="lmuted">—</span>';
  const c3 = el('div', 'lcell lcell--documents', { role: 'cell', 'data-label': 'Documents' });
  c3.innerHTML = docsAffordanceHTML(ch); wireDocsAff(c3, ch);
  row.append(c1, cL, c2, c3);
  row.addEventListener('click', (e) => { if (e.target.closest('button')) return; openDetail(ch, btn); });
  return row;
}

/* ---------- Rendu : vue par pilier ---------- */
function pilierProgress(items) {
  const L = getStates().length; const known = items.filter((c) => stIdx(c.etat) >= 0);
  if (!known.length || L < 2) return 0;
  return Math.round(known.reduce((s, c) => s + stIdx(c.etat), 0) / ((L - 1) * known.length) * 100);
}
function miniRing(pct) {
  const r = 13, C = 2 * Math.PI * r, off = C * (1 - pct / 100);
  return `<svg class="ring ring--mini" viewBox="0 0 32 32" aria-hidden="true"><circle class="ring__track" cx="16" cy="16" r="${r}"/><circle class="ring__val" cx="16" cy="16" r="${r}" stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/></svg>`;
}
function chantierCard(ch) {
  const sv = stateVar(ch.etat);
  const card = el('article', 'pcard', { role: 'listitem' });
  const btn = el('button', 'pcard__open', { type: 'button', 'aria-label': `Ouvrir ${ch.chantier} — ${etatLabel(ch.etat)}` });
  btn.innerHTML = `<span class="pcard__title">${escapeHtml(ch.chantier)}</span>`;
  card.append(btn);
  const meta = el('div', 'pcard__meta');
  meta.innerHTML = `<span class="etatpill" style="--c:var(${sv})"><span class="etatpill__dot"></span>${etatLabel(ch.etat)}</span>`
    + (ch.dateAnnonce ? `<span class="pcard__date" title="Date de lancement">${icon('megaphone', 'ic ic--xs')}<span>${fmtDate(ch.dateAnnonce)}</span></span>` : '');
  card.append(meta);
  const rail = el('div', 'rail', { 'aria-hidden': 'true' }); setCssVar(rail, sv); rail.innerHTML = railHTML(ch.etat);
  card.append(rail);
  const docs = el('div', 'pcard__docs'); docs.innerHTML = docsAffordanceHTML(ch); wireDocsAff(docs, ch);
  card.append(docs);
  card.addEventListener('click', (e) => { if (e.target.closest('button')) return; openDetail(ch, btn); });
  return card;
}
function pilierBoard(visible) {
  const wrap = el('div', 'pboard');
  const cols = [...PILIERS];
  const orphans = visible.filter((c) => !PILIERS.includes(c.pilier));
  if (orphans.length) cols.push('Transversal');
  cols.forEach((p) => {
    const items = p === 'Transversal' ? orphans : visible.filter((c) => c.pilier === p);
    const col = el('section', 'pcol', { 'aria-label': `Pilier ${p}` });
    setCssVar(col, PILIER_VAR[p] || '--ink-3');
    const head = el('header', 'pcol__head');
    head.innerHTML = `<span class="pcol__dot"></span><span class="pcol__name">${p}</span>`
      + `<span class="pcol__ring" title="Avancement moyen">${miniRing(pilierProgress(items))}</span>`
      + `<span class="pcol__count">${items.length}</span>`;
    col.append(head);
    const body = el('div', 'pcol__body', { role: 'list', 'aria-label': `Chantiers — ${p}` });
    if (!items.length) body.append(el('p', 'col__empty', { text: '—' }));
    else items.forEach((ch) => body.append(chantierCard(ch)));
    col.append(body); wrap.append(col);
  });
  return wrap;
}
function announce(n) {
  $('#result-status').textContent = `${n} chantier${n > 1 ? 's' : ''} affiché${n > 1 ? 's' : ''}.`;
}

function escapeHtml(s) { return (s || '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

/* ---------- Slide-over ---------- */
const detail = $('#detail'), scrim = $('#scrim');
function row(dt, dd, cls) { return `<dt>${dt}</dt><dd class="${cls || ''}">${dd}</dd>`; }
function openDetail(ch, trigger) {
  state.lastFocus = trigger;
  const docs = renderDocs(ch);
  const idx = stIdx(ch.etat), L = getStates().length;
  const etape = idx >= 0 ? `<span class="detail__step">Étape ${idx + 1} sur ${L}</span>` : '';
  detail.style.setProperty('--c', `var(${ch.pilier ? PILIER_VAR[ch.pilier] : stateVar(ch.etat)})`);
  detail.innerHTML = `
    <div class="detail__head">
      <div class="detail__heading">
        <div class="detail__eyebrow">
          ${ch.pilier ? `<span class="pastille" style="--c:var(${PILIER_VAR[ch.pilier]})">${ch.pilier}</span>` : ''}
        </div>
        <h2 class="detail__title" id="detail-title">${escapeHtml(ch.chantier)}</h2>
      </div>
      <button class="iconbtn detail__close" type="button" aria-label="Fermer">${icon('x')}</button>
    </div>
    <div class="detail__body">
      <div>
        <div class="dsection__head"><div class="dsection__label">État d’avancement — ${etatLabel(ch.etat)}</div>${etape}</div>
        <div class="rail detail__rail" style="--c:var(${stateVar(ch.etat)})" aria-hidden="true">${railHTML(ch.etat)}</div>
      </div>
      ${ch.dateAnnonce ? `<dl class="dgrid">${row('Date d’annonce', fmtDate(ch.dateAnnonce))}</dl>` : ''}
      ${ch.prochaineEtape ? `<div class="dsection"><div class="dsection__label">Prochaine étape</div><p class="dsection__text">${escapeHtml(ch.prochaineEtape)}</p></div>` : ''}
      ${ch.aProduire?.length ? `<div class="dsection"><div class="dsection__label">À produire</div><div class="produire">${ch.aProduire.map(tagHTML).join('')}</div></div>` : ''}
      <div class="dsection"><div class="dsection__label">Documents</div>${docs}</div>
    </div>`;

  detail.querySelector('.detail__close').addEventListener('click', closeDetail);
  detail.querySelectorAll('.docbtn').forEach((btn) => btn.addEventListener('click', () => downloadDoc(btn)));
  const pb = detail.querySelector('.packbtn');
  if (pb) pb.addEventListener('click', () => downloadPack(ch, pb));

  detail.hidden = false; scrim.hidden = false;
  app.inert = true; // confine réellement le focus à la modale
  void detail.offsetWidth; // reflow forcé : déclenche la transition sans dépendre de rAF
  detail.classList.add('is-open'); scrim.classList.add('is-open');
  detail.querySelector('.detail__close').focus();
  document.addEventListener('keydown', onDetailKey);
  scrim.addEventListener('click', closeDetail, { once: true });
}
function docbtnHTML(d) {
  return `<button class="docbtn" type="button" data-id="${d.id}" data-name="${escapeHtml(d.name)}" data-mime="${d.mime}" aria-label="Télécharger ${escapeHtml(d.name)}">
      <span class="docbtn__ic">${icon('file')}</span>
      <span class="docbtn__main"><span class="docbtn__name">${escapeHtml(d.name)}</span><span class="docbtn__meta">${d.size ? fmtSize(d.size) : 'Télécharger'}</span></span>
      <span class="docbtn__dl">${icon('download')}</span>
    </button>`;
}
function renderDocs(ch) {
  const cols = state.data.docColumns || [];
  const groups = cols.map((col) => ({ label: col.label, files: ch.documents?.[col.key] || [] })).filter((g) => g.files.length);
  if (!groups.length) return `<p class="docs__empty">Aucun document pour l’instant.</p>`;
  const total = groups.reduce((n, g) => n + g.files.length, 0);
  const pack = total > 1
    ? `<button class="btn btn--primary btn--sm packbtn" type="button"><span class="btn__label">${icon('download', 'ic ic--sm')} Tout télécharger (.zip)</span><span class="btn__spin" aria-hidden="true"></span></button>`
    : '';
  const body = groups.map((g) => `<div class="docgroup">
      <div class="docgroup__label">${escapeHtml(g.label)} <span class="docgroup__n">${g.files.length}</span></div>
      <div class="docgroup__list">${g.files.map(docbtnHTML).join('')}</div>
    </div>`).join('');
  return `${pack}<div class="docs">${body}</div>`;
}

/* ---------- Téléchargement « pack » (.zip côté navigateur, sans dépendance) ---------- */
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
function makeZip(entries) { // store (sans compression — les PDF le sont déjà)
  const enc = new TextEncoder(); const chunks = []; const central = []; let offset = 0;
  for (const e of entries) {
    const name = enc.encode(e.name); const crc = crc32(e.data); const size = e.data.length;
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true);
    lh.setUint16(8, 0, true); lh.setUint32(14, crc, true); lh.setUint32(18, size, true);
    lh.setUint32(22, size, true); lh.setUint16(26, name.length, true);
    chunks.push(new Uint8Array(lh.buffer), name, e.data);
    const cd = new DataView(new ArrayBuffer(46));
    cd.setUint32(0, 0x02014b50, true); cd.setUint16(4, 20, true); cd.setUint16(6, 20, true);
    cd.setUint16(8, 0x0800, true); cd.setUint32(16, crc, true); cd.setUint32(20, size, true);
    cd.setUint32(24, size, true); cd.setUint16(28, name.length, true); cd.setUint32(42, offset, true);
    central.push(new Uint8Array(cd.buffer), name);
    offset += 30 + name.length + size;
  }
  let centralSize = 0; for (const c of central) centralSize += c.length;
  const eocd = new DataView(new ArrayBuffer(22));
  eocd.setUint32(0, 0x06054b50, true); eocd.setUint16(8, entries.length, true);
  eocd.setUint16(10, entries.length, true); eocd.setUint32(12, centralSize, true); eocd.setUint32(16, offset, true);
  const parts = [...chunks, ...central, new Uint8Array(eocd.buffer)];
  let len = 0; for (const p of parts) len += p.length;
  const out = new Uint8Array(len); let pos = 0; for (const p of parts) { out.set(p, pos); pos += p.length; }
  return out;
}
async function downloadPack(ch, btn) {
  if (btn.classList.contains('is-loading')) return;
  btn.classList.add('is-loading');
  try {
    const cols = state.data.docColumns || [];
    const all = cols.flatMap((col) => (ch.documents?.[col.key] || []));
    const used = new Map(); const entries = [];
    for (const d of all) {
      const bytes = await decryptBytes(state.key, await fetchEnc('files/' + d.id + '.enc'));
      let name = d.name || 'document';
      if (used.has(name)) { const i = name.lastIndexOf('.'); const k = used.get(name); name = i > 0 ? `${name.slice(0, i)} (${k})${name.slice(i)}` : `${name} (${k})`; }
      used.set(d.name || 'document', (used.get(d.name || 'document') || 0) + 1);
      entries.push({ name, data: bytes });
    }
    const url = URL.createObjectURL(new Blob([makeZip(entries)], { type: 'application/zip' }));
    const a = el('a', null, { href: url, download: (ch.chantier || 'chantier').replace(/[^\w\-]+/g, '_') + '.zip' });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  } catch (e) { btn.classList.add('is-error'); setTimeout(() => btn.classList.remove('is-error'), 5000); }
  finally { btn.classList.remove('is-loading'); }
}
async function downloadDoc(btn) {
  if (btn.classList.contains('is-loading')) return;
  btn.classList.add('is-loading');
  try {
    const blob = await fetchEnc('files/' + btn.dataset.id + '.enc');
    const bytes = await decryptBytes(state.key, blob);
    const url = URL.createObjectURL(new Blob([bytes], { type: btn.dataset.mime || 'application/octet-stream' }));
    const a = el('a', null, { href: url, download: btn.dataset.name || 'document' });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  } catch (e) {
    const meta = btn.querySelector('.docbtn__meta'); // panneau détail
    if (meta) {
      const original = meta.textContent;
      meta.textContent = 'Téléchargement impossible — réessayez.';
      meta.classList.add('is-error');
      setTimeout(() => { meta.textContent = original; meta.classList.remove('is-error'); }, 5000);
    } else { // puce de liste : pas de zone méta, on signale par le titre + une classe
      const original = btn.getAttribute('title');
      btn.classList.add('is-error');
      btn.setAttribute('title', 'Téléchargement impossible — réessayez.');
      setTimeout(() => { btn.classList.remove('is-error'); if (original) btn.setAttribute('title', original); }, 5000);
    }
  } finally {
    btn.classList.remove('is-loading');
  }
}
function onDetailKey(e) {
  if (e.key === 'Escape') { closeDetail(); return; }
  if (e.key !== 'Tab') return;
  const focusables = detail.querySelectorAll('button, [href], input, [tabindex]:not([tabindex="-1"])');
  if (!focusables.length) return;
  const first = focusables[0], last = focusables[focusables.length - 1];
  if (!detail.contains(document.activeElement)) { e.preventDefault(); first.focus(); return; }
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}
function closeDetail() {
  detail.classList.remove('is-open'); scrim.classList.remove('is-open');
  app.inert = false;
  document.removeEventListener('keydown', onDetailKey);
  const restore = state.lastFocus;
  setTimeout(() => { detail.hidden = true; scrim.hidden = true; detail.innerHTML = ''; if (restore) restore.focus(); }, 200);
}

/* ---------- Topbar : rafraîchir / verrouiller / accueil ---------- */
$('#refresh').addEventListener('click', async (e) => {
  const btn = e.currentTarget; btn.classList.add('is-spinning'); btn.disabled = true;
  try {
    const res = await fetch('manifest.json', { cache: 'no-store' });
    state.manifest = await res.json();
    state.key = await deriveKey(state.pw, b64ToBytes(state.manifest.salt), state.manifest.kdf.iterations);
    await loadData();
    renderUpdated(); renderKpis(); renderFilters(); syncFilterControls(); render();
  } catch (err) { showDataBanner(); }
  finally { btn.classList.remove('is-spinning'); btn.disabled = false; }
});
$('#lock').addEventListener('click', lock);
function lock() {
  state.key = null; state.pw = null; state.data = null;
  clearUi();
  document.body.dataset.state = 'locked';
  app.hidden = true; gate.hidden = false; gate.style.display = '';
  pwInput.value = ''; gateError.hidden = true; pwInput.focus();
}
function showDataBanner() {
  const b = $('#databanner'); if (!b) return;
  b.textContent = 'Données momentanément indisponibles — affichage de la dernière version.';
  b.hidden = false;
  clearTimeout(b._t); b._t = setTimeout(() => { b.hidden = true; }, 6000);
}
$('#home').addEventListener('click', (e) => { e.preventDefault(); clearFilters(); window.scrollTo({ top: 0 }); });

boot();
