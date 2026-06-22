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
  filters: { etats: new Set(), piliers: new Set(), priorites: new Set() },
  query: '',
  sort: { key: 'etat', dir: -1 }, // tri par défaut : du plus avancé (Lancé) au moins avancé
  lastFocus: null, // élément ayant ouvert le slide-over
};

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
const DOC_VERB = { Livret: 'Télécharger le livret', Tract: 'Télécharger le tract', Autre: 'Télécharger le document' };
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
  } catch (e) {
    showGateError('Données indisponibles. Réessaie plus tard.');
    unlockBtn.disabled = true;
  }
  pwInput.focus();
}
function showGateError(msg) { gateError.textContent = msg; gateError.hidden = false; }

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
    await loadData();
    enterApp();
  } catch (err) {
    showGateError('Mot de passe incorrect. Réessaie.');
    pwInput.select();
  } finally {
    unlockBtn.classList.remove('is-loading'); unlockBtn.disabled = false;
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
  renderUpdated();
  renderKpis();
  renderFilters();
  render();
  $('#search').addEventListener('input', (e) => { state.query = e.target.value.trim(); render(); });
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
function makeChipGroup(label, dim, values, varMap) {
  const g = el('div', 'fgroup');
  g.append(el('span', 'fgroup__label', { text: label }));
  values.forEach((v) => {
    const chip = el('button', 'chip', { type: 'button', 'aria-pressed': state.filters[dim].has(v) ? 'true' : 'false' });
    if (varMap) setCssVar(chip, varMap[v]);
    chip.innerHTML = (varMap ? `<span class="chip__dot"></span>` : '') + `<span>${v}</span>`;
    chip.addEventListener('click', () => toggleFilter(dim, v));
    g.append(chip);
  });
  return g;
}
function renderFilters() {
  const groups = $('#filter-groups'); groups.innerHTML = '';
  groups.append(makeChipGroup('Pilier', 'piliers', PILIERS, PILIER_VAR));
  $('#clear').addEventListener('click', clearFilters);
}
function toggleFilter(dim, value) {
  const set = state.filters[dim];
  set.has(value) ? set.delete(value) : set.add(value);
  syncFilterControls(); render();
}
function clearFilters() {
  state.filters.etats.clear(); state.filters.piliers.clear();
  state.query = ''; $('#search').value = '';
  syncFilterControls(); render();
}
function syncFilterControls() {
  $('#kpis').querySelectorAll('.kpi[data-etat]').forEach((k) => k.setAttribute('aria-pressed', state.filters.etats.has(k.dataset.etat) ? 'true' : 'false'));
  $('#filter-groups').querySelectorAll('.fgroup .chip').forEach((chip) => {
    const v = chip.querySelector('span:last-child').textContent;
    chip.setAttribute('aria-pressed', state.filters.piliers.has(v) ? 'true' : 'false');
  });
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

/* ---------- Urgence d'échéance ---------- */
function echeanceClass(ch) {
  if (!ch.echeance || ch.etat === 'Annoncé') return '';
  const d = new Date(ch.echeance); if (Number.isNaN(+d)) return '';
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const days = Math.round((d - today) / 86400000);
  if (days < 0) return 'is-urgent';
  if (days <= 14) return 'is-soon';
  return '';
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
};
// Colonnes : Chantier + Avancement + une colonne Documents (bouton → fenêtre).
function buildColumns() {
  return [
    { key: 'chantier', label: 'Chantier', sortable: true },
    { key: 'etat', label: 'Avancement', sortable: true },
    { key: 'documents', label: 'Documents', sortable: false },
  ];
}
function docCount(ch) {
  return (state.data.docColumns || []).reduce((n, col) => n + (ch.documents?.[col.key]?.length || 0), 0);
}

/* ---------- Rendu : liste ---------- */
function render() {
  const board = $('#board'); board.innerHTML = '';
  let visible = state.data.chantiers.filter(matches);

  if (visible.length === 0) {
    board.classList.add('is-empty');
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
    board.append(e);
    announce(0); return;
  }
  board.classList.remove('is-empty');

  const cmp = SORTS[state.sort.key] || SORTS.etat;
  visible = [...visible].sort((a, b) => cmp(a, b) * state.sort.dir);

  const columns = buildColumns();
  const table = el('div', 'list', { role: 'table', 'aria-label': 'Liste des chantiers' });
  const head = el('div', 'list__head', { role: 'row' });
  columns.forEach((col) => {
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
  board.append(table);
  announce(visible.length);
}
function sortBy(key) {
  if (state.sort.key === key) state.sort.dir *= -1;
  else { state.sort.key = key; state.sort.dir = key === 'etat' ? -1 : 1; } // l'avancement démarre du plus avancé
  render();
}

function rowEl(ch) {
  const row = el('div', 'lrow', { role: 'row' });
  const sv = stateVar(ch.etat);

  const c1 = el('div', 'lcell lcell--chantier', { role: 'cell' });
  const aria = `Ouvrir ${ch.chantier} — ${etatLabel(ch.etat)}`;
  const btn = el('button', 'lrow__open', { type: 'button', 'aria-label': aria });
  btn.innerHTML = `<span class="lrow__title">${escapeHtml(ch.chantier)}</span><span class="lrow__sub">${ch.pilier ? `<span class="pastille" style="--c:var(${PILIER_VAR[ch.pilier]})">${ch.pilier}</span>` : ''}</span>`;
  c1.append(btn);

  const c2 = el('div', 'lcell lcell--etat', { role: 'cell', 'data-label': 'Avancement' });
  c2.innerHTML = `<span class="etatpill" style="--c:var(${sv})"><span class="etatpill__dot"></span>${etatLabel(ch.etat)}</span><span class="rail" style="--c:var(${sv})" aria-hidden="true">${railHTML(ch.etat)}</span>`;

  // Colonne Documents : un bouton (compteur) ouvrant la fenêtre détaillée.
  const c3 = el('div', 'lcell lcell--documents', { role: 'cell', 'data-label': 'Documents' });
  const n = docCount(ch);
  if (n === 0) c3.innerHTML = '<span class="lmuted">—</span>';
  else {
    const db = el('button', 'docsbtn', { type: 'button', 'aria-label': `Voir les ${n} document(s) de ${ch.chantier}` });
    db.innerHTML = `${icon('file', 'ic ic--sm')}<span>${n} doc${n > 1 ? 's' : ''}</span>`;
    db.addEventListener('click', (e) => { e.stopPropagation(); openDetail(ch, db); });
    c3.append(db);
  }

  row.append(c1, c2, c3);
  row.addEventListener('click', (e) => { if (e.target.closest('button')) return; openDetail(ch, btn); });
  return row;
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
        <div class="dsection__label">État d’avancement — ${etatLabel(ch.etat)}</div>
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
    renderUpdated(); renderKpis(); syncFilterControls(); render();
  } catch (err) { /* on garde l'affichage courant */ }
  finally { btn.classList.remove('is-spinning'); btn.disabled = false; }
});
$('#lock').addEventListener('click', lock);
function lock() {
  state.key = null; state.pw = null; state.data = null;
  document.body.dataset.state = 'locked';
  app.hidden = true; gate.hidden = false; gate.style.display = '';
  pwInput.value = ''; gateError.hidden = true; pwInput.focus();
}
$('#home').addEventListener('click', (e) => { e.preventDefault(); clearFilters(); window.scrollTo({ top: 0 }); });

boot();
