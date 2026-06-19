// Pilotage BR2027 — application front-end (vanilla, déchiffrement WebCrypto).
// Aucune donnée n'est lisible avant la saisie du mot de passe : le manifeste
// public ne contient que des paramètres cryptographiques.

'use strict';

/* ---------- Constantes (miroir de scripts/generate.mjs) ---------- */
const STATES = ['GT lancé', 'Travail en cours', 'Validation BR', 'Finalisation', 'Prêt', 'Annoncé'];
const PILIERS = ['Prospérité', 'Ordre', 'Fierté'];
const PRIORITES = ['Haute', 'Moyenne', 'Basse'];
const STATE_VAR = { 'GT lancé': '--s-gt', 'Travail en cours': '--s-cours', 'Validation BR': '--s-valid', 'Finalisation': '--s-final', 'Prêt': '--s-pret', 'Annoncé': '--s-annonce' };
const PILIER_VAR = { 'Prospérité': '--p-prosperite', 'Ordre': '--p-ordre', 'Fierté': '--p-fierte' };
const PRIORITE_VAR = { 'Haute': '--urgent', 'Moyenne': '--soon', 'Basse': '--s-gt' };
const IV_BYTES = 12;

/* ---------- État applicatif ---------- */
const state = {
  manifest: null, key: null, pw: null, data: null,
  filters: { etats: new Set(), piliers: new Set(), priorites: new Set() },
  query: '',
  sort: { key: 'etat', dir: 1 }, // tri de la liste (état, par défaut)
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
  renderSynthese();
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

/* ---------- Rendu : synthèse ---------- */
function countsByState() {
  const c = Object.fromEntries(STATES.map((s) => [s, 0]));
  for (const ch of state.data.chantiers) if (c[ch.etat] != null) c[ch.etat]++;
  return c;
}
function renderSynthese() {
  const counts = countsByState();
  const total = state.data.chantiers.length;
  $('#total').innerHTML = `<b>${total}</b> chantier${total > 1 ? 's' : ''}`;

  const bar = $('#dist-bar'); bar.innerHTML = '';
  const sum = STATES.reduce((a, s) => a + counts[s], 0);
  if (sum === 0) { const e = el('span', 'distseg', { 'data-empty': '' }); bar.append(e); }
  else STATES.forEach((s) => {
    if (!counts[s]) return;
    const seg = el('span', 'distseg', { title: `${s} : ${counts[s]}` });
    setCssVar(seg, STATE_VAR[s]); seg.style.background = `var(${STATE_VAR[s]})`;
    seg.style.flex = String(counts[s]); bar.append(seg);
  });
  bar.setAttribute('aria-label', 'Répartition : ' + STATES.map((s) => `${counts[s]} ${s}`).join(', '));

  const wrap = $('#counters'); wrap.innerHTML = '';
  STATES.forEach((s) => {
    const c = el('button', 'counter', { type: 'button', 'aria-pressed': state.filters.etats.has(s) ? 'true' : 'false' });
    setCssVar(c, STATE_VAR[s]);
    c.innerHTML = `<span class="counter__dot"></span><span class="counter__label">${s}</span><span class="counter__n">${counts[s]}</span>`;
    c.addEventListener('click', () => toggleFilter('etats', s));
    wrap.append(c);
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
  groups.append(makeChipGroup('Priorité', 'priorites', PRIORITES, PRIORITE_VAR));
  $('#clear').addEventListener('click', clearFilters);
}
function toggleFilter(dim, value) {
  const set = state.filters[dim];
  set.has(value) ? set.delete(value) : set.add(value);
  syncFilterControls(); render();
}
function clearFilters() {
  state.filters.etats.clear(); state.filters.piliers.clear(); state.filters.priorites.clear();
  state.query = ''; $('#search').value = '';
  syncFilterControls(); render();
}
function syncFilterControls() {
  $('#counters').querySelectorAll('.counter').forEach((c, i) => c.setAttribute('aria-pressed', state.filters.etats.has(STATES[i]) ? 'true' : 'false'));
  $('#filter-groups').querySelectorAll('.fgroup').forEach((g) => {
    const dim = g.querySelector('.fgroup__label').textContent === 'Pilier' ? 'piliers' : 'priorites';
    g.querySelectorAll('.chip').forEach((chip) => {
      const v = chip.querySelector('span:last-child').textContent;
      chip.setAttribute('aria-pressed', state.filters[dim].has(v) ? 'true' : 'false');
    });
  });
  renderActiveChips();
}
function renderActiveChips() {
  const wrap = $('#active-chips'); wrap.innerHTML = '';
  const add = (dim, value, varName) => {
    const a = el('span', 'achip');
    if (varName) { setCssVar(a, varName); a.style.borderColor = `color-mix(in srgb, var(${varName}) 36%, transparent)`; a.style.background = `color-mix(in srgb, var(${varName}) 12%, var(--surface))`; }
    a.innerHTML = `<span>${value}</span>`;
    const x = el('button', null, { type: 'button', 'aria-label': `Retirer le filtre ${value}` });
    x.innerHTML = icon('x');
    x.addEventListener('click', () => toggleFilter(dim, value));
    a.append(x); wrap.append(a);
  };
  state.filters.etats.forEach((v) => add('etats', v, STATE_VAR[v]));
  state.filters.piliers.forEach((v) => add('piliers', v, PILIER_VAR[v]));
  state.filters.priorites.forEach((v) => add('priorites', v, PRIORITE_VAR[v]));
  const any = state.filters.etats.size || state.filters.piliers.size || state.filters.priorites.size || state.query;
  $('#clear').hidden = !any;
}

/* ---------- Filtrage ---------- */
function matches(ch) {
  const f = state.filters;
  if (f.etats.size && !f.etats.has(ch.etat)) return false;
  if (f.piliers.size && !f.piliers.has(ch.pilier)) return false;
  if (f.priorites.size && !f.priorites.has(ch.priorite)) return false;
  if (state.query) {
    const q = deburr(state.query);
    if (!deburr(ch.chantier).includes(q) && !deburr(ch.synthese).includes(q) && !deburr(ch.pilote).includes(q)) return false;
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
  const idx = STATES.indexOf(etat);
  let segs = '';
  for (let i = 0; i < STATES.length; i++) {
    const cls = idx < 0 ? '' : i < idx ? 'is-on' : i === idx ? 'is-on is-cur' : '';
    segs += `<span class="rail__seg ${cls}"></span>`;
  }
  return segs;
}

/* ---------- Tri ---------- */
const stIdx = (e) => { const i = STATES.indexOf(e); return i < 0 ? 99 : i; };
const prIdx = (p) => { const i = PRIORITES.indexOf(p); return i < 0 ? 99 : i; };
const byStr = (a, b) => (a || '').localeCompare(b || '', 'fr', { sensitivity: 'base' });
const SORTS = {
  chantier: (a, b) => byStr(a.chantier, b.chantier),
  etat: (a, b) => (stIdx(a.etat) - stIdx(b.etat)) || (prIdx(a.priorite) - prIdx(b.priorite)) || byStr(a.chantier, b.chantier),
  priorite: (a, b) => (prIdx(a.priorite) - prIdx(b.priorite)) || (stIdx(a.etat) - stIdx(b.etat)) || byStr(a.chantier, b.chantier),
  pilote: (a, b) => byStr(a.pilote, b.pilote) || byStr(a.chantier, b.chantier),
  echeance: (a, b) => byStr(a.echeance || '9999-99-99', b.echeance || '9999-99-99'),
};
const COLUMNS = [
  { key: 'chantier', label: 'Chantier', sortable: true },
  { key: 'etat', label: 'Avancement', sortable: true },
  { key: 'priorite', label: 'Priorité', sortable: true },
  { key: 'pilote', label: 'Pilote', sortable: true },
  { key: 'echeance', label: 'Échéance', sortable: true },
  { key: 'documents', label: 'Documents', sortable: false },
];
const DOC_SHORT = { Livret: 'Livret', Tract: 'Tract', Autre: 'Document' };

/* ---------- Rendu : liste ---------- */
function render() {
  const board = $('#board'); board.innerHTML = '';
  let visible = state.data.chantiers.filter(matches);

  if (visible.length === 0) {
    board.classList.add('is-empty');
    const filtresActifs = state.filters.etats.size || state.filters.piliers.size || state.filters.priorites.size || state.query;
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

  const table = el('div', 'list', { role: 'table', 'aria-label': 'Liste des chantiers' });
  const head = el('div', 'list__head', { role: 'row' });
  COLUMNS.forEach((col) => {
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
  if (state.sort.key === key) state.sort.dir *= -1; else { state.sort.key = key; state.sort.dir = 1; }
  render();
}

function docButtonsHTML(ch) {
  const groups = [['Livret', ch.documents?.livret], ['Tract', ch.documents?.tract], ['Autre', ch.documents?.autres]];
  const all = groups.flatMap(([label, arr]) => (arr || []).map((d) => ({ ...d, label })));
  if (!all.length) return '<span class="lmuted">—</span>';
  return `<div class="docchips">${all.map((d) => `<button class="docchip" type="button" data-id="${d.id}" data-name="${escapeHtml(d.name)}" data-mime="${d.mime}" aria-label="Télécharger ${escapeHtml(d.name)}" title="Télécharger ${escapeHtml(d.name)}">${icon('download', 'ic ic--xs')}<span>${DOC_SHORT[d.label]}</span></button>`).join('')}</div>`;
}
function rowEl(ch) {
  const row = el('div', 'lrow', { role: 'row' });
  const ecl = echeanceClass(ch);
  const sv = STATE_VAR[ch.etat] || '--ink-3';

  const c1 = el('div', 'lcell lcell--chantier', { role: 'cell' });
  const aria = `Ouvrir ${ch.chantier}${ch.ref ? ', ' + ch.ref : ''} — état ${ch.etat || 'non classé'}${ch.pilote ? ', piloté par ' + ch.pilote : ''}${ch.echeance ? ', échéance ' + fmtDate(ch.echeance) : ''}`;
  const btn = el('button', 'lrow__open', { type: 'button', 'aria-label': aria });
  btn.innerHTML = `<span class="lrow__title">${escapeHtml(ch.chantier)}</span><span class="lrow__sub">${ch.pilier ? `<span class="pastille" style="--c:var(${PILIER_VAR[ch.pilier]})">${ch.pilier}</span>` : ''}${ch.ref ? `<span class="lrow__ref">${ch.ref}</span>` : ''}</span>`;
  c1.append(btn);

  const c2 = el('div', 'lcell lcell--etat', { role: 'cell', 'data-label': 'Avancement' });
  c2.innerHTML = `<span class="etatpill" style="--c:var(${sv})"><span class="etatpill__dot"></span>${ch.etat || 'Non classé'}</span><span class="rail" style="--c:var(${sv})" aria-hidden="true">${railHTML(ch.etat)}</span>`;

  const c3 = el('div', 'lcell lcell--priorite', { role: 'cell', 'data-label': 'Priorité' });
  c3.innerHTML = ch.priorite ? `<span class="prio" style="--c:var(${PRIORITE_VAR[ch.priorite] || '--ink-3'})"><span class="prio__dot"></span>${ch.priorite}</span>` : '<span class="lmuted">—</span>';

  const c4 = el('div', 'lcell lcell--pilote', { role: 'cell', 'data-label': 'Pilote' });
  c4.innerHTML = ch.pilote ? escapeHtml(ch.pilote) : '<span class="lmuted">—</span>';

  const c5 = el('div', 'lcell lcell--echeance', { role: 'cell', 'data-label': 'Échéance' });
  c5.innerHTML = ch.echeance ? `<span class="ech ${ecl}">${ecl ? icon('alert', 'ic ic--xs') : ''}<span>${fmtDate(ch.echeance)}${ecl === 'is-urgent' ? ' · en retard' : ecl === 'is-soon' ? ' · bientôt' : ''}</span></span>` : '<span class="lmuted">—</span>';

  const c6 = el('div', 'lcell lcell--documents', { role: 'cell', 'data-label': 'Documents' });
  c6.innerHTML = docButtonsHTML(ch);
  c6.querySelectorAll('.docchip').forEach((b) => b.addEventListener('click', (e) => { e.stopPropagation(); downloadDoc(b); }));

  row.append(c1, c2, c3, c4, c5, c6);
  row.addEventListener('click', (e) => { if (e.target.closest('.docchip')) return; openDetail(ch, btn); });
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
  const ecl = echeanceClass(ch);
  const docs = renderDocs(ch);
  detail.innerHTML = `
    <div class="detail__head">
      <div class="detail__heading">
        <div class="detail__eyebrow">
          ${ch.pilier ? `<span class="pastille" style="--c:var(${PILIER_VAR[ch.pilier]})">${ch.pilier}</span>` : ''}
          ${ch.ref ? `<span class="detail__ref">${ch.ref}</span>` : ''}
        </div>
        <h2 class="detail__title" id="detail-title">${escapeHtml(ch.chantier)}</h2>
      </div>
      <button class="iconbtn detail__close" type="button" aria-label="Fermer">${icon('x')}</button>
    </div>
    <div class="detail__body">
      <div>
        <div class="dsection__label">État d’avancement — ${ch.etat || 'non classé'}</div>
        <div class="rail detail__rail" style="--c:var(${STATE_VAR[ch.etat] || '--ink-3'})" aria-hidden="true">${railHTML(ch.etat)}</div>
      </div>
      <dl class="dgrid">
        ${row('Priorité', ch.priorite || '—')}
        ${row('Pilote', escapeHtml(ch.pilote) || '—')}
        ${row('Échéance', ch.echeance ? fmtDate(ch.echeance) + (ecl === 'is-urgent' ? ' · en retard' : ecl === 'is-soon' ? ' · bientôt' : '') : '—', ecl)}
        ${row('Date d’annonce', ch.dateAnnonce ? fmtDate(ch.dateAnnonce) : '—')}
      </dl>
      ${ch.synthese ? `<div class="dsection"><div class="dsection__label">Synthèse</div><p class="dsection__text">${escapeHtml(ch.synthese)}</p></div>` : ''}
      ${ch.prochaineEtape ? `<div class="dsection"><div class="dsection__label">Prochaine étape</div><p class="dsection__text">${escapeHtml(ch.prochaineEtape)}</p></div>` : ''}
      ${ch.aProduire?.length ? `<div class="dsection"><div class="dsection__label">À produire</div><div class="produire">${ch.aProduire.map(tagHTML).join('')}</div></div>` : ''}
      <div class="dsection"><div class="dsection__label">Documents</div>${docs}</div>
    </div>`;

  detail.querySelector('.detail__close').addEventListener('click', closeDetail);
  detail.querySelectorAll('.docbtn').forEach((btn) => btn.addEventListener('click', () => downloadDoc(btn)));

  detail.hidden = false; scrim.hidden = false;
  app.inert = true; // confine réellement le focus à la modale
  void detail.offsetWidth; // reflow forcé : déclenche la transition sans dépendre de rAF
  detail.classList.add('is-open'); scrim.classList.add('is-open');
  detail.querySelector('.detail__close').focus();
  document.addEventListener('keydown', onDetailKey);
  scrim.addEventListener('click', closeDetail, { once: true });
}
function renderDocs(ch) {
  const groups = [['Livret', ch.documents?.livret], ['Tract', ch.documents?.tract], ['Autre', ch.documents?.autres]];
  const all = groups.flatMap(([label, arr]) => (arr || []).map((d) => ({ ...d, label })));
  if (!all.length) return `<p class="docs__empty">Aucun document pour l’instant.</p>`;
  return `<div class="docs">${all.map((d) => `
    <button class="docbtn" type="button" data-id="${d.id}" data-name="${escapeHtml(d.name)}" data-mime="${d.mime}" aria-label="Télécharger ${escapeHtml(d.name)}">
      <span class="docbtn__ic">${icon('file')}</span>
      <span class="docbtn__main"><span class="docbtn__name">${DOC_VERB[d.label] || 'Télécharger le document'}</span><span class="docbtn__meta">${escapeHtml(d.name)}${d.size ? ' · ' + fmtSize(d.size) : ''}</span></span>
      <span class="docbtn__dl">${icon('download')}</span>
    </button>`).join('')}</div>`;
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
    renderUpdated(); renderSynthese(); syncFilterControls(); render();
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
