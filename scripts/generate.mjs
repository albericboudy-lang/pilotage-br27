// Pilotage BR2027 — générateur du site statique chiffré.
//
// Lit la base Notion « Chantiers » (ou un jeu de démonstration local), recopie
// les fichiers (Livret / Tract / Autres livrables — JAMAIS « Documents de
// travail »), chiffre l'ensemble (AES-GCM, clé dérivée du mot de passe partagé
// par PBKDF2) et écrit le site prêt à publier dans dist/.
//
// Modes :
//   node scripts/generate.mjs              -> live si NOTION_TOKEN présent, sinon démo
//   node scripts/generate.mjs --fixture    -> force le mode démonstration
//
// Variables d'environnement (cf. README) :
//   NOTION_TOKEN, NOTION_DATA_SOURCE_ID, SITE_PASSWORD

import { Client } from '@notionhq/client';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  mkdirSync, rmSync, readFileSync, writeFileSync, cpSync, appendFileSync,
} from 'node:fs';
import { dirname, join, extname } from 'node:path';
import { deriveKey, encrypt, encryptJSON, KDF } from './crypto.mjs';
import { webcrypto } from 'node:crypto';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WEB = join(ROOT, 'web');
const DIST = join(ROOT, 'dist');
const FIX = join(ROOT, 'fixtures');

const PILIERS = ['Prospérité', 'Ordre', 'Fierté'];
// États retirés de l'affichage (demande utilisateur). Le reste est lu DYNAMIQUEMENT depuis Notion.
const HIDDEN_STATES = new Set(['GT lancé']);
// Colonnes de documents exposées, calquées sur le tableau Notion.
// « Documents de travail » est inclus à la demande explicite du commanditaire
// (le CDC le réservait à l'interne ; arbitrage assumé par Albéric).
const DOC_COLUMNS = [
  { key: 'livret', prop: 'Livret', label: 'Livret' },
  { key: 'tract', prop: 'Tract', label: 'Tract' },
  { key: 'travail', prop: 'Documents de travail', label: 'Documents de travail' },
  { key: 'retombees', prop: 'Retombées Presse', label: 'Retombées presse' },
  { key: 'autres', prop: 'Autres supports de présentation', label: 'Autres supports de présentation' },
];

const SALT = webcrypto.getRandomValues(new Uint8Array(KDF.saltBytes)); // sel aléatoire par build

const argv = process.argv.slice(2);
const env = (k) => (process.env[k] || '').trim(); // trim : un secret posé via stdin garde un \n
const NOTION_TOKEN = env('NOTION_TOKEN');
const DATA_SOURCE_ID = env('NOTION_DATA_SOURCE_ID') || '21366175-3d72-401c-9ecc-b76b1ac513bf';
const FIXTURE = argv.includes('--fixture') || !NOTION_TOKEN;

// Mot de passe : requis en prod ; défaut de dev (averti) pour bâtir/prévisualiser en local.
let SITE_PASSWORD = env('SITE_PASSWORD');
if (!SITE_PASSWORD) {
  if (!FIXTURE) { console.error('✗ SITE_PASSWORD manquant (requis en mode live).'); process.exit(1); }
  SITE_PASSWORD = 'BR27-demo';
  console.warn('⚠  SITE_PASSWORD non défini — mot de passe de DÉMONSTRATION « BR27-demo » utilisé pour ce build.');
}

const log = (...a) => console.log(...a);

// ---------- helpers de lecture Notion (défensifs, indexés sur le type réel) ----------
const plain = (rich) => ((rich || []).map((r) => r.plain_text).join('').trim() || null);
function readProp(props, name) {
  const p = props[name];
  if (!p) return null;
  switch (p.type) {
    case 'title': return plain(p.title);
    case 'rich_text': return plain(p.rich_text);
    case 'select': return p.select?.name ?? null;
    case 'status': return p.status?.name ?? null;
    case 'multi_select': return (p.multi_select || []).map((o) => o.name);
    case 'date': return p.date?.start ?? null;
    case 'number': return p.number ?? null;
    case 'url': return p.url ?? null;
    case 'unique_id':
      return p.unique_id == null ? null
        : `${p.unique_id.prefix ? p.unique_id.prefix + '-' : ''}${p.unique_id.number}`;
    case 'files': return p.files || [];
    default: return null;
  }
}
function fileEntries(filesProp) {
  if (!Array.isArray(filesProp)) return [];
  return filesProp
    .map((f) => {
      const url = f.type === 'file' ? f.file?.url : f.external?.url;
      return url ? { name: f.name || 'document', url } : null;
    })
    .filter(Boolean);
}
const inList = (v, list) => (v && list.includes(v) ? v : v || null);

const MIME = {
  '.pdf': 'application/pdf', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.doc': 'application/msword', '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.txt': 'text/plain',
  '.zip': 'application/zip', '.svg': 'image/svg+xml',
};
const mimeFromName = (name) => MIME[extname(name || '').toLowerCase()] || 'application/octet-stream';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Réessaie sur erreurs transitoires (429 / 5xx). status() extrait le code HTTP.
async function withRetry(fn, { tries = 4, base = 600, label = '' } = {}) {
  for (let i = 1; ; i++) {
    try { return await fn(); }
    catch (e) {
      const code = e?.status ?? e?.statusCode ?? e?.httpStatus;
      const transient = code === 429 || (code >= 500 && code < 600) || code === undefined;
      if (!transient || i >= tries) throw e;
      const wait = (e?.headers?.['retry-after'] ? Number(e.headers['retry-after']) * 1000 : 0) || base * 2 ** (i - 1);
      console.warn(`  ↻ ${label} : tentative ${i}/${tries} après ${wait}ms (${code ?? e.message})`);
      await sleep(wait);
    }
  }
}

// ---------- lecture des données ----------
async function readLive() {
  const notion = new Client({ auth: NOTION_TOKEN });
  log(`→ Lecture Notion (data source ${DATA_SOURCE_ID})`);

  // 1) Schéma : ordre RÉEL des états d'avancement (lecture dynamique → robuste aux changements).
  const ds = await withRetry(() => notion.dataSources.retrieve({ data_source_id: DATA_SOURCE_ID }), { label: 'schéma' });
  const etatProp = ds.properties?.["État d'avancement"];
  const states = (etatProp?.select?.options || []).map((o) => o.name).filter((s) => !HIDDEN_STATES.has(s));
  log(`  états : ${states.join(' · ')}`);

  // 2) Lignes (paginées).
  const rows = [];
  let cursor;
  do {
    const res = await withRetry(
      () => notion.dataSources.query({ data_source_id: DATA_SOURCE_ID, start_cursor: cursor, page_size: 100 }),
      { label: 'query Notion' });
    rows.push(...res.results.filter((r) => r.object === 'page' && !r.archived && !r.in_trash));
    cursor = res.has_more ? res.next_cursor : undefined;
  } while (cursor);
  log(`  ${rows.length} chantier(s) lus.`);

  const titleKeyOf = (props) =>
    'Chantier' in props ? 'Chantier' : Object.keys(props).find((k) => props[k].type === 'title');

  const chantiers = rows.map((page) => {
    const props = page.properties;
    return {
      id: page.id,
      chantier: readProp(props, titleKeyOf(props)) || '(Sans titre)',
      pilier: inList(readProp(props, 'Pilier'), PILIERS),
      etat: readProp(props, "État d'avancement"),
      dateAnnonce: readProp(props, "Date d'annonce"),
      prochaineEtape: readProp(props, 'Prochaine étape'),
      aProduire: readProp(props, 'To do') || readProp(props, 'À produire') || [],
      // Fichiers par colonne (cf. DOC_COLUMNS — inclut « Documents de travail » sur demande).
      _files: Object.fromEntries(DOC_COLUMNS.map((c) => [c.key, fileEntries(readProp(props, c.prop))])),
    };
  });
  return { states, chantiers };
}

function readFixtureData() {
  log('→ Mode DÉMONSTRATION (fixtures/chantiers.json)');
  const data = JSON.parse(readFileSync(join(FIX, 'chantiers.json'), 'utf8'));
  const chantiers = data.chantiers.map((c) => ({
    ...c,
    aProduire: c.aProduire || [],
    _files: Object.fromEntries(DOC_COLUMNS.map((col) =>
      [col.key, (c.documents?.[col.key] || []).map((d) => ({ name: d.name, mime: d.mime, path: d.path }))])),
  }));
  return { states: data.states, chantiers };
}

// ---------- récupération des octets d'un fichier ----------
async function fetchBytes(entry) {
  if (entry.path) {
    return { bytes: readFileSync(join(FIX, entry.path)), mime: entry.mime || mimeFromName(entry.name) };
  }
  // Réessaie sur 429/5xx ; un 404 (fichier réellement supprimé) échoue tout de suite.
  return withRetry(async () => {
    const res = await fetch(entry.url);
    if (!res.ok) { const err = new Error(`HTTP ${res.status} pour ${entry.name}`); err.status = res.status; throw err; }
    const bytes = Buffer.from(await res.arrayBuffer());
    const ct = (res.headers.get('content-type') || '').split(';')[0].trim();
    const mime = ct && ct !== 'application/octet-stream' ? ct : mimeFromName(entry.name);
    return { bytes, mime };
  }, { label: `fichier ${entry.name}`, tries: 3 });
}

// ---------- build ----------
async function main() {
  const t0 = Date.now();
  const key = deriveKey(SITE_PASSWORD, Buffer.from(SALT));

  const { states, chantiers } = FIXTURE ? readFixtureData() : await readLive();

  // Prépare dist/ : site statique + dossier des fichiers chiffrés.
  rmSync(DIST, { recursive: true, force: true });
  mkdirSync(join(DIST, 'files'), { recursive: true });
  cpSync(WEB, DIST, { recursive: true });

  // Recopie + chiffrement des fichiers, dédupliqués par contenu.
  const writtenFiles = new Map(); // sha1(bytes) -> fileId
  let fileCount = 0;
  let docCount = 0;
  let skipped = 0; // documents attendus mais non récupérés (live)

  async function processSlot(entries) {
    const out = [];
    for (const entry of entries) {
      try {
        const { bytes, mime } = await fetchBytes(entry);
        const sha = createHash('sha1').update(bytes).digest('hex');
        let fileId = writtenFiles.get(sha);
        if (!fileId) {
          fileId = sha.slice(0, 16);
          writeFileSync(join(DIST, 'files', `${fileId}.enc`), encrypt(key, bytes));
          writtenFiles.set(sha, fileId);
          fileCount++;
        }
        out.push({ id: fileId, name: entry.name, mime, size: bytes.length });
        docCount++;
      } catch (e) {
        skipped++;
        console.warn(`  ⚠  fichier ignoré (${entry.name}) : ${e.message}`);
      }
    }
    return out;
  }

  const publicChantiers = [];
  for (const c of chantiers) {
    const documents = {};
    for (const col of DOC_COLUMNS) documents[col.key] = await processSlot(c._files[col.key] || []);
    const { _files, documents: _d, ...rest } = c;
    publicChantiers.push({ ...rest, documents });
  }

  // Charge utile chiffrée (tout le contenu lisible vit ici).
  const generatedAt = new Date().toISOString();
  const payload = {
    version: 2,
    generatedAt,
    source: FIXTURE ? 'fixture' : 'live',
    states,                                                  // ordre réel des états (dynamique)
    piliers: PILIERS,
    docColumns: DOC_COLUMNS.map((c) => ({ key: c.key, label: c.label })),
    chantiers: publicChantiers,
  };
  writeFileSync(join(DIST, 'data.enc'), encryptJSON(key, payload));

  // Manifeste public : UNIQUEMENT des paramètres crypto (aucune donnée lisible).
  const manifest = {
    version: 1,
    algo: 'AES-GCM',
    kdf: { name: KDF.name, hash: KDF.hash, iterations: KDF.iterations },
    salt: Buffer.from(SALT).toString('base64'),
    data: 'data.enc',
    // jeton de vérification du mot de passe (ciphertext d'une constante) :
    check: encrypt(key, Buffer.from('BR27-OK')).toString('base64'),
  };
  writeFileSync(join(DIST, 'manifest.json'), JSON.stringify(manifest));

  // Résumé console (non publié).
  const byState = Object.fromEntries(states.map((s) => [s, publicChantiers.filter((c) => c.etat === s).length]));
  log('\n✔ Build terminé en', ((Date.now() - t0) / 1000).toFixed(1) + 's');
  log('  mode        :', FIXTURE ? 'démonstration' : 'live Notion');
  log('  chantiers   :', publicChantiers.length, JSON.stringify(byState));
  log('  fichiers    :', fileCount, 'chiffrés,', docCount, 'références de document');
  log('  horodatage  :', generatedAt);
  log('  sortie      :', DIST);

  // Critère d'acceptation §9.3 : un document attendu ne doit pas disparaître en silence.
  if (!FIXTURE && skipped > 0) {
    const msg = `⚠ ${skipped} document(s) attendu(s) n'ont pas pu être récupérés depuis Notion et NE figurent PAS sur le site.`;
    console.error('\n' + msg);
    if (process.env.GITHUB_STEP_SUMMARY) {
      try { appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n### Pilotage BR2027 — alerte\n\n${msg}\n`); } catch { /* non bloquant */ }
    }
  }
}

main().catch((e) => { console.error('✗ Échec du build :', e); process.exit(1); });
