# Pilotage BR2027 — note de synthèse V1

*Pour Albéric — présentation de la V1 terminée. Dépôt : `albericboudy-lang/pilotage-br27` (privé).*

---

## Ce qui a été réalisé

Une **plateforme de pilotage complète**, conforme au cahier des charges v1.4 :

- **Pipeline de génération** (Node.js) qui lit la base Notion « Chantiers » via l'API officielle
  (SDK v5, *data sources* 2025), recopie les documents, **chiffre tout** (données + fichiers) et
  produit un site statique prêt à publier. La colonne **« Documents de travail » n'est jamais lue**.
- **Chiffrement de bout en bout** : AES-GCM 256, clé dérivée du mot de passe par PBKDF2-SHA256
  (600 000 itérations). Le déchiffrement a lieu **dans le navigateur** (WebCrypto), après mot de passe.
  L'interopérabilité chiffrement/déchiffrement est prouvée par un test automatisé.
- **Le cockpit** : board à 6 colonnes d'état, bandeau « santé du programme » (barre de répartition +
  compteurs cliquables), **rail d'avancement à 6 segments** (l'élément signature), recherche,
  filtres combinables (pilier / état / priorité), fiche détaillée en panneau latéral avec
  téléchargement des livrets/tracts/autres.
- **Design « état-major »** sur-mesure (Spectral + IBM Plex Sans auto-hébergés, palette raffinée,
  logo BR.27 réel, photo institutionnelle sur l'écran d'accès), **mode sombre**, **responsive ≤ 400 px**,
  **accessibilité WCAG AA** (contrastes vérifiés, clavier, focus, lecteurs d'écran).
- **CI/CD** GitHub Actions : régénération **horaire** + **manuelle** + à chaque push → **GitHub Pages**.
  `noindex` + `robots.txt`. **Aucun secret committé.**
- **Revue par 5 agents experts** (design, UX, accessibilité, technique/sécurité, fonctionnel),
  avec vérification adverse puis re-critique de clôture : **tous les constats ont été traités.**

> **Tout est vérifié en conditions réelles** (déverrouillage, cockpit, filtres, recherche,
> slide-over, déchiffrement d'un vrai PDF, mobile, mode sombre) — **zéro erreur console**,
> **aucune donnée lisible avant mot de passe**.

---

## Pour la mettre en ligne (≈ 5 min, 4 étapes)

Le code est poussé sur GitHub. Il reste **3 secrets à renseigner** (que vous seul détenez) et
**Pages à activer**. Tout est détaillé dans le [README](README.md §2) ; en résumé :

1. **Intégration Notion** → créer un token (`ntn_…`) et **partager la base « Chantiers »** avec.
2. **Secrets GitHub** (Settings → Secrets → Actions) :
   `NOTION_TOKEN`, `NOTION_DATA_SOURCE_ID` = `21366175-3d72-401c-9ecc-b76b1ac513bf`,
   `SITE_PASSWORD` (le mot de passe d'accès au site — à choisir fort).
3. **Pousser le workflow CI** (une seule fois — limite de permissions du jeton, voir plus bas) :
   ```
   cd C:\Users\aboudy\pilotage-br27
   gh auth refresh -s workflow
   git push
   ```
4. **Activer Pages** : Settings → Pages → *Source : GitHub Actions*. Puis Actions → *Run workflow*.

L'URL publiée apparaît dans Settings → Pages.

> **Tant que les secrets ne sont pas posés**, le site se publie en **mode démonstration**
> (8 chantiers fictifs, mot de passe **`BR27-demo`**) — pratique pour voir l'outil vivre tout de suite.
> Dès `NOTION_TOKEN` + `SITE_PASSWORD` renseignés, il bascule sur **vos vraies données** et **votre mot de passe**.

---

## Choix structurants

- **Site statique chiffré plutôt que serveur.** Imposé par le CDC et le bon sens : pas de serveur à
  maintenir, le jeton Notion reste côté build, et même sur un hébergement public le contenu reste
  illisible sans mot de passe. Le manifeste public ne contient que des paramètres cryptographiques.
- **Fichiers « cuits » dans le build.** Les PDF Notion (URLs qui expirent en ~1 h) sont téléchargés
  puis re-chiffrés à chaque régénération → **jamais de lien mort** côté utilisateur.
- **Deux modes (live / démonstration).** Le même pipeline tourne avec ou sans Notion. Cela permet une
  mise en ligne immédiate et un développement/tests sans dépendre d'un jeton.
- **Discipline de design.** 2 familles de polices, 4 tailles dans l'interface, trame 8 px, palette
  d'états raffinée (jamais les couleurs Notion brutes) — un outil de pilotage, pas un site de com.

---

## Points ouverts (décisions pour vous)

1. **Dépôt public ou privé.** Il est **privé** pour l'instant. ⚠️ **GitHub Pages gratuit exige un dépôt
   public** ; pour rester privé il faut **GitHub Pro**. Le modèle de sécurité (tout chiffré, mot de passe)
   est conçu pour tolérer un hébergement public — mais c'est votre arbitrage. *Dites-le-moi et je peux
   basculer une URL de démonstration publique immédiatement.*
2. **Permission `workflow`.** Le jeton `gh` de la machine n'a pas le scope `workflow`, je n'ai donc pas
   pu pousser le fichier d'automatisation. Il est prêt en commit local ; un `gh auth refresh -s workflow`
   puis `git push` le met en place (étape 3 ci-dessus).
3. **Reprise des chantiers (Lot 1).** L'**ancienne base de pilotage est supprimée** (corbeille Notion)
   et la **nouvelle base « Chantiers » est vide**. Il n'y a donc rien à migrer de façon destructive.
   Le site tourne sur le jeu de démonstration jusqu'à ce que vous saisissiez les vrais chantiers dans
   Notion — ils apparaîtront automatiquement à la régénération suivante. *Je n'ai volontairement rien
   écrit dans votre Notion sans votre feu vert.*
4. **Mot de passe & token** : à vous de les générer (je ne les ai pas) — étape 2 ci-dessus.

---

## Pour développer / faire évoluer

`npm run build:fixture && npm run serve` → aperçu local (mot de passe `BR27-demo`).
`npm run test:crypto` → test d'interopérabilité du chiffrement.
Design entièrement en jetons CSS en tête de `web/styles.css`. Détails dans le [README](README.md §4–5).
