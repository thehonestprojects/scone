# Storage — persistance locale du nœud (redb)

> Document normatif. Toute divergence entre ce document et
> `crates/scone-storage/src/` est un bug (identifier la source de
> vérité, corriger). Référence d'implémentation : crate
> `scone-storage` (format v1), backend `redb` 4.2.

## Objectif

Persistance locale embarquée du nœud : blocs canoniques, états de
domaines, cache DHT, métadonnées. Le store est une **persistance**,
jamais une autorité : l'état en RAM ([`ChainState`], source du
consensus) est reconstruit au démarrage depuis le store, et chaque
écriture est un **delta** (domaines modifiés par bloc), jamais une
copie intégrale de l'état.

Contrainte transverse (utilisateur, chaque jalon) : **empreinte mémoire
minimale**. Gros volumes (blocs, états domaines, cache DHT) vivent
dans redb et sont accessibles par curseurs/plages — jamais chargés
intégralement en RAM, jamais dupliqués inutilement.

## Frontière : trait `NodeStore`

`crates/scone-storage/src/lib.rs` définit le seul visage storage du
reste du code (blockchain, futur relay M4) :

- `append_block(height, hash, bytes)` / `append_block_with_state(...,
  deltas)` — append atomique (voir ci-dessous) ;
- `block_at_height(h)` / `block_by_hash(hash)` — lectures ponctuelles ;
- `tip() -> (height, hash)` — O(1), lu depuis `meta` ;
- `put_domain_state` / `domain_state` / `domain_count` — compteur
  **maintenu** (`meta["domain_count"]`), jamais de `COUNT(*)` ;
- `iterate_domains(after, max) -> DomainPage` — pagination par curseur
  (lots de 100 par défaut), ordre croissant des octets du `DomainId` ;
- `put_tld_state` / `tld_state` / `tld_count` / `iterate_tlds` —
  mêmes contrats pour le registre TLD (`tld_count` maintenu,
  curseur borné) (M7d) ;
- `put_dht_cache` / `dht_cache` — octets `SignedDnsRecord` opaques ;
- `resolve_name(canonical)` / `resolve_tld(tld)` — index Name→Id
  persistant (P0.2), lookup ponctuel O(1), sans itération des
  domaines (défaut `None` = backend sans index, l'appelant retombe
  sur `iterate_domains` ou l'état chaîne) ;
- `meta_get` / `meta_set` ;
- `snapshot_meta` / `snapshot_domains` / `snapshot_tlds` — lecture du
  snapshot d'état de boot (M6b ; défauts vides = backend sans
  snapshot, `load_chain` retombe alors sur le chargement complet).

Règles :

- **Aucun type redb dans l'API** : octets (`&[u8]`, `[u8; 32]`) et
  types core uniquement. Le backend est remplaçable.
- **Async-free, pas d'intérior mutabilité** : écritures `&mut self`
  (redb sérialise les writers), lectures `&self` (une read
  transaction courte par appel).
- L'API ne revalide jamais les blocs : le hash passé à
  `append_block*` est le hash **recalculé** fourni par l'appelant
  (`Blockchain::push_block`).

## Schéma des tables redb

| Table | Clé (tri) | Valeur |
|---|---|---|
| `blocks_by_height` | `u64` height (b-tree ordonné) | `hash(32) ‖ height(8 BE) ‖ block canonique` |
| `blocks_by_hash` | hash de bloc (32 o) | encodage canonique du bloc |
| `domains` | `DomainId` (32 o, ordre octet) | `DomainStateBytes` (ci-dessous) |
| `tlds` | `TldId` (32 o, ordre octet) | `TldStateBytes` (ci-dessous, M7d) |
| `dht_cache` | `DomainId` (32 o) | octets `SignedDnsRecord` (opaques) |
| `names_v3` (P0.2) | clé d'index (32 o, ordre octet) | id cible (32 o) |
| `name_reverse_v3` (P0.2) | id cible (32 o, ordre octet) | `tag(1) ‖ nom canonique` |
| `meta` | `&[u8]` | `&[u8]` |
| `snapshot_v3_meta` (M6b) | `u64` = 0 (slot unique) | `height(8 BE) ‖ tip_hash(32)` = 40 o exactement |
| `snapshot_v3_domains` (M6b) | `DomainId` (32 o, ordre octet) | `DomainStateBytes` (même format que `domains`) |
| `snapshot_v3_tlds` (M6b) | `TldId` (32 o, ordre octet) | `TldStateBytes` (même format que `tlds`) |

Clé de `meta` supplémentaire (P0.3/P0.4) :

| Clé | Valeur |
|---|---|
| `verified_snapshot_v1` (P0.3) | `height(8 BE) ‖ tip_hash(32) ‖ manifest_hash(32)` = 72 o — marqueur d'un snapshot importé VÉRIFIÉ (réservée, comme `tip`) |

Clés de `meta` :

| Clé | Valeur |
|---|---|
| `format_version` | `u64 BE` = `STORAGE_FORMAT_VERSION` (1) |
| `tip` | hash (32 o) du bloc tip |
| `tip_height` | `u64 BE` (rend `tip()` O(1)) |
| `domain_count` | `u64 BE` (compteur maintenu) |
| `tld_count` | `u64 BE` (compteur maintenu, M7d) |

L'en-tête `hash ‖ height` de `blocks_by_height` rend chaque index
auto-porteur (vérifiable sans lire le bloc) ; les deux index sont mis
à jour dans la même transaction.

### Convention genèse

Le bloc de genèse est déterministe (constantes de protocole) et n'est
**jamais stocké** en octets. Un store frais a `tip == (0,
genesis_hash)` ; le premier bloc appendu a la hauteur 1. Le hash de
genèse est toujours re-dérivé (`scone_blockchain::genesis_hash()`),
jamais lu.

## Format d'encodage `DomainStateBytes` (v2, M8b)

57 ou 89 octets selon le tag de version en tête, entiers big-endian à
largeur fixe (canoniques, comparables octet par octet) :

```text
DomainStateBytes = tag ‖ owner(32) ‖ sequence(8 BE) ‖ registered_at(8 BE)
                   ‖ valid_until(8 BE) [‖ record_hash(32)]

tag = 0x01 : record_hash présent → 89 octets exactement
tag = 0x02 : record_hash absent  → 57 octets exactement
```

- `registered_at` / `valid_until` (M8b) : l'expiration de
  l'enregistrement (1 an à la claim, renouvelable, voir
  `/docs/technical/blockchain.md`).

Les encodages M7 (41/73 octets, sans expiration) sont **illégitimes**
depuis M8b : décodage strict → `Corrupted`. (Un store M7 se régénère
par replay : `load_chain_replay`.)

- `owner` : `OwnerId` (32 o) ;
- `sequence` : dernière séquence `UpdateDomain` appliquée (0 juste après
  un `RegisterDomain`) ;
- `record_hash` : engagement on-chain courant du jeu d'enregistrements
  DNS (`None` tant qu'aucun `UpdateDomain` n'a été appliqué).

Décodage **strict** (`DomainStateBytes::decode`) : tag inconnu,
longueur erronée ou octets en excès → `StorageError::Corrupted`,
jamais de panic.

## Format d'encodage `TldStateBytes` (v2, M8b)

Toujours exactement 34 octets (un owner + le drapeau d'ouverture du
namespace ; ni séquence ni record hash) :

```text
TldStateBytes = tag(0x02) ‖ owner(32) ‖ open(0x00|0x01)
```

- `open` (M8b) : `false` = assign-only, `true` = auto-enregistrement
  avec PoW. Strictement canonique — tout autre octet → `Corrupted`.

Les encodages M7d (33 octets, tag `0x01`, sans `open`) sont
**illégitimes** : décodage strict → `Corrupted`.

Le tag n'existe que pour l'évolution du format : un futur layout
bump le tag et les vieux lecteurs échouent en `Corrupted` au lieu de
deviner. Décodage **strict** (`TldStateBytes::decode`) : tag inconnu,
longueur erronée, octets en excès ou booléen non canonique →
`StorageError::Corrupted`, jamais de panic.

## Garanties d'atomicité

`append_block_with_state` écrit dans **une seule** `WriteTransaction`
redb :

1. le bloc dans `blocks_by_height` (vérification préalable : la
   hauteur ne doit pas exister avec un autre contenu, sinon
   `StorageError::Conflict`) ;
2. le bloc dans `blocks_by_hash` ;
3. chaque delta d'état de domaine (`domains`) ;
4. le compteur `domain_count` (incrémenté du nombre de domaines
   **nouveaux** seulement ; un `UpdateDomain` d'un domaine existant ne
   l'incrémente pas) ;
5. chaque delta du registre TLD (`tlds`, M8b : claims, transfers,
   open/close) — **dans la même transaction** : un bloc écrit sans ses
   changements TLD est structurellement impossible ;
6. le compteur `tld_count` (nouveaux TLDs seulement) ;
7. chaque **retrait** (M8b) : domaines expirés par le GC déterministe
   (`removed_domains`) et TLDs révoqués (`removed_tlds`) quittent le
   store dans la même transaction, compteurs décrémentés — un
   redémarrage ne peut jamais ressusciter un enregistrement expiré ;
8. les deltas de l'**index de noms** P0.2 (upserts et retraits, voir
   ci-dessous) — mêmes garanties : un crash ne laisse jamais une
   entrée d'index pointant vers un domaine absent ;
9. `tip` et `tip_height`.

redb commite en style WAL : un crash en pleine écriture laisse l'état
cohérent **précédent**. **Un bloc écrit sans son état est donc
structurellement impossible** — c'est l'invariant clé du jalon.

Garanties supplémentaires :

- **Monotonie** : append à une hauteur ≠ `tip_height + 1` →
  `StorageError::NonMonotonicHeight`, rien n'est écrit (vérifié
  *avant* d'ouvrir la transaction d'écriture) ;
- **Idempotence** : ré-appender le bloc tip courant avec le même
  couple `(height, hash)` est un no-op (le chemin rapide compare
  hauteur et hash ; à hauteur égale, des octets de bloc identiques
  sont aussi un no-op silencieux, des octets différents un
  `Conflict`) ;
- **Base corrompue** : fichier tronqué/pollué → erreur typée
  (`StorageError::Database`/`Corrupted`) à l'ouverture ou à la
  lecture, jamais de panic (testé) ;
- **Version de format** : un `format_version` ≠ 1 →
  `StorageError::UnsupportedFormat` (chemin de migration explicite
  requis, jamais de devinette).

## Intégration blockchain (`integration.rs`)

Division des rôles : [`ChainState`] en RAM = autorité consensus ;
store = persistance. Stratégie choisie (la plus simple, documentée) :
**persistance de l'état à chaque bloc** — `store_block` écrit le bloc
+ les états des domaines **touchés par ce bloc** (delta). Le rejeu
complet reste possible et sert de contrôle/repair.

- `store_block(store, chain, block, hash)` : encode le bloc
  canoniquement, lit l'état final des domaines touchés ET des TLDs
  claimés dans l'état RAM (déjà mis à jour par `push_block`), append
  atomique.
- `load_chain(store)` : **sans rejeu** — lit tip + bloc tip (O(1)
  lectures bloc), restaure l'état domaines par pages de 100
  (`DOMAIN_PAGE`) **et le registre TLD par pages de 100**
  (`TLD_PAGE`, M7d — fermeture de la fenêtre de redémarrage : sans
  elle, un nœud redémarré oubliait tout TLD claimé et rejetait tout
  `RegisterDomain` sous ce TLD en `UnknownTld`, alors même que son
  disque détenait l'état complet). La chaîne RAM ne retient que
  genèse + tip ; les blocs historiques restent dans le store et sont
  servis depuis lui. Depuis M8, `load_chain` reconstruit ensuite
  **l'index anti-replay TXID** (voir ci-dessous).
- `load_chain_replay(store)` : rejoue tous les blocs stockés un par un
  (jamais tous en RAM) avec la validation complète ; le tip obtenu
  doit égaler le tip stocké, sinon `Corrupted`.
- `rebuild_replay_index_from_store(store, chain, tip_height)` (M8) :
  rescanne les derniers `min(REPLAY_WINDOW_BLOCKS, tip_height)`
  blocs persistés (un bloc en RAM à la fois) et réinsère chaque TxId
  dans l'index de la chaîne **à sa hauteur d'inclusion d'origine**,
  via l'API publique `Blockchain::rebuild_replay_index` (aucun accès
  aux champs privés). Bloc manquant sous le tip ou indécodable dans
  la fenêtre → `Corrupted` (ces octets ont déjà servi à bâtir la
  chaîne : une défaillance ici signale un store endommagé).
- `touched_domains(block)` : ids des domaines modifiés par les
  transactions du bloc, dédupliqués, ordre du bloc.
- `touched_tlds(block)` : ids des TLDs mutés par le bloc
  (`RegisterTld`, `TransferTld`, `RevokeTld`, `SetTldOpen`),
  dédupliqués, ordre du bloc (M8b).
- `store_block_with_removals(...)` : variante de `store_block`
  recevant aussi les domaines retirés par le GC du bloc (M8b) pour
  l'écriture atomique décrite ci-dessus. Le relay alimente cette
  liste depuis `Blockchain::push_block_with_gc` (l'issue
  d'application expose `gc_removed_domains`).

Le relay (M4) utilisera : `load_chain` au démarrage, puis pour chaque
bloc accepté `push_block` (RAM) puis `store_block` (disque).

## Snapshot d'état de boot (M6b)

`load_chain` tel que décrit ci-dessus reste O(taille de l'état) :
aucun bloc n'est rejoué, mais toute la table `domains` est relue.
C'est le chemin de persistance-état-par-bloc qui rend le rejeu
inutile. Le snapshot M6b répond à un autre coût : le cas où l'état
RAM doit être reconstruit **par rejeu** (réparation, contrôle, ou
backend sans état persisté par bloc). Il offre un boot en
**O(tip − H)** — rejeu du seul suffixe au-dessus du snapshot.

### Écriture

- **Intervalle** : `SNAPSHOT_INTERVAL = 64` (constante publique de
  `scone-storage`). Le déclencheur est l'append du bloc
  `k·SNAPSHOT_INTERVAL + 1` : la transaction gèle alors l'état des
  tables vivantes **tel qu'il est avant l'application de ce bloc**,
  c'est-à-dire l'état canonique après le bloc `k·SNAPSHOT_INTERVAL`.
- **Jamais à la pointe** : le snapshot siège donc à `tip − 1` au
  plus proche, toujours strictement sous la pointe au moment où il
  est écrit. Un crash juste après ne peut jamais laisser un snapshot
  « au-dessus » de la chaîne persistée.
- **Atomique** : le gel (clear + copie des tables `domains`/`tlds`
  vers `snapshot_v3_*`, écriture de `snapshot_v3_meta`) se produit
  dans la MÊME transaction redb que l'append du bloc déclencheur —
  un crash laisse soit l'ancien snapshot intact, soit le nouveau
  complet avec son bloc (WAL redb).
- **Slot unique** : chaque snapshot REMPLACE le précédent (tables
  vidées puis recopiées) — pas d'accumulation, pas de pruning à
  gérer, la taille disque est bornée par ~2× l'état.
- Le format des états gelés est strictement celui de
  `DomainStateBytes`/`TldStateBytes` (réutilisation, aucun encodage
  nouveau) ; seule la ligne `snapshot_v3_meta` est un format neuf
  (`height(8 BE) ‖ tip_hash(32)`, décodage strict : toute autre
  longueur → `Corrupted`).

### Lecture au boot (`load_chain`)

1. Le tip est validé comme toujours (hash recalculé depuis le header
   du bloc tip vs `meta["tip"]`).
2. Si `snapshot_meta()` existe, que sa hauteur `H` vérifie
   `0 < H < tip_height`, et que le hash RECALCULÉ du bloc stocké à
   `H` égale le `tip_hash` du snapshot (**ancre** — un snapshot
   étranger à la chaîne persistée, altéré ou issu d'un autre fichier
   est détecté ici), l'état gelé est restauré par pages de 100 puis
   les blocs `H+1..=tip` seuls sont rejoués (validation complète,
   identique aux blocs vivants).
3. Le tip rejoint par le rejeu doit égaler le tip stocké.
4. **Toute défaillance sur ce chemin (absence de snapshot, hauteur
   inutilisable, ancre invalide, octets indécodables, rejeu en
   échec) dégrade silencieusement vers le chargement complet
   pré-M6b** (lecture des tables vivantes, sans rejeu) — un snapshot
   en mauvais état ne fait jamais échouer le boot. La compatibilité
   descendante est le cas particulier « aucun snapshot » : un store
   écrit avant M6b (sans les tables `snapshot_v3_*`) charge à
   l'identique, `snapshot_meta()` valant `None`.

Le suffixe rejoué est borné par `SNAPSHOT_INTERVAL` (au plus 64
blocs au moment du déclenchement + les blocs minés depuis) : le boot
est O(tip − H) avec H garanti récent.

## Index anti-replay TXID reconstruit au boot (M8)

L'index anti-replay (`included`, TxId → hauteur d'inclusion, fenêtre
`REPLAY_WINDOW_BLOCKS = 256` — voir `/docs/technical/blockchain.md`)
est une **fonction pure de la chaîne canonique** : il n'est jamais
persisté. `load_chain` ne rejouant pas l'historique, une chaîne
restaurée démarrait avant M8 avec un index **vide** — un nœud
redémarré acceptait la ré-inclusion de toute transaction encore dans
sa fenêtre de rejeu (limitation documentée ; les règles d'état
demeuraient le seul garde-fou).

M8 ferme cette fenêtre : après la restauration (chemin complet OU
snapshot + rejeu de suffixe), `load_chain` appelle
`rebuild_replay_index_from_store`, qui relit les derniers
`min(REPLAY_WINDOW_BLOCKS, tip_height)` blocs persistés — un bloc en
RAM à la fois, borné mémoire comme partout — et réinsère chaque TxId
à sa **hauteur d'origine**. Un store de moins de 256 blocs
reconstitue donc tout son index.

Propriétés :

- **Décisions identiques au nœud vivant** : mêmes entrées, même règle
  d'élagage (`h > tip − 256`) — un nœud qui redémarre et un nœud qui
  n'a jamais arrêté rejettent les mêmes rejeux (testé : comptage
  exact de l'index et égalité avec l'index vivant élagué).
- **Sémantique d'élagage inchangée** : une transaction plus vieille
  que la fenêtre reste admise par l'index (et échoue ensuite sur les
  règles d'état si applicable) — exactement comme avant.
- **Le snapshot ne gèle PAS l'index** : le rejeu de suffixe du
  snapshot reconstruit les entrées au-dessus de H, le rescan M8
  ajoute la partie de la fenêtre SOUS H (même contrat que
  owner_keys/grace : reconstruits, jamais persistés).
- **Coût** : ≤ 256 lectures bloc ponctuelles au boot, O(fenêtre) —
  indépendant de l'âge de la chaîne.
- Un bloc manquant ou indécodable **dans la fenêtre** fait échouer le
  boot en `Corrupted` (ces octets ont déjà servi à bâtir la chaîne) ;
  en dehors de la fenêtre, les blocs historiques ne sont pas touchés.

`load_chain_replay` (confiance zéro) reconstruit l'index de la même
manière par son rejeu complet — les deux chemins convergent.

## Index Name → Id persistant (P0.2)

`DomainId = BLAKE3-256(DOMAIN_ID_VERSION ‖ nom canonique)` n'est pas
inversible : résoudre un nom (relay/DNS) exige un index persistant.
P0.2 l'ajoute au store, avec la même discipline transactionnelle que
le reste.

### Schéma

Deux tables compagnes, écrites et effacées ensemble :

```text
names_v3        clé  = BLAKE3-256("SCONE-NAME-IDX-V1" ‖ nom canonique)  (32 o)
                val  = id cible (32 o : DomainId ou TldId)

name_reverse_v3 clé  = id cible (32 o)
                val  = tag(0x01 domaine | 0x02 TLD) ‖ nom canonique
```

- La clé de `names_v3` est un **hash du nom, pas le nom en clair**
  (tables d'index compactes, pas de gossip de noms par dump). La clé
  est une **fonction pure du nom** : l'index est reconstructible à
  tout moment depuis la chaîne (`rebuild_name_index`), aucune
  métadonnée supplémentaire n'est persistée pour lui.
- `name_reverse_v3` stocke le nom (une seule fois) parce que les
  chemins de retrait (GC des domaines expirés, `RevokeTld`) ne
  connaissent que des **ids** : il faut bien retrouver la clé hachée
  à effacer. Le tag distingue les deux espaces de noms.
- Séparation stricte : `resolve_name` ne répond JAMAIS une entrée
  TLD et `resolve_tld` jamais une entrée domaine (le tag de la table
  reverse tranche ; un `DomainName` a ≥ 2 labels, un TLD en a 1 —
  les deux dérivations de clé partagent l'espace `names_v3` mais pas
  les résultats).
- Le `DomainId` reste 32 octets, jamais réduit (règle dure du
  projet : identité consensus, résistance aux collisions).

### Cohérence transactionnelle

Les upserts (`RegisterDomain`, `AssignDomain`, `RegisterTld` — noms
portés en clair par les transactions) et les retraits (GC,
révocations — ids nus) sont portés par le `StateDelta` du bloc
(`name_upserts` / `name_removals`) et appliqués dans la **même
transaction redb** que l'écriture du bloc et des états. Un crash ne
peut donc laisser ni une entrée d'index vers un domaine absent (pas
de fantômes), ni un domaine enregistré sans son entrée. Un append
échoué n'écrit rien (testé). Les variantes nommées
`put_domain_state_with_name` / `put_tld_state_with_name` /
`remove_domain_state` offrent la même atomicité aux outils de
réparation.

`store_block` / `store_block_with_removals` dérivent les deltas de
noms des MÊMES transactions du bloc — aucun paramètre supplémentaire
à l'interface du relay.

### Reconstruction (`RedbStore::rebuild_name_index`)

L'index est une fonction pure de la chaîne canonique, comme l'index
anti-replay M8. `rebuild_name_index` le reconstruit depuis les
**blocs persistés** (les `DomainStateBytes` ne contiennent PAS le
nom — owner/séquence/expiration uniquement — donc la source de
vérité est le flux des transactions, où `RegisterDomain` et
`AssignDomain` portent le nom canonique en clair) :

1. passe 1 : scan `blocks_by_height` genèse→tip, un bloc en RAM à la
   fois ; collecte des liaisons `nom → id` vues dans les
   `RegisterDomain`/`AssignDomain`/`RegisterTld` ;
2. passe 2 : filtrage des cibles **vivantes** uniquement (l'état
   persisté fait foi) — un domaine enregistré puis GC'd/expiré n'est
   pas réindexé ;
3. passe 3 : effacement + réécriture complète des deux tables dans
   UNE transaction (crash → ancien ou nouvel index complet).

Un bloc manquant ou indécodable → `Corrupted` (mêmes octets qui ont
bâti la chaîne). Le coût est O(nom distincts vus) en RAM (≤ 253 o
par nom) et O(blocs) en lectures — outil de réparation, pas un chemin
de boot.

### Ce que l'index n'est PAS

- Pas une autorité : l'état chaîne en RAM reste la seule autorité ;
  l'index est un cache reconstructible (une divergence est un bug de
  transactionnalité, détectable par `rebuild_name_index` comparé).
- Pas gelé dans le snapshot M6b : les tables `names_v3`/`name_reverse_v3`
  sont vivantes et suivent les deltas de chaque bloc ; le snapshot
  d'état ne les embarque pas (reconstruction par deltas à la reprise,
  ou `rebuild_name_index` en réparation).

### Ce que le snapshot n'engage PAS

L'état RAM `ChainState` porte des structures internes non engagées
par la consensus (clés d'owners, fenêtres de grâce). Elles ne sont
PAS gelées : le rejeu du suffixe les reconstruit par application des
transactions (déterministe, même contenu que le rejeu complet pour
la fenêtre concernée). L'index anti-replay TXID suit le même contrat
(M8, voir section précédente) : reconstruit au boot, jamais gelé.
L'égalité bit à bit avec `load_chain_replay` est vérifiée par test
sur l'état canonique (state_root V2 + SMT).

## Snapshot d'état VÉRIFIÉ — chunks + manifest + vérification crypto (P0.3)

Le snapshot M6b ci-dessus accélère le boot d'un nœud qui fait
confiance à son disque. P0.3 répond à un autre besoin : transporter
un état entre nœuds (bootstrap d'un nouveau nœud, réparation) sans
faire confiance au transport. Le format et la vérification vivent
dans `crates/scone-storage/src/verified_snapshot.rs` + la
reconstruction de racine dans
`crates/scone-blockchain/src/snapshot_verify.rs`.

### Modèle de confiance

Le snapshot porte l'état d'un bloc **finalisé** — un checkpoint
signé par le quorum du comité (`CheckpointData.state_root`, la
racine `state_root_smt` O(1)). L'authenticité du checkpoint
(quorum de signatures Ed25519) est validée par la couche chaîne
AVANT l'import. L'import lui-même vérifie l'adhérence
snapshot ↔ checkpoint par RECALCUL :

1. **hash de chaque page** : `blake3("SCONE-SNAP-PAGE-HASH" ‖
   encodage intégral de la page)` doit égaler le hash annoncé par le
   manifest (un octet falsifié → rejet) ;
2. **somme des entrées == compteurs** du manifest (une page
   manquante ou un compteur faux → rejet) ;
3. **racine SMT recalculée depuis les entrées importées ==
   `checkpoint.data.state_root`** — LA vérification
   cryptographique : l'état entier (domaines + TLDs) est re-plié
   dans un SMT neuf (`snapshot_verify::recompute_state_root`,
   feuilles `SCONE-LEAF-DOM-V2`/`SCONE-LEAF-TLD-V2` exactement
   comme le chemin vivant) et la racine doit égaler celle que le
   comité a signée. Un snapshot falsifié, tronqué ou incomplet est
   rejeté AVANT TOUTE ÉCRITURE ;
4. **cohérences structurelles** : `height`/`tip_hash`/`state_root`
   du manifest == ceux du checkpoint ; ids strictement croissants
   (pas de doublons) ; index de pages séquentiels ; bornes DoS
   (≤ 10 000 entrées/page, ≤ 2^20 pages, budget total).

Échec de vérification → `StorageError::SnapshotRejected`, le store
reste strictement inchangé (tout est vérifié avant la transaction
d'écriture).

### Format sérialisé (strict, big-endian, décodage sans pitié)

```text
manifest = "SCONE-SNAP-MAN-V1"
        ‖ height(8) ‖ tip_hash(32) ‖ state_root(32)
        ‖ page_count(4) ‖ domain_count(8) ‖ tld_count(8)
        ‖ page_hashes(page_count × 32)

page    = "SCONE-SNAP-PAGE-V1"
        ‖ index(4) ‖ height(8) ‖ state_root(32)      ← chaque page est
        ‖ entry_count(4) ‖ entries                     auto-identifiante

entry   = kind(0x01 domaine | 0x02 TLD) ‖ id(32) ‖ len(2) ‖ état
          (état = DomainStateBytes 57/89 o ou TldStateBytes 34 o —
           les formats de stockage canoniques existants, réutilisés)
```

Ordre des pages : toutes les entrées domaine (ids croissants),
puis toutes les entrées TLD (ids croissants) — l'ordre de la
pagination curseur du store. Chaque page porte `(index, hauteur,
state_root du checkpoint, entrées)` : une page seule sait à quel
snapshot elle appartient. Pages de 256 entrées à l'export
(`VERIFIED_SNAPSHOT_PAGE_ENTRIES`) ; bornes DoS à l'import.

### Export (`export_verified_snapshot(store, checkpoint)`)

Sérialise l'état du DERNIER CHECKPOINT FINALISÉ — pas la pointe.
Prérequis : le store détient un snapshot M6b persisté
(`snapshot_v3_*`) exactement à la hauteur du checkpoint (la fenêtre
`CHECKPOINT_KEEP`/`SNAPSHOT_INTERVAL` garantit qu'un tel état est
disponible régulièrement) ; l'ancre du bloc est RECALCULÉE depuis
les octets stockés et doit égaler `checkpoint.data.block_hash`.
Sinon → `StorageError::SnapshotUnavailable` (l'export est une
action explicite : attendre le prochain intervalle/checkpoint).

### Import (`import_verified_snapshot(store, checkpoint, manifest, pages)`)

Vérifie tout (voir ci-dessus), puis écrit dans UNE transaction
redb : tables vivantes `domains`/`tlds` + compteurs + `tip = (H,
hash du checkpoint)`, tables gelées `snapshot_v3_*` ancrées au même
bloc, et marqueur réservé `meta["verified_snapshot_v1"]`
(`height ‖ tip_hash ‖ manifest_hash`). Cible : store vide
uniquement (sinon `SnapshotUnavailable`).

### Coût de la vérification (documenté)

Reconstruction du SMT par insertions ordonnées : N entrées × O(40)
hachages ≈ O(N·40). ~2,1 M hachages blake3 pour 100 000 domaines
(dizaines de ms). PONCTUEL — un import de bootstrap/réparation,
jamais un chemin par bloc : acceptable. L'insertion ordonnée
(ids croissants) crée chaque point de branchement une seule fois ;
de toute façon la racine ne dépend que du contenu (garantie SMT,
fuzz différentiel dans `smt.rs`).

## Bootstrap d'état — sans rejeu genèse (P0.4)

Un nouveau nœud rejoint le réseau sans rejouer l'historique depuis
la genèse :

```text
finalized checkpoint (relay, validé par la couche chaîne)
        │
        ▼
verified snapshot (manifest + pages, vérification crypto ci-dessus)
        │  import → état à H + tip (H, hash) + marqueur
        ▼
bloc d'ancrage H (demandé au réseau PAR HASH — append_bootstrap_anchor)
        │
        ▼
blocs récents H+1..H+k (relay, hauteur croissante, append atomique
        │               ordinaire — l'API storage n'exige que ça)
        ▼
synced — boot rejoue SEULEMENT le suffixe au-dessus de H
```

- **API storage exposée au relay** : `append_bootstrap_anchor(H,
  hash, bytes)` (pose le bloc d'ancrage : marqueur requis,
  cohérence hauteur/hash avec le marqueur, idempotent) puis
  l'append atomique ordinaire par hauteur croissante. La
  récupération réseau (par hash depuis le manifest) est un concern
  du relay, pas du store.
- **`load_chain`** reconnaît le marqueur : l'historique sous H est
  légitimement absent (nœud non-archive). Concrètement : le
  rescan de la fenêtre anti-replay M8 est plancher à H (les blocs
  sous H n'existent pas et ne manquent pas) ; un tip sans bloc
  stocké APRÈS un import (ancre pas encore posée) → diagnostic
  typé `SnapshotUnavailable` (« l'ancre doit venir du réseau »),
  pas une corruption.
- **Nœud archive vs full-state** : un nœud archive (drapeau
  opérateur) continue de tout garder — il sert les blocs
  historiques au réseau et démarre par les chemins existants. Un
  nœud full-state (default P0.4 pour un nouveau nœud CONFIGURÉ
  ainsi) démarre à H : il valide les blocs futurs (rejeu de
  suffixe) mais ne peut servir l'historique sous H ni rejouer la
  genèse. **Le comportement par défaut ne change PAS** : ce chemin
  n'est actif que si l'opérateur déclenche explicitement
  l'import (`import_verified_snapshot` est une action dédiée,
  jamais automatique) ; tout nœud existant boote à l'identique.
- **Égalité avec le nœud complet** : après jonction du suffixe
  H+1..H+k, l'état, le tip et `state_root_smt` sont bit-exacts
  avec un nœud complet au même tip (testé) ; l'index anti-replay
  couvre exactement les txs à/au-dessus de H — un nœud non-archive
  ne peut pas connaître la fenêtre sous H, les règles d'état
  demeurent le garde-fou (une tx dupliquée sous H échoue sur
  l'état, jamais acceptée deux fois).

## Politique mémoire

- **Curseurs partout** : `iterate_domains` borne la page à `max`
  entrées (100 par défaut) via le `range` lazy de redb ; le tableau
  entier des domaines n'est jamais matérialisé. Les listes
  volumineuses (TLD, domaines) passent obligatoirement par ce curseur
  (`iterate_tlds`, même contrat, M7d).
- **Delta-only** : `append_block_with_state` n'écrit que les domaines
  et TLDs modifiés par le bloc — jamais l'état complet ;
- **Pas de duplication synchrone** : l'état RAM n'est pas re-persisté
  en bloc ; l'état disque n'est pas rechargé par bloc ;
- **Lectures ponctuelles** : chaque lecture ouvre une read
  transaction courte, rend la valeur, referme ; les `AccessGuard`
  redb ne vivent que le temps de la copie bornée ;
- **Blocs historiques jamais en RAM** : `load_chain` ne charge que le
  tip ; `load_chain_replay` streame hauteur par hauteur ;
- **Compteur maintenu** : `domain_count` est O(1), pas un scan.

## Bornes DoS

Le store borne ce qu'un pair hostile peut lui faire persister ou lui
faire allouer :

- **`MAX_DHT_CACHE_ENTRY` (64 KiB)** : un enregistrement DHT plus
  grand est rejeté avant toute transaction d'écriture par
  `put_dht_cache` → `StorageError::TooLarge` (rien n'est écrit) ;
- **`MAX_DOMAIN_PAGE` (10 000)** : `iterate_domains` borne
  *internement* la page demandée à `min(max, 10_000)` — un `max`
  démesuré ne matérialise jamais plus de 10 000 états en RAM ;
  `iterate_tlds` a la même borne (`MAX_TLD_PAGE`, M7d) ;
- **Clés `meta` réservées** : `meta_set` rejette `tip`,
  `tip_height`, `format_version`, `domain_count`, `tld_count` et
  `verified_snapshot_v1` (P0.3) avec `StorageError::ReservedKey` —
  écraser la comptabilité interne du store reviendrait à le
  corrompre silencieusement.

## Modèle de confiance

Deux chemins de chargement, deux niveaux de garantie :

- **`load_chain` — confiance disque local** : le hash du tip est
  **recalculé** depuis le header du bloc tip et comparé au
  `meta["tip"]` stocké (divergence → `StorageError::Corrupted`,
  jamais de chaîne restaurée sur un hash forgé), et les états de
  domaines sont décodés strictement. En revanche les blocs
  historiques ne sont **pas rejoués** : les états persistés sont
  crus tels quels. C'est le démarrage rapide d'un nœud qui fait
  confiance à son propre disque (écrit uniquement par ce même nœud,
  de façon atomique). Depuis M6b, ce chemin utilise d'abord le
  **snapshot d'état** quand il est utilisable (voir ci-dessous) :
  l'ancre du snapshot est recalculée et le suffixe au-dessus de H
  est revalidé comme des blocs vivants — la portion rejouée est
  donc de confiance zéro, le socle gelé de confiance disque.
- **`load_chain_replay` — confiance zéro** : tous les blocs sont
  relus et revalidés un par un (validation complète, identique aux
  blocs vivants) ; le tip obtenu doit égaler le tip stocké. C'est
  l'outil de contrôle/repair.

**Recommandation** : un nœud strict (ou un nœud dont le fichier de
stockage a pu être manipulé — disque partagé, restore d'une sauvegarde
douteuse) doit démarrer via `load_chain_replay`, pas `load_chain`.

## Concurrency

redb 4.x autorise **un seul objet `Database` par fichier et par
processus** (les doubles `open` simultanés échouent avec
`DatabaseAlreadyOpen`). Le modèle supporté : un `RedbStore` cloné
(`Arc<Database>`) partagé entre threads — writers sérialisés par
`&mut self` + verrou interne redb, readers concurrents (read
transactions snapshot). Après drop complet de tous les handles, le
fichier peut être ré-ouvert.

## Tests (`tests/redb_store.rs` + modules `#[cfg(test)]`)

Chaque test utilise son tmpfile redb (`tempfile`). Couverture :

- roundtrip blocs genèse→N, restart, relecture, rejeu ;
- M7d : registre TLD persisté par delta atomique, restauré au
  redémarrage (un `RegisterDomain` sous un TLD claimé avant le
  restart reste admissible — fermeture de la fenêtre), compteurs
  exacts à la réouverture, curseur `tlds` croissant, append échoué
  ne laisse aucun TLD, clé réservée `tld_count` rejetée ;
- atomicité : append échoué ne laisse rien (tip, domaines, index
  intacts) ; deltas dupliqués comptés une fois ;
- curseurs domains : pagination 100/7, ordre croissant `DomainId`,
  départ strictement après un id existant ou non, `max = 0` ;
- compteur `domain_count` exact (insert/update/reopen) ;
- cache DHT roundtrip + écrasement ;
- concurrence : lectures depuis deux threads sur des handles clonés ;
- base corrompue : fichier tronqué / garbage → erreur typée, aucune
  panic (`catch_unwind`) ;
- M6b : snapshot écrit à l'intervalle, strictement sous la pointe ;
  boot depuis snapshot = rejeu complet bit-exact (state_root V2 +
  SMT, état logique complet, tip) ; snapshot altéré (tip_hash
  corrompu, état indécodable, hauteur > pointe, méta de mauvaise
  longueur) → repli silencieux sur le chargement complet, même
  chaîne finale ; suffixe rejoué < intervalle ; remplacement (pas
  d'accumulation) du snapshot au franchissement de l'intervalle ;
  store pré-M6b sans tables snapshot charge à l'identique ;
- M8 : index anti-replay reconstruit au boot — une tx ré-incluse
  dans la fenêtre est rejetée (`TxReplay`) après restore ; une tx
  plus vieille que la fenêtre est admise (élagage inchangé, les
  règles d'état décident) ; comptage exact == index vivant (==
  `load_chain_replay`) pour un store plus court ET plus long que la
  fenêtre ; boot snapshot : la partie de la fenêtre sous H est
  reconstituée par le rescan, la partie au-dessus par le rejeu de
  suffixe ;
- P0.2 : index de noms — `resolve_name == DomainId::from_name` pour
  120 domaines (vivant, après restart, après wipe + rebuild),
  `resolve_tld` pour le TLD claimé ; le GC d'un domaine expiré
  supprime l'entrée (pas de fantômes), avant et après rebuild ;
  séparation stricte des espaces de noms domaine/TLD ; un append
  échoué ne laisse aucune entrée d'index ; la clé d'index est la
  dérivation BLAKE3 documentée ;
- P0.3/P0.4 (`tests/verified_snapshot.rs`) : export → import →
  boot == rejeu complet (état, tip, `state_root_smt` bit-exact ;
  l'état importé est celui du bloc finalisé, pas de la pointe) ;
  page falsifiée d'un octet → rejet avant toute écriture (store
  strictement inchangé) ; page manquante → rejet ; mauvais
  `state_root` (manifest ↔ checkpoint, puis racine recalculée ≠
  racine signée) → rejet ; compteurs faux / hauteurs / tip
  incohérents / doublons d'ids → rejet ; import exige un store
  vide ; export exige un snapshot persisté à la hauteur du
  checkpoint ; contrat de l'ancre (`append_bootstrap_anchor` :
  marqueur requis, cohérence, idempotence) ; format sérialisé
  strict (octets en excès, tags, bornes DoS) ; snapshot à H puis
  blocs H+1..H+k rejoint → chaîne identique au nœud complet
  (état/tip/racine), boot sans historique sous H, index
  anti-replay = txs à/au-dessus de H exactement.

[`ChainState`]: ../../../crates/scone-blockchain/src/state.rs
