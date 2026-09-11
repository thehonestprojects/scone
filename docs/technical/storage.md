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
- `meta_get` / `meta_set`.

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
| `meta` | `&[u8]` | `&[u8]` |

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
8. `tip` et `tip_height`.

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
  servis depuis lui.
- `load_chain_replay(store)` : rejoue tous les blocs stockés un par un
  (jamais tous en RAM) avec la validation complète ; le tip obtenu
  doit égaler le tip stocké, sinon `Corrupted`.
- `touched_domains(block)` : ids des domaines modifiés par les
  transactions du bloc, dédupliqués, ordre du bloc.
- `touched_tlds(block)` : ids des TLDs mutés par le bloc
  (`RegisterTld`, `TransferTld`, `RevokeTld`, `SetTldOpen`),
  dédupliqués, ordre du bloc (M8b).
- `store_block_with_removals(...)` : variante de `store_block`
  recevant aussi les domaines retirés par le GC du bloc (M8b) pour
  l'écriture atomique décrite ci-dessus.

Le relay (M4) utilisera : `load_chain` au démarrage, puis pour chaque
bloc accepté `push_block` (RAM) puis `store_block` (disque).

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
  `tip_height`, `format_version`, `domain_count` et `tld_count`
  avec `StorageError::ReservedKey` — écraser la comptabilité
  interne du store reviendrait à le corrompre silencieusement.

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
  de façon atomique).
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
  panic (`catch_unwind`).

[`ChainState`]: ../../../crates/scone-blockchain/src/state.rs
