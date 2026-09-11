# Architecture

## Principe directeur

Scone sépare l'autorité de la disponibilité :

- la **blockchain** est la source de vérité pour la propriété et l'ordre des changements ;
- la **DHT** est un système de distribution/réplication, ce n'est **pas** une autorité ;
- le **stockage local** porte l'état du nœud, ses index et ses caches.

Un nœud doit considérer toute donnée venue de la DHT comme potentiellement
malveillante : elle n'est acceptée qu'après vérification cryptographique
(signature du propriétaire, concordance avec l'ownership / sequence /
record_hash de la chaîne).

## Séparation des responsabilités

```text
BLOCKCHAIN
──────────
Ownership
Registration
Authorization
Ordering
Sequence
Record hash
Consensus information

DHT
───
DNS records
Signed records
Replication
Availability

LOCAL STORAGE
─────────────
Local state
Indexes
Cached DHT records
Blockchain state
```

## Crates et dépendances

```text
scone-crypto    ← couche la plus basse : primitives pures sur octets
    ▲
scone-core      ← types du protocole (dépend de scone-crypto)
    ▲
scone-protocol  ← format binaire wire/blockchain
    ▲
scone-blockchain← logique blockchain, état canonique (en mémoire)
    ▲
scone-storage   ← abstraction stockage local (à venir)
    ▲
scone           ← binaire / application
```

### Décision : `scone-core` dépend de `scone-crypto`

Le `DomainId` doit être calculable dès le socle
(`BLAKE3-256(préfixe || nom canonique)`), mais la cryptographie concrète ne
doit pas contaminer le core. Résolution :

- `scone-crypto` est la couche la plus basse : fonctions purement
  déterministes sur octets, zéro type du core, aucune dépendance
  réseau/système → aucune circularité possible ;
- `scone-core` ne l'utilise que pour le hachage ;
- plus tard, signatures et clés vivront dans `scone-crypto` et opéreront
  sur des octets (payloads canoniques produits par `scone-protocol`).

### Rôle de chaque crate

**scone-core** — noms (`TldName`, `DomainName`), identifiants (`DomainId`,
`OwnerId`, `PublicKeyRef`), données DNS (`DnsRecord`, `SignedDnsRecord`),
transactions (`RegisterDomain`, `UpdateDomain`). Déterministe et portable. Interdits
dans ce crate : libp2p, redb, tokio/async, réseau, fichiers, OS, serveur
DNS, logique blockchain.

**scone-crypto** — primitives cryptographiques. Aujourd'hui : `hash256`
(BLAKE3). Prévu : signatures (Ed25519), clés, proof of work, Merkle tree.
Règle : aucun algorithme maison, dépendances auditées uniquement.

**scone-protocol** — format binaire du protocole : encodage/décodage
canonique (varint LEB128 minimal, identifiants 32 octets nus) des
transactions, records DNS, blocs (`Block`/`BlockHeader` au champ
consensus opaque) et messages P2P, avec limites de taille vérifiées
avant allocation, rejet des formes non canoniques et versionnement
(`PROTOCOL_VERSION`). Aucune logique de consensus, de réseau ou de
stockage. Référence du format : `/docs/technical/protocol.md`.

**scone-blockchain** — logique blockchain et état canonique :
identification des transactions (`TxId`), arbre de Merkle ordonné,
`BlockHash`, genèse déterministe, validation des blocs et transactions,
règles d'application à l'état (`DomainState`/`ChainState`, en mémoire,
accès direct par `DomainId`), détection minimale de forks et
abstraction du consensus (`trait Consensus`, impl permissive par
défaut). Interdits dans ce crate : réseau, DHT, stockage (redb),
serveur DNS, consensus concret (PoW/difficulté/fork choice). Référence :
`/docs/technical/blockchain.md`.

**scone-storage** — abstraction de stockage local. Le backend concret sera
`redb`, caché derrière un trait minimal afin que blockchain/DHT/DNS ne
soient jamais couplés directement à redb ; un autre backend (KV distribué)
pourra être branché. Le trait naîtra avec la première implémentation
réelle.

**scone** — binaire/CLI. Ne dépend d'une crate que lorsqu'il l'utilise
réellement (aujourd'hui : aucune).

## Le nœud (futur)

Un nœud Scone combine :

1. une blockchain (validation du consensus, état d'ownership) ;
2. un routage DHT (publication/récupération des `SignedDnsRecord`) ;
3. un stockage local (état, index, caches) ;
4. un resolver / serveur DNS en façade.

## Flux de résolution DNS (futur, provisoire)

```text
requête DNS (example.uip)
    │
    ▼
Node : DomainId = BLAKE3-256("SCONE-DOMAIN-V1" || "example.uip")
    │
    ├── cache local (SignedDnsRecord) ──► vérification (signature, owner,
    │                                      sequence, record_hash vs chaîne)
    ├── DHT get(DomainId) ──────────────► même vérification
    ▼
réponse DNS (si et seulement si valide)
```

## Évolutivité

- préimages versionnées (`SCONE-DOMAIN-V1`, `SCONE-PUBKEY-V1`,
  `SCONE-OWNER-V1`, …) : changer une règle de dérivation crée un nouvel
  espace de noms plutôt que de casser l'existant ;
- `RecordData` extensible par variants + `Unknown { type_code, data }`
  pour les types non connus à la lecture ;
- `PROTOCOL_VERSION` (`scone-protocol`) pour les ruptures de format wire ;
- la chaîne ne stocke que des hashs : les données volumineuses restent
  en DHT.
