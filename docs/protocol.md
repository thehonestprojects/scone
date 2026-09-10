# Protocol

Document de référence du protocole Scone : format binaire, encodage
canonique, transactions, records DNS, blocs, messages P2P, limites et
compatibilité de version. L'implémentation de référence est la crate
[`scone-protocol`](../crates/scone-protocol).

Les éléments marqués **(provisoire)** ne sont pas figés.

## Version du protocole

- constante : `PROTOCOL_VERSION: u32 = 1` (`scone-protocol`) ;
- transportée par `Hello.version` (handshake) et `BlockHeader.version` ;
- règles de compatibilité :
  - version reçue **supérieure** à la version locale → rejet
    (`ProtocolError::UnsupportedVersion`) ; le nœud ne devine pas le
    format d'une version qu'il ne connaît pas ;
  - version `0` → invalide ;
  - version inférieure → acceptée (aucune n'existe encore) ;
- pas de découpage majeur/mineur à ce stade : un entier unique,
  incrémenté à toute rupture de format wire.

## Principes du format binaire

- binaire, jamais JSON pour les données protocolaires ;
- déterministe et canonique : deux objets logiquement égaux produisent
  **exactement les mêmes octets** ;
- parsing séquentiel, sans allocation lorsque possible (emprunts
  d'octets) ;
- toutes les entrées réseau sont non fiables : longueurs et compteurs
  sont vérifiés **avant** toute allocation, le décodage ne panique
  jamais.

### Endianness

- tous les entiers sont des varints LEB128 (groupes de 7 bits, poids
  faible d'abord) : l'endianness native ne s'applique pas ;
- adresses IPv4/IPv6 et identifiants 32 octets : tableaux d'octets
  bruts, sans préfixe de longueur ;
- il n'existe aucun entier large à taille fixe dans le format : une
  seule règle d'encodage des entiers.

### Varint (LEB128 minimal)

Chaque octet porte 7 bits de donnée ; le bit de poids fort vaut 1 sur
tous les octets sauf le dernier. Un `u64` tient sur 1 à 10 octets.

| valeur | octets (hex) |
|---|---|
| 0 | `00` |
| 1 | `01` |
| 127 | `7f` |
| 128 | `80 01` |
| 255 | `ff 01` |
| 16 384 | `80 80 01` |
| 2^32 | `80 80 80 80 10` |
| u64::MAX | `ff ff ff ff ff ff ff ff ff 01` |

L'encodage doit être **minimal** : les formes surdimensionnées sont
rejetées au décodage (`InvalidVarint`). C'est la condition nécessaire
pour qu'une valeur n'ait qu'une seule séquence d'octets valide
(encodage canonique). Rejets : `80 00` (non minimal), `ff×9 02`
(dépassement u64), `ff×10` (trop long).

### Chaînes et octets

- `bytes` : varint longueur + octets bruts ;
- `str` : idem, avec décodage UTF-8 obligatoire ;
- chaque longueur est plafonnée (voir [Limites](#limites)) et vérifiée
  avant lecture.

### Identifiants

| Type | Représentation wire |
|---|---|
| `DomainId` | 32 octets nus |
| `OwnerId` | 32 octets nus |
| `PublicKeyRef` | 32 octets nus |
| `RecordHash` | 32 octets nus |
| `BlockHash` | 32 octets nus |
| `MerkleRoot` | 32 octets nus |
| `DomainName` | `str` (≤ 253 octets, revalidé par `scone-core`) |

Les dérivations (`BLAKE3-256` + préfixes `SCONE-DOMAIN-V1`, etc.)
restent définies par `scone-core` (voir `/docs/naming.md`).

## Transactions

```text
Transaction = disc u8 || payload
```

| Discriminant | Type |
|---|---|
| `0x01` | `Register` |
| `0x02` | `Update` |

### REGISTER (0x01)

```text
domain_id[32] owner[32] timestamp.v proof(bytes ≤ 256)
```

`proof` est opaque : réservé au futur PoW de registration. Les
invariants métier restent ceux de `scone-core`.

### UPDATE (0x02)

```text
domain_id[32] owner[32] sequence.v record_hash[32] timestamp.v
```

Invariant re-vérifié au décodage : `sequence > 0`. La transaction ne
porte que des références compactes — le contenu DNS complet reste dans
la DHT (voir ci-dessous).

## Records DNS (côté DHT)

Les enregistrements DNS complets n'entrent jamais dans la blockchain :
ils sont échangés via la DHT (messages `GetRecord`/`Record`) et
engagés sur la chaîne par leur `RecordHash` uniquement.

### RecordData

```text
RecordData = type.v || payload(type)
```

Les codes de type sont les **codes DNS réels** (IANA) :

| Code | Type | Payload |
|---|---|---|
| 1 | A | 4 octets |
| 2 | NS | `name` |
| 5 | CNAME | `name` |
| 15 | MX | `preference.v`, `name` |
| 16 | TXT | `str` ≤ 4096 |
| 28 | AAAA | 16 octets |
| autre | Unknown | code.v + `bytes` ≤ 4096 |

Exemple : `A 192.0.2.1` → `01 c0 00 02 01`.

Un `Unknown` portant un code connu est rejeté à l'encodage (le
décodage ne peut jamais en produire).

### DnsRecord

```text
domain_id[32] sequence.v expiration.v count.v(≤ 256) records…
```

**Règle canonique** : un record set est une collection sans ordre. Il
est encodé **trié par ordre lexicographique de l'encodage individuel
de chaque record**, strictement croissant (doublons rejetés). Un wire
non trié est rejeté au décodage (`NonCanonical`). L'ordre du `Vec`
d'origine n'est pas transporté.

### SignedDnsRecord

```text
DnsRecord owner[32] signature(bytes ≤ 128)
```

### RecordHash

```text
RecordHash = BLAKE3-256("SCONE-RECORD-V1" || canonical(DnsRecord))
```

Le hash couvre le **contenu du record seul** ; la signature du
propriétaire se vérifie séparément sur les mêmes octets canoniques.
*(Décision : l'engagement ne couvre pas la signature — une version
précédente de ce document mentionnait le « SignedDnsRecord complet » ;
coupler le hash à la signature n'apportait rien et liait le
commitment au schéma de signature.)*

## Blocs

### BlockHeader

```text
version.v height.v prev_hash[32] tx_root[32] timestamp.v consensus(bytes ≤ 256)
```

- `version` : version du protocole (règles ci-dessus) ;
- `height` : hauteur (genèse = 0) ;
- `prev_hash` : hash du bloc précédent (zéros pour la genèse) ;
- `tx_root` : engagement sur la liste des transactions (arbre de
  Merkle défini par `scone-blockchain`, voir `/docs/blockchain.md`) ;
- `timestamp` : information d'ordre (Unix, secondes) ;
- `consensus` : payload **opaque** réservé aux règles de consensus
  futures (champs PoW, difficulté…). Le protocole ne l'interprète pas ;
  seules sa borne et sa longueur sont garanties.

### Block

```text
BlockHeader tx_count.v(≤ 4096) transactions…
```

Parsing séquentiel ; le compteur est plafonné **avant** allocation ;
toute troncature est rejetée. Contrairement aux record sets, l'ordre
des transactions est **significatif** (ordre de consensus) et
préservé exactement.

`BlockHash` (hash du header canonique) et `tx_root` sont calculés par
`scone-blockchain` sur les encodages définis ici (formules exactes dans
`/docs/blockchain.md`).

## Messages P2P

```text
Message = disc u8 || payload
```

Le transport (framing, libp2p…) est hors périmètre ; une trame
transport ne devrait pas dépasser `MAX_MESSAGE_LEN` (1 Mio).

| Disc | Message | Direction | Payload | Limite | Réponse attendue |
|---|---|---|---|---|---|
| `0x01` | `Hello` | les deux | `version.v` | — | `Hello` |
| `0x02` | `Ping` | les deux | — | — | `Pong` |
| `0x03` | `Pong` | les deux | — | — | — |
| `0x04` | `GetBlock` | les deux | `hash[32]` | — | `Block` |
| `0x05` | `GetBlocks` | les deux | `start.v` `max.v` | `max ≤ 128` | ≤ `max` × `Block` |
| `0x06` | `Block` | les deux | `Block` | tx ≤ 4096 | — |
| `0x07` | `Transaction` | les deux | `Transaction` | — | — |
| `0x08` | `GetRecord` | les deux | `domain_id[32]` | — | `Record` |
| `0x09` | `Record` | les deux | `SignedDnsRecord` | — | — |

`TxId` est désormais défini par `scone-blockchain`
(`BLAKE3-256("SCONE-TX-V1" || canonical(Transaction))`, voir
`/docs/blockchain.md`). Différé volontairement : le message
`GetTransaction` et le mempool — leur définition dépend des décisions de
consensus.

## Répartition blockchain / DHT

```text
BLOCKCHAIN                      DHT
──────────                      ───
domain_id                       domain_id
owner                           SignedDnsRecord (complet, signé)
sequence
record_hash
```

La chaîne dit *qui* possède et *quel est l'état courant* (sequence +
record_hash). La DHT fournit *le contenu*. Un enregistrement DHT est
accepté si et seulement si :

1. sa signature est valide pour le propriétaire enregistré sur la chaîne ;
2. sa `sequence` est cohérente avec (ou supérieure à) celle de la chaîne ;
3. le `RecordHash` recalculé sur son encodage canonique correspond au
   `record_hash` de la chaîne.

## Limites

| Constante | Valeur | Rôle |
|---|---|---|
| `MAX_NAME_LEN` | 253 | longueur d'un nom |
| `MAX_TXT_LEN` | 4096 | chaîne TXT |
| `MAX_PROOF_LEN` | 256 | preuve d'enregistrement |
| `MAX_SIGNATURE_LEN` | 128 | signature (Ed25519 = 64) |
| `MAX_RECORDS_PER_SET` | 256 | records par ensemble |
| `MAX_UNKNOWN_DATA` | 4096 | données d'un type inconnu |
| `MAX_TXS_PER_BLOCK` | 4096 | transactions par bloc |
| `MAX_CONSENSUS_LEN` | 256 | payload consensus d'un header |
| `MAX_BLOCKS_PER_REQUEST` | 128 | blocs par `GetBlocks` |
| `MAX_MESSAGE_LEN` | 1 Mio | trame transport (recommandé) |

Tout dépassement → `LimitExceeded`, détecté avant allocation : un pair
malveillant ne peut pas provoquer d'allocation démesurée au décodage.

## Encodage canonique

Règle fondamentale :

```text
objet canonique → encodage binaire canonique → hash / signature
```

- varints minimaux uniquement ;
- record sets triés strictement croissants ;
- un objet logiquement égal a exactement **un seul** encodage valide ;
- le décodage rejette les formes non canoniques (`NonCanonical`), il
  n'existe donc pas plusieurs encodages valides pour un même objet.

## Gestion d'erreurs

`ProtocolError` (`scone-protocol::error`) :

| Variante | Signification |
|---|---|
| `Truncated` | entrée terminée au milieu d'une valeur |
| `InvalidVarint` | varint non minimal, débordant ou trop long |
| `IntegerOutOfRange` | entier ne tenant pas dans son type cible |
| `UnsupportedVersion` | version nulle ou supérieure à la locale |
| `UnknownDiscriminant` | discriminant de transaction/message inconnu |
| `LimitExceeded` | longueur ou compte au-delà d'une limite |
| `InvalidUtf8` | chaîne non UTF-8 |
| `TrailingBytes` | octets restants après une valeur complète |
| `Validation` | violation d'un invariant de `scone-core` |
| `NonCanonical` | encodage valide par champ mais non canonique |

Le décodage ne panique jamais sur des données réseau.

## Signatures (futur)

- schéma prévu : **Ed25519 (provisoire)** via `scone-crypto` ;
- le payload signé est l'encodage canonique produit par
  `scone-protocol` (ex. `DnsRecord` pour un `SignedDnsRecord`) ;
- la vérification croise `record + owner + signature` avec l'identité
  enregistrée dans la blockchain.

## Règles de consensus (futur)

Non définies. Sujets ouverts : algorithme (PoW/PoS/hybride), difficulté
du PoW de registration, frais anti-spam, résolution de conflits,
expiration/renouvellement des claims, rotation de clé propriétaire.
