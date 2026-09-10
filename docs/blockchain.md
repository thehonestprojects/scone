# Blockchain

Document de référence de la couche blockchain : identités, hash, genèse,
état canonique, ordre des transactions et validation des blocs.
L'implémentation de référence est la crate
[`scone-blockchain`](../crates/scone-blockchain), au-dessus de
`scone-protocol` (encodage canonique), `scone-core` (règles métier) et
`scone-crypto` (BLAKE3).

Périmètre actuel : logique blockchain **en mémoire**, sans consensus
concret ni réseau ni stockage (voir [Différé au consensus](#différé-au-consensus)).

## Identités et séparation des domaines de hash

Quatre identités, quatre rôles, quatre préfixes BLAKE3 distincts — un
préfixe n'est jamais réutilisé entre deux usages :

| Type | Rôle | Préfixe | Formule |
|---|---|---|---|
| `DomainId` | identité du nom de domaine | `SCONE-DOMAIN-V1` | voir `/docs/naming.md` |
| `RecordHash` | identité du contenu DNS | `SCONE-RECORD-V1` | voir `/docs/protocol.md` |
| `TxId` | identité de la transaction | `SCONE-TX-V1` | ci-dessous |
| `BlockHash` | identité du bloc | `SCONE-BLOCK-V1` | ci-dessous |

Le Merkle tree utilise son propre préfixe `SCONE-MERKLE-V1`. À ces
préfixes s'ajoutent ceux de `scone-core` (`SCONE-PUBKEY-V1`,
`SCONE-OWNER-V1`).

Chaîne de dépendance complète :

```text
DomainId
    ↓
Register / Update
    ↓
Transaction
    ↓
TxId
    ↓
MerkleRoot
    ↓
BlockHeader
    ↓
BlockHash
    ↓
prev_hash du bloc suivant
    ↓
chaîne canonique
```

## TxId

```text
TxId = BLAKE3-256("SCONE-TX-V1" || canonical_encode(Transaction))
```

- déterministe : même transaction (même encodage canonique) ⇒ même
  `TxId`, sur tous les nœuds, pour toujours ;
- identité **par contenu** : tout champ modifié change le `TxId`
  (domaine, owner, timestamp, proof, sequence, record_hash) ;
- aucun timestamp local ni valeur non canonique n'entre dans le calcul ;
- aucune dépendance au stockage ou au réseau ;
- l'identité ne garantit pas l'unicité d'application : rejouer une
  transaction identique échoue sur les règles d'état (double
  `Register`, replay de séquence), pas sur le `TxId`.

API : `scone_blockchain::transaction_id(&Transaction) -> Result<TxId>`.

## Merkle tree (tx_root)

Engagement sur la **liste ordonnée** des transactions d'un bloc :

```text
0 transaction   root = BLAKE3-256("SCONE-MERKLE-V1" || "EMPTY")
feuille         BLAKE3-256("SCONE-MERKLE-V1" || 0x00 || TxId)
nœud interne    BLAKE3-256("SCONE-MERKLE-V1" || 0x01 || left || right)
niveau impair   le dernier hash est dupliqué pour compléter la paire
```

Règles :

- **jamais de tri** : l'ordre des transactions d'un bloc est
  significatif ; deux blocs contenant les mêmes transactions dans un
  ordre différent ont des racines différentes ;
- les tags `0x00` / `0x01` empêchent toute confusion entre feuille et
  nœud interne (second-preimage) ;
- le préfixe `SCONE-MERKLE-V1` isole l'arbre des autres domaines de
  hash (un `TxId` ne peut pas être interprété comme un nœud) ;
- implémentation maison (~30 lignes), déterministe et testée ; aucune
  bibliothèque Merkle externe.

API : `merkle_root(&[TxId]) -> MerkleRoot` et
`tx_root(&[Transaction]) -> Result<MerkleRoot>`.

## BlockHash

```text
BlockHash = BLAKE3-256("SCONE-BLOCK-V1" || canonical_encode(BlockHeader))
```

Le hash ne couvre **que** le header canonique : les transactions y sont
déjà engagées par `tx_root`, elles ne sont donc pas hashées une seconde
fois :

```text
transactions -> TxIds -> MerkleRoot -> BlockHeader -> BlockHash
```

Modifier une transaction, leur ordre, la hauteur, le timestamp, le
`prev_hash` ou le payload consensus change le `BlockHash`.

API : `block_hash(&BlockHeader) -> Result<BlockHash>`.

## Genèse

La genèse est une constante de protocole, reproductible à partir des
constantes seules (aucun aléa, aucune horloge locale, aucun réseau) :

| Champ | Valeur |
|---|---|
| `version` | `PROTOCOL_VERSION` (`1`) |
| `height` | `0` |
| `prev_hash` | 32 octets nuls (aucun bloc précédent) |
| `tx_root` | Merkle root de la liste vide |
| `timestamp` | `GENESIS_TIMESTAMP = 0` (puriquement structurel) |
| `consensus` | vide |
| transactions | vide |

API : `genesis() -> Block`, `genesis_hash() -> BlockHash` (identiques
sur tous les nœuds).

## État canonique

```text
DomainState  = { owner: OwnerId, sequence: u64, record_hash: Option<RecordHash> }
ChainState   = DomainId -> DomainState        (accès direct, en mémoire)
```

- accès direct par `DomainId` (32 octets) : jamais de `String` comme
  clé, jamais de scan complet — condition nécessaire pour viser des
  centaines de milliards de domaines ;
- `record_hash == None` tant qu'aucun `Update` n'a été appliqué.

### Règles d'application

`state.apply(transaction)` est déterministe et atomique (en cas
d'erreur, l'état est inchangé) :

**REGISTER** :

- le domaine doit être **libre** (absent de l'état) ;
- à l'application : `{ owner, sequence: 0, record_hash: None }` ;
- la `proof` n'est **pas** interprétée ici : sa validation (PoW de
  registration) est un crochet du consensus (différé).

**UPDATE** :

- le domaine doit exister ;
- `tx.owner` doit être le propriétaire actuel ;
- `tx.sequence` doit être **exactement** `sequence_courante + 1` (aucun
  trou, aucun replay ; après `Register`, le premier `Update` valide
  porte `sequence = 1`) ;
- à l'application : `sequence` avance, `record_hash` est remplacé.

Deux nœuds partant du même état et appliquant les mêmes blocs dans le
même ordre produisent exactement le même état final.

## Ordre des transactions

L'ordre est une propriété fondamentale, engagée à chaque niveau :

```text
ordre des transactions dans le bloc
    ↓
MerkleRoot
    ↓
BlockHash
    ↓
chaîne canonique
```

Deux transactions ne sont pas interchangeables : dans un même bloc,
`[REGISTER, UPDATE]` s'applique, `[UPDATE, REGISTER]` est rejeté
(domaine inexistant au moment de l'`UPDATE`). Le tie-break global
(qui ordonne le mempool, qui produit le bloc) appartient au consensus.

## Validation d'un bloc (push_block)

Tout est **recalculé**, rien n'est cru sur parole — un `tx_root`, un
hash, une signature ou un champ fourni par un pair n'est jamais pris
pour argent comptant :

1. `prev_hash` == hash de la pointe canonique (sinon `UnknownParent`
   si le parent est inconnu, `ParentNotTip` s'il est connu mais pas la
   pointe : détection de fork minimale) ;
2. `height` == hauteur pointe + 1 ;
3. `version` == `PROTOCOL_VERSION` **exactement** (un bloc v1 —
   format antérieur aux transactions signées — est rejeté, pas
   réinterprété) ;
4. nombre de transactions ≤ `MAX_TXS_PER_BLOCK` (4096) ;
5. `tx_root` recalculé sur les transactions dans l'ordre du bloc ;
6. crochets du consensus (`validate_header`, `validate_tx`) ;
7. pour chaque transaction, dans l'ordre : validation
   **cryptographique** (`validate_transaction` : binding
   owner/clé recomputé + `verify_strict` sur le payload signé
   recomputé de zéro, voir `/docs/transactions.md`), puis
   application à un état de travail ;
8. commit atomique : tout passe ⇒ bloc ajouté, état remplacé ; la
   moindre erreur ⇒ chaîne rigoureusement inchangée.

Aucune fonction de validation ne panique ; toute entrée malformée ou
hostile produit une `BlockchainError` typée
(`OwnerKeyMismatch`, `InvalidSignature`, …).

## Assemblage de blocs (BlockBuilder)

`BlockBuilder` (`scone-blockchain::builder`) assemble un bloc depuis
une queue de transactions validées :

```text
BlockBuilder::after(hauteur_parent, prev_hash)
    .with_timestamp(t) .with_consensus(payload)
    .push_tx(tx)… .build() -> Block
```

- `tx_root` **recalculé** sur la liste ordonnée des transactions
  queued (jamais fourni) ;
- `prev_hash`/`height` chaînés sur le parent (le hash parent est
  calculé par l'appelant via `block_hash`, jamais pris d'un pair) ;
- `version` = `PROTOCOL_VERSION` ;
- borne `MAX_TXS_PER_BLOCK` appliquée à l'ajout
  (`TooManyTransactions`) ;
- le payload `consensus` (champs PoW futurs) et le `timestamp` sont
  fournis par l'appelant : le consensus concret s'insère via le trait
  [`Consensus`](#abstraction-du-consensus) existant, symétriquement à
  la validation.

Un bloc assemblé passe `push_block` sans réencodage (testé).

## Forks

Traitement minimal, volontairement sans algorithme de fork choice :

- parent inconnu → `UnknownParent` (le bloc attend, il n'est ni accepté
  ni canonique) ;
- parent connu mais non-pointe → `ParentNotTip` (branche concurrente
  refusée par cette implémentation linéaire) ;
- hauteur logique = `height` du header, vérifiée == pointe + 1 ;
- aucun bloc reçu n'est canonique avant validation complète.

La structure interne (hashes connus, chaîne linéaire + état) permet
d'ajouter ultérieurement le suivi multi-branches et la sélection de
branche.

## Abstraction du consensus

```rust
pub trait Consensus {
    fn validate_header(&self, header: &BlockHeader) -> Result<()>;
    fn validate_tx(&self, tx: &Transaction) -> Result<()>;
}
```

- `PermissiveConsensus` (défaut) : accepte tout — utilisé tant que les
  règles réelles ne sont pas définies ;
- les crochets sont appelés par `push_block` : le consensus concret
  (PoW, difficulté, frais, timestamp/anti-replay, fork choice)
  s'insérera sans réécrire la chaîne ;
- une seule abstraction, pas de hiérarchie de traits.

## Différé au consensus

Volontairement non définis dans cette crate :

- **PoW** : RandomX ou autre, difficulté (notamment PoW lourd pour les
  TLD / registration coûteuse, `UPDATE` léger — à l'étude) ;
- **fork choice** : sélection entre pointes concurrentes, reorg ;
- **mempool** : admission, remplacement, frais ;
- **ordering global** : autorité de tri, tie-break final ;
- **timestamp authority / anti-replay** : les champs `timestamp`
  existent dans le format mais aucune règle ne les contraint encore ;
- **validation de la `proof` de `Register`** : crochet prêt, règles à
  venir ;
- expiration / renouvellement des claims de domaine ;
- stockage : l'état est en mémoire ; le backend (`scone-storage`,
  redb puis KV distribué) viendra sans changer ces règles.
