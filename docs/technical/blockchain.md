# Blockchain

Document de référence de la couche blockchain : identités, hash, genèse,
état canonique, ordre des transactions et validation des blocs.
L'implémentation de référence est la crate
[`scone-blockchain`](../../crates/scone-blockchain), au-dessus de
`scone-protocol` (encodage canonique), `scone-core` (règles métier) et
`scone-crypto` (BLAKE3).

Périmètre actuel : logique blockchain **en mémoire**, sans consensus
concret ni réseau ni stockage (voir [Différé au consensus](#différé-au-consensus)).

## Identités et séparation des domaines de hash

Quatre identités, quatre rôles, quatre préfixes BLAKE3 distincts — un
préfixe n'est jamais réutilisé entre deux usages :

| Type | Rôle | Préfixe | Formule |
|---|---|---|---|
| `DomainId` | identité du nom de domaine | `SCONE-DOMAIN-V1` | voir `/docs/general/naming.md` |
| `RecordHash` | identité du contenu DNS | `SCONE-RECORD-V1` | voir `/docs/technical/protocol.md` |
| `TxId` | identité de la transaction | `SCONE-TX-V1` | ci-dessous |
| `BlockHash` | identité du bloc | `SCONE-BLOCK-V1` | ci-dessous |

Le Merkle tree utilise son propre préfixe `SCONE-MERKLE-V1`. À ces
préfixes s'ajoutent ceux de `scone-core` (`SCONE-PUBKEY-V1`,
`SCONE-OWNER-V1`).

Chaîne de dépendance complète :

```text
DomainId
    ↓
RegisterDomain / UpdateDomain
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
  `RegisterDomain`, replay de séquence), pas sur le `TxId`.

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

## Réseaux et genèse (M8b)

Scone définit deux réseaux disjoints, identifiés par un
`network_id` canonique (1..=16 octets ASCII `[a-z0-9-]`) :

| Réseau | `network_id` | difficulté TLD | difficulté domaine |
|---|---|---|---|
| testnet | `scone-testnet` | 8 bits (symbolique) | 4 bits (symbolique) |
| mainnet | `scone-mainnet` | 24 bits | 20 bits |

Les paramètres vivent dans `scone-core::network::NetworkParams`
(instances nommées `TESTNET` / `MAINNET`, lookup
`NetworkParams::by_name`). Changer une difficulté = changement de
consensus **pour ce réseau**.

La genèse est une constante de protocole **par réseau**, reproductible
à partir des constantes seules (aucun aléa, aucune horloge locale,
aucun réseau) :

| Champ | Valeur |
|---|---|
| `version` | `PROTOCOL_VERSION` (`1`) |
| `height` | `0` |
| `prev_hash` | 32 octets nuls (aucun bloc précédent) |
| `tx_root` | Merkle root de la liste vide |
| `timestamp` | `GENESIS_TIMESTAMP = 0` (puriquement structurel) |
| `consensus` | les octets canoniques du `network_id` |
| transactions | vide |

Le `network_id` dans le payload consensus rend les hashs de genèse —
et donc toute la chaîne de blocs — **disjoints entre réseaux** : un
bloc testnet ne peut jamais s'attacher à une chaîne mainnet
(`UnknownParent`), aucun replay n'est possible sans tout re-signer.

API : `genesis_of(&NetworkParams) -> Block`,
`genesis_hash_of(NetworkId) -> BlockHash` ; les alias `genesis()` /
`genesis_hash()` désignent la testnet (défaut de développement).

## État canonique

```text
DomainState  = { owner: OwnerId, sequence: u64, record_hash: Option<RecordHash>,
                 registered_at: u64, valid_until: u64 }
TldState     = { owner: OwnerId, open: bool }
ChainState   = NetworkParams                  (réseau lié, M8b)
               + DomainId -> DomainState      (accès direct, en mémoire)
               + TldId -> TldState            (registre TLD, M7b)
               + DomainId -> (expired_at, OwnerId)   (fenêtres de grâce, M8b)
```

* `registered_at` / `valid_until` (M8b) : l'expiration de
  l'enregistrement, évaluée contre le **timestamp du bloc parent**
  (déterministe, engagé dans le header — jamais l'horloge locale) ;
* `open` (M8b) : `false` à la claim (fermé = assign-only), `true`
  après un `SetTldOpen` (auto-enregistrement avec PoW) ;

- accès direct par `DomainId` (32 octets) : jamais de `String` comme
  clé, jamais de scan complet — condition nécessaire pour viser des
  centaines de milliards de domaines ;
- `record_hash == None` tant qu'aucun `UpdateDomain` n'a été appliqué ;
- les espaces d'ids TLD et domaine sont **disjoints par construction**
  (préfixes de dérivation distincts, voir `/docs/general/naming.md`) :
  enregistrer le TLD `uip` ne peut jamais squatter l'identité d'un
  domaine, ni l'inverse.

### Règles d'application

`state.apply(transaction)` est déterministe et atomique (en cas
d'erreur, l'état est inchangé) :

**Toutes les transactions (M8b)** : le champ `network` de la
transaction doit être **exactement** le `network_id` de la chaîne —
sinon `WrongNetwork { tx, chain }`, AVANT toute autre règle (une tx
testnet n'est jamais appliquée, jamais poolée par un nœud mainnet, et
inversement).

**REGISTER_TLD** :

- le TLD doit être **libre** (absent du registre TLD) ;
- **PoW obligatoire** : `pow::verify` sur le challenge
  `SCONE-TLD-V1 || tld` (dérivé du nom porté par la tx) à la
  difficulté `tld_pow_difficulty` du réseau — le digest est
  recalculé de zéro (`SCONE-POW-V1 || network || challenge || nonce`),
  la difficulté auto-déclarée doit égaler la constante réseau ;
- à l'application : `{ owner, open: false }` — **fermé par défaut**
  (assign-only) ; l'ouverture est explicite via `SetTldOpen`.

**REGISTER (RegisterDomain)** :

- **le TLD du nom porté doit être enregistré ET ouvert** : la chaîne
  dérive elle-même `TldId(nom.tld())` (jamais une valeur fournie) ;
  absent → `UnknownTld` (D1, M7c), présent mais fermé → `TldClosed`
  (M8b : le chemin assign-only est exclusif) ;
- le domaine doit être **libre** : absent de l'état ET hors de toute
  fenêtre de grâce d'un enregistrement expiré (voir GC ci-dessous) ;
- **PoW obligatoire** : challenge `SCONE-DOMAIN-V1 || nom` à la
  difficulté `domain_pow_difficulty` (le TLD étant ouvert, c'est le
  prix d'entrée auto-service) ;
- à l'application : `{ owner, sequence: 0, record_hash: None,
  registered_at: now, valid_until: now + 1 an }` — **l'enregistrement
  dure 1 an** (365 jours).

**Ordre intra-bloc** : significatif. `[RegisterTld, SetTldOpen,
RegisterDomain]` dans un même bloc est valide ; toute permutation qui
applique une règle avant que sa précondition existe est rejetée en
bloc entier (undo-log).

**UPDATE (UpdateDomain)** :

- le domaine doit exister (non expiré) ;
- `tx.owner` doit être le propriétaire actuel ;
- `tx.sequence` doit être **exactement** `sequence_courante + 1`
  (aucun trou, aucun replay) ;
- à l'application : `sequence` avance, `record_hash` est remplacé.

**TRANSFER_TLD (0x47)** :

- le TLD doit exister (`UnknownTld` sinon) ;
- le signataire doit être l'owner courant (`NotTldOwner` sinon) ;
- à l'application : `owner = new_owner` (l'identité du destinataire
  est opaque ; le binding aux clés qui peuvent la dépenser se fait
  par les tx suivantes). Pas de séquence : premier transfert appliqué
  gagne (ordre de chaîne).

**REVOKE_TLD (0x6B)** :

- le TLD doit exister, signataire = owner courant ;
- à l'application : le TLD est retiré du registre et re-claimable par
  un `RegisterTld` frais (PoW compris).

**SET_TLD_OPEN (0xB8)** :

- le TLD doit exister, signataire = owner courant ;
- à l'application : `open = tx.open`.

**ASSIGN_DOMAIN (0xD4)** :

- le TLD du nom porté doit exister (ouvert ou fermé — l'owner peut
  toujours assigner), signataire = owner du TLD (`NotTldOwner`) ;
- le domaine doit être libre (même règle de grâce que REGISTER) ;
- à l'application : `{ owner: assignee, sequence: 0, record_hash:
  None, registered_at: now, valid_until: now + 1 an }`. **Pas de
  PoW** : c'est l'owner du namespace qui se porte garant.

**RENEW_DOMAIN (0x3C)** :

- le domaine doit exister, signataire = owner courant ;
- `valid_until` doit **strictement étendre** l'échéance courante
  (`RenewalNotExtending` sinon) ;
- `valid_until ≤ now + 3 ans` (`RenewalExceedsTerm` — borne
  anti-thésaurisation : **1 terme de renouvellement = 1 an,
  3 ans d'avance maximum**) ;
- à l'application : `valid_until = tx.valid_until`.

**GC déterministe (M8b)** : avant l'application des transactions
d'un bloc, la chaîne évalue les expirations au **timestamp du bloc
parent** : tout domaine dont `valid_until ≤ now` est retiré de l'état
vivant et parqué dans une **fenêtre de grâce de 30 jours**
(`valid_until + 30 j`). Pendant la grâce, seul l'ancien owner peut
re-réclamer le nom ; après, il est libre pour tous. Le GC est
journalisé : un bloc rejeté restaure l'état pré-GC bit à bit.

**Replay** : le replay cross-réseau est impossible à trois niveaux —
genesis disjointes (`UnknownParent`), champ `network` signé dans
chaque payload de signature (`WrongNetwork` + signature invalide),
PoW séparé par réseau dans le digest. Le replay intra-réseau d'une
tx identique échoue sur les règles d'état (double claim, séquence),
jamais sur le `TxId`.

Deux nœuds du même réseau partant du même état et appliquant les
mêmes blocs dans le même ordre produisent exactement le même état
final.

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
3. `version` == `PROTOCOL_VERSION` **exactement** (toute autre
   version — inférieure ou supérieure — est rejetée, pas
   réinterprétée) ;
4. nombre de transactions ≤ `MAX_TXS_PER_BLOCK` (4096) ;
5. `tx_root` recalculé sur les transactions dans l'ordre du bloc ;
6. crochets du consensus (`validate_header`, `validate_tx`) ;
7. pour chaque transaction, dans l'ordre : validation
   **cryptographique** (`validate_transaction` : binding
   owner/clé recomputé + `verify_strict` sur le payload signé
   recomputé de zéro, voir `/docs/technical/transactions.md`), puis
   application à l'état canonique sous **journal d'annulation**
   (undo-log : une entrée par transaction appliquée, coût
   O(transactions du bloc) et non O(domaines)) ;
8. commit atomique : tout passe ⇒ bloc ajouté, journal jeté ; la
   moindre erreur ⇒ rembobinage du journal (ordre inverse) et chaîne
   rigoureusement inchangée, bit à bit.

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

- **fork choice** : sélection entre pointes concurrentes, reorg ;
- **mempool** : admission, remplacement, frais ;
- **ordering global** : autorité de tri, tie-break final ;
- **timestamp authority** au-delà du GC : les expirations (M8b)
  utilisent le timestamp du bloc parent ; d'autres règles de temps
  (anti-replay fin) restent au consensus ;
- stockage distribué : l'état est en mémoire ; le backend
  (`scone-storage`, redb) applique ces règles sans les dupliquer.

Livré depuis M8b (auparavant différé) : PoW de registration par
réseau (`RegisterTld` toujours, `RegisterDomain` sur TLD ouvert),
expirations/renouvellement 1 an + grâce 30 j + horizon 3 ans, GC
déterministe au timestamp du bloc parent, replay cross-réseau
impossible (genesis + champ signé + digest PoW).
