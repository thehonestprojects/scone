# Transactions signées (format v1)

Document de référence **normatif** du format de transaction signée.
Il spécifie les champs, l'ordre wire exact, les tailles, le payload
signé et les règles de validation, de manière à permettre une
implémentation indépendante sans lire le Rust. L'implémentation de
référence est [`scone-protocol`](../../crates/scone-protocol)
(encodage) et [`scone-blockchain`](../../crates/scone-blockchain)
(validation).

`PROTOCOL_VERSION` = **1**. Il n'existe qu'un seul ensemble de
formats : tout octet de version autre que `0x01` (dans une
transaction) ou différent de la version locale (dans un bloc) est
rejeté avec `UnsupportedVersion`.

## Vue d'ensemble

```text
Transaction = disc u8 || version u8 || payload
```

| Champ | Taille | Rôle |
|---|---|---|
| `disc` | 1 o | type de transaction (table ci-dessous) |
| `version` | 1 o | **exactement `0x01`** (version du format tx) |

Depuis M8b, **le premier champ de chaque payload est le
`network_id`** (`str` ≤ 16, ASCII `[a-z0-9-]` — ex. `scone-testnet`,
13 octets) : c'est un champ **signé** (couvert par le payload de
signature) et séparé par réseau dans le digest PoW. Une transaction
construite pour un réseau ne vérifie jamais sur un autre (voir
`/docs/technical/blockchain.md` — réseaux et genèse).

### Discriminants (table normative)

Chaque discriminant est une **constante opaque, fixe et arbitraire** :
les valeurs sont choisies distinctes exprès, pour que le wire ne
suggère **jamais** d'ordre logique entre les types (aucune suite
0x01/0x02/0x03…). `0x00` n'est **jamais** un type valide (octet de
corruption typique). Les types futurs prendront toute valeur libre
non utilisée, documentée une fois pour toutes dans cette table.

| Discriminant | Type | Rôle |
|---|---|---|
| `0x21` | `RegisterDomain` | claim d'un domaine |
| `0x52` | `UpdateDomain` | nouvelle version des données DNS d'un domaine |
| `0x93` | `RegisterTld` | claim d'un top-level domain (M7) |
| `0x47` | `TransferTld` | transfert d'un TLD à un nouvel owner (M8a) |
| `0x6B` | `RevokeTld` | abandon d'un TLD (M8a) |
| `0xB8` | `SetTldOpen` | ouverture/fermeture d'un TLD à l'auto-enregistrement (M8a) |
| `0xD4` | `AssignDomain` | assignation directe d'un domaine par l'owner du TLD (M8a) |
| `0x3C` | `RenewDomain` | prolongation de l'enregistrement d'un domaine (M8a) |
| `0x15` | `SlashTx` | preuve d'équivocation d'un anchor + bannissement (M9) |

Tout octet de version autre que `0x01` est rejeté explicitement
(`UnsupportedVersion(valeur reçue)`) : un format inconnu ou obsolète
n'est jamais analysé par accident.

## SLASH_TX (0x15, M9)

Preuve on-chain qu'un anchor a signé deux checkpoints
**conflictuels à la même epoch** (équivocation). Chacun peut la
soumettre — la preuve est cryptographique et autonome :

```text
network | offender[32] | evidence_a (CheckpointData 116 o)
  | sig_a[64] | evidence_b (CheckpointData) | sig_b[64]
  | reporter_pk[32] | reporter_signature[64]
```

- `validate()` vérifie la structure : même epoch, `signing_hash`
  distincts, deux signatures distinctes, signatures du reporter sur
  le payload canonique ;
- règles d'état (journalisées, annulables au reorg) : les DEUX
  signatures de l'accusé doivent vérifier sur les DEUX signing hashes
  distincts à la même epoch ; l'accusé doit être dans le pool
  éligible (`SlashOffenderNotInPool` sinon) ; puis **bannissement**
  — la clé est retirée du pool PoS de façon persistante (liste noire
  dans l'état) ;
- sanction minimale : les domaines/TLD de l'accusé ne sont PAS saisis
  (décision M9 documentée) ;
- même checkpoint deux fois = pas une équivocation (rejet) ; epochs
  différentes = rejet ; signature forgée = rejet.

## REGISTER_DOMAIN (0x21)

```text
network(str ≤ 16) name(str ≤ 253) domain_id[32] owner[32] timestamp.v proof(bytes ≤ 256) public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `name` | `str` ≤ 253 | nom canonique du domaine claimé, **porté en clair** (voir ci-dessous) |
| `domain_id` | 32 octets nus | **doit** valoir `DomainId(name)` (recomputé, jamais cru) |
| `owner` | 32 octets nus | **doit** être la dérivation de `public_key` (voir ci-dessous) |
| `timestamp` | varint | information d'ordre (Unix, secondes) |
| `proof` | `bytes` ≤ 256 | charge utile du PoW de registration (voir [ci-dessous](#preuve-de-travail-pow-de-registration)) |
| `public_key` | 32 octets nus | clé publique Ed25519 du signataire (RFC 8032) |
| `signature` | **exactement 64 octets** | signature Ed25519 du payload signé |

### Le nom est porté par la transaction

Le `RegisterDomain` transporte le nom canonique en clair, suivi de
son `DomainId`. La cohérence `domain_id == DomainId(name)` est
re-vérifiée à l'encodage, au décodage et à la validation (défense en
profondeur) : un `RegisterDomain` dont l'id ne correspond pas au nom
porté est invalide. Le `DomainId` reste l'identité de consensus
(clés de chaîne, de DHT) ; le nom porté rend la chaîne
auto-descriptive et couvre l'intégralité de la claim dans la
signature.

## REGISTER_TLD (0x93)

Claim d'un top-level domain (registre TLD, M7) :

```text
network(str ≤ 16) tld(str ≤ 63) tld_id[32] owner[32] timestamp.v proof(bytes ≤ 256) public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `tld` | `str` ≤ 63 | nom canonique du TLD **porté en clair** (M8b : le challenge PoW se dérive du nom, comme `RegisterDomain` porte le sien) |
| `tld_id` | 32 octets nus | identité du TLD : `BLAKE3-256("SCONE-TLD-V1" || tld)` — **doit** être la dérivation de `tld` (recomputé) |
| `owner` | 32 octets nus | dérivation de `public_key` |
| `timestamp` | varint | information d'ordre (Unix, secondes) |
| `proof` | `bytes` ≤ 256 | charge utile du PoW de registration (voir [ci-dessous](#preuve-de-travail-pow-de-registration)) |
| `public_key` | 32 octets nus | clé Ed25519 du signataire |
| `signature` | **exactement 64 octets** | signature Ed25519 du payload signé |

L'espace des `TldId` est **disjoint** de celui des `DomainId`
(préfixes de dérivation distincts — voir `/docs/general/naming.md`) :
enregistrer le TLD `uip` (claim sur le namespace `*.uip`) ne peut
jamais squatter l'identité d'un domaine, ni l'inverse. Règle d'état à
l'application : le TLD doit être libre (registre séparé de celui des
domaines).

## Famille M8a — formats wire

Cinq types complètent le registre TLD et le cycle de vie des
domaines. Formats wire normatifs depuis M8a ; **règles d'état
complètes depuis M8b** (voir `/docs/technical/blockchain.md`) :
owner-du-TLD requis, PoW là où une claim est auto-service,
expirations et grâce côté domaines. Chaque payload commence par le
champ `network` (M8b).

### TRANSFER_TLD (0x47)

```text
network(str ≤ 16) tld_id[32] owner[32] new_owner[32] public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `tld_id` | 32 octets nus | TLD transféré |
| `owner` | 32 octets nus | dérivation de `public_key` (owner courant / signataire) |
| `new_owner` | 32 octets nus | identité du destinataire (opaque : toute valeur est syntaxiquement valide ; le binding aux clés qui peuvent le dépenser est une règle d'état M8b) |
| `public_key` | 32 octets nus | clé Ed25519 du signataire |
| `signature` | **exactement 64 octets** | signature Ed25519 du payload signé |

Pas de timestamp ni de séquence : un TLD a exactement un owner à la
fois, le premier transfert appliqué gagne (ordre de chaîne seul).

### REVOKE_TLD (0x6B)

```text
network(str ≤ 16) tld_id[32] owner[32] public_key[32] signature[64]
```

Abandon volontaire d'un TLD (re-claimable ensuite par un
`RegisterTld` frais). Signé par l'owner courant ; volontairement sans
timestamp ni séquence — un revoke est one-shot contre l'état courant.

### SET_TLD_OPEN (0xB8)

```text
network(str ≤ 16) tld_id[32] owner[32] open u8 public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `open` | 1 octet | **strictement `0x00` ou `0x01`** (forme canonique ; toute autre valeur → erreur de décodage, jamais de coercion) |

TLD **fermé** = assign-only (domaines créés exclusivement par l'owner
du TLD via `AssignDomain`) ; TLD **ouvert** = quiconque peut faire le
PoW de registration et claimer un domaine libre (`RegisterDomain`).

### ASSIGN_DOMAIN (0xD4)

```text
network(str ≤ 16) name(str ≤ 253) domain_id[32] owner[32] assignee[32] public_key[32] signature[64]
```

Miroir de `RegisterDomain` : le nom canonique est porté en clair et
`domain_id` doit valoir `DomainId(name)` (recomputé au décodage,
encodage et validation). Signé par l'**owner du TLD** du nom
(vérifié à l'application, M8b) ; `assignee` devient le premier owner
du domaine (opaque, comme `new_owner`).

### RENEW_DOMAIN (0x3C)

```text
network(str ≤ 16) domain_id[32] owner[32] valid_until.v public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `valid_until` | varint | nouvelle échéance d'enregistrement (Unix, secondes) |

Signé par l'owner courant du domaine ; le fait que `valid_until`
prolonge réellement l'échéance (et d'au plus un terme de
renouvellement) est une règle d'état (M8b).

## UPDATE_DOMAIN (0x52)

```text
network(str ≤ 16) domain_id[32] owner[32] sequence.v record_hash[32] public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `domain_id` | 32 octets nus | domaine visé |
| `owner` | 32 octets nus | dérivation de `public_key` |
| `sequence` | varint | **> 0**, doit valoir `current + 1` à l'application |
| `record_hash` | 32 octets nus | engagement vers le record set DHT |
| `public_key` | 32 octets nus | clé Ed25519 du signataire |
| `signature` | **exactement 64 octets** | signature Ed25519 du payload signé |

Note : `UpdateDomain` ne porte **pas** de `timestamp` — l'ordre passe
par `sequence`. Il ne porte pas non plus le nom : le domaine est déjà
enregistré, l'id suffit.

### Bornes strictes

- `public_key` : **exactement 32 octets bruts**, sans préfixe de
  longueur. Une pk qui ne se décode pas en point de courbe → erreur
  `InvalidTransactionKey` au décodage.
- `signature` : **exactement 64 octets bruts**, sans préfixe de
  longueur ni marge. Toute autre taille est une erreur dure de
  décodage (troncature rejetée).
- `proof` : varint longueur + octets, plafonné à 256
  (`MAX_PROOF_LEN`), vérifié avant allocation.
- `name` : varint longueur + octets UTF-8, plafonné à 253
  (`MAX_NAME_LEN`), revalidé par les règles de nommage `scone-core`.

## Dérivation de l'owner

Règle dure : **l'owner est toujours recalculé, jamais cru**.

```text
PublicKeyRef = BLAKE3-256("SCONE-PUBKEY-V1" || public_key)
OwnerId      = BLAKE3-256("SCONE-OWNER-V1" || PublicKeyRef)
```

Une transaction dont `owner` ne correspond pas à la dérivation de sa
propre `public_key` est invalide (`InvalidOwner` côté core,
`OwnerKeyMismatch` côté chaîne), rejetée à l'encodage, au décodage
**et** à la validation de chaîne (défense en profondeur).

## Payload signé

Le payload signé est l'encodage canonique de la transaction **sans le
champ signature**, préfixé par un domaine de séparation :

```text
signing_payload = "SCONE-TX-SIG-V1" || canonical_encode(tx_sans_signature)
```

où `canonical_encode(tx_sans_signature)` reprend **exactement** la
structure wire ci-dessus, discriminant et octet de version compris,
en s'arrêtant avant `signature` :

```text
REGISTER_DOMAIN_sans_sig = disc(0x21) version(0x01) network name domain_id[32] owner[32]
                            timestamp.v proof public_key[32]
REGISTER_TLD_sans_sig    = disc(0x93) version(0x01) network tld tld_id[32] owner[32]
                            timestamp.v proof public_key[32]
UPDATE_DOMAIN_sans_sig   = disc(0x52) version(0x01) network domain_id[32] owner[32]
                            sequence.v record_hash[32] public_key[32]
TRANSFER_TLD_sans_sig    = disc(0x47) version(0x01) network tld_id[32] owner[32]
                            new_owner[32] public_key[32]
REVOKE_TLD_sans_sig      = disc(0x6B) version(0x01) network tld_id[32] owner[32]
                            public_key[32]
SET_TLD_OPEN_sans_sig    = disc(0xB8) version(0x01) network tld_id[32] owner[32]
                            open(0x00|0x01) public_key[32]
ASSIGN_DOMAIN_sans_sig   = disc(0xD4) version(0x01) network name domain_id[32] owner[32]
                            assignee[32] public_key[32]
RENEW_DOMAIN_sans_sig    = disc(0x3C) version(0x01) network domain_id[32] owner[32]
                            valid_until.v public_key[32]
```

Propriétés :

- déterministe et pur : même transaction ⇒ même payload partout ;
- le préfixe ASCII `SCONE-TX-SIG-V1` (15 octets,
  hex `53434f4e452d54582d5349472d5631`) empêche toute réutilisation
  de la signature dans un autre domaine de hash du protocole ;
- tous les champs sauf `signature` sont couverts — **y compris le
  nom porté par un `RegisterDomain`** : modifier n'importe lequel
  invalide la signature.

## Preuve de travail (PoW) de registration

Le champ `proof` de `RegisterDomain` et `RegisterTld` porte la preuve
de travail de registration (module `scone-core::pow`).

### Digest

```text
digest = BLAKE3-256("SCONE-POW-V1" || network || challenge || nonce_le64)
```

`network` est le `network_id` canonique (M8b) : une preuve minée pour
un réseau n'est pas une preuve sur un autre.
```

`challenge` est l'entrée de dérivation de l'objet claimé —
`"SCONE-TLD-V1" || tld` pour un TLD, `"SCONE-DOMAIN-V1" || nom` pour
un domaine : exactement les octets hashés pour `TldId` / `DomainId`,
si bien qu'une preuve n'est jamais rejouable entre namespaces ni
entre kinds d'objets. `nonce_le64` est l'encodage little-endian sur
8 octets du nonce.

La preuve est valide quand `digest` a au moins `difficulty` bits de
zéro en tête.

### Charge utile wire (12 octets fixes)

```text
nonce_le64 || difficulty_le32
```

La difficulté voyage avec la preuve, mais elle est
**producteur-déclarée et donc jamais crue** : le vérificateur la
compare à la **constante protocole** du kind de registration, et un
payload dont la difficulté déclarée diffère de la constante (plus
basse *ou* plus haute) est rejeté (`InvalidProof`). Le nonce est
ensuite re-vérifié à la difficulté constante, digest recomputé de
zéro.

### Difficultés (paramètres **par réseau**, M8b)

| Kind | testnet | mainnet |
|---|---|---|
| `RegisterTld` | 8 bits (symbolique, ms) | 24 bits |
| `RegisterDomain` (TLD ouvert) | 4 bits (symbolique) | 20 bits |

Claimer un namespace entier coûte toujours ~16× le claim d'un nom à
l'intérieur. Les difficultés vivent dans
`scone-core::network::NetworkParams` ; changer une valeur = changement
de consensus **pour ce réseau**.

Branchements d'état (M8b, livré) : `RegisterTld` exige TOUJOURS son
PoW ; `RegisterDomain` l'exige sur un TLD **ouvert** (le chemin
fermé est assign-only — `AssignDomain`, sans PoW, signé par l'owner
du TLD).

## Règles de validation

Une transaction est valide si et seulement si :

1. **décodage strict** : structure et bornes ci-dessus respectées
   (discriminant connu, version `0x01`, pk 32 o, signature 64 o,
   invariants core re-vérifiés au décodage) ;
2. **binding owner/pk** : `owner == OwnerId::from(public_key)`
   (recomputé) ;
3. **cohérence nom/id** (RegisterDomain) : `domain_id ==
   DomainId(name)` (recomputé) ;
4. **signature** : `verify_strict` Ed25519 de `signature` sur le
   payload signé **recomputé de zéro** (jamais pris d'un pair ni de
   la transaction telle que fournie) ;
5. **règles d'état** (à l'application dans un bloc — M8b, voir
   `/docs/technical/blockchain.md`) :
   toutes → `network` == celui de la chaîne (`WrongNetwork` sinon) ;
   RegisterTld → TLD libre + PoW (difficulté réseau) ;
   RegisterDomain → TLD enregistré **et ouvert** + domaine libre
   (grâce comprise) + PoW ;
   UpdateDomain → domaine existant, `owner` courant,
   `sequence == current + 1` ;
   TransferTld / RevokeTld / SetTldOpen → TLD existant, signataire =
   owner du TLD ;
   AssignDomain → TLD existant, signataire = owner du TLD, domaine
   libre (sans PoW) ;
   RenewDomain → domaine existant, owner, extension stricte ≤ 3 ans.

La vérification utilise `verify_strict` (rejet des signatures
malléables et des clés faibles/non canoniques), comme exigé pour des
données non fiables.

## Ordre des opérations dans `push_block`

La validation cryptographique (2 à 4) a lieu pour chaque transaction
**avant** l'application d'état, sur un état de travail atomique par
bloc ; la moindre erreur laisse la chaîne rigoureusement inchangée.

## Assemblage de blocs

`BlockBuilder` (`scone-blockchain`) assemble un bloc depuis une queue
de transactions : `tx_root` recalculé sur la liste ordonnée, header
enchaîné sur le hash parent (`prev_hash`), `version` =
`PROTOCOL_VERSION`. Le payload consensus (PoW futur) et le timestamp
sont fournis par l'appelant ; le trait `Consensus` existant est
utilisé symétriquement à la validation.

## Exemples hex (vecteurs réels, reproductibles — M8b)

### RegisterDomain `example.uip`, timestamp 42, testnet

Payload signé (vecteur épinglé, généré par `scone tx build
register-domain --name example.uip --timestamp 42`) :

```text
53434f4e452d54582d5349472d5631       préfixe SCONE-TX-SIG-V1
21                                    disc REGISTER_DOMAIN (0x21)
01                                    version format
0d 73636f6e652d746573746e6574         network (str, "scone-testnet")
0b 6578616d706c652e756970             name (str, longueur 11)
e6a2cbe264f81ed7da4d901c4deec6a3579224b8080fad01cb7461b8c264f181  domain_id
7b2446dadddf640244ac8677a401f148b2b23d1c836d5ad3dd340f8ef2edbed8   owner (clé de build fixe)
2a                                    timestamp (varint, 42)
0c 010000000000000004000000           proof (12 o : nonce 1, difficulté 4 — testnet)
2a002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12  pk + début sig
```

### RegisterTld `uip`, timestamp 42

Payload signé (vecteur épinglé) — le `TldId` est le vecteur de
dérivation épinglé dans `/docs/general/naming.md` :

```text
53434f4e452d54582d5349472d5631       préfixe SCONE-TX-SIG-V1
93 01                                 disc REGISTER_TLD + version
0d 73636f6e652d746573746e6574         network (str, "scone-testnet")
03 756970                             tld (str, "uip")
ad5a86d68643d5c22d6a959bb1a315530c77dfda241f1ac1a8107450f3fab25e  tld_id ("uip")
7b2446dadddf640244ac8677a401f148b2b23d1c836d5ad3dd340f8ef2edbed8   owner
2a                                    timestamp (varint, 42)
0c 740400000000000008000000           proof (12 o : nonce 0x474, difficulté 8 — testnet)
2a002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12  pk
```

(Les valeurs complètes sont reproductibles via `scone tx build
register-domain --name example.uip --timestamp 42`,
`scone tx build register-tld --tld uip --timestamp 42` puis
`scone tx sign`. Depuis M8b le PoW est miné automatiquement à la
difficulté testnet — les nonces varient d'un run à l'autre, seuls
network/nom/id/owner/pk sont stables.)

## CLI de test et debug

```bash
scone tx build register-domain --name example.uip --timestamp 42  # hex du payload à signer
scone tx build register-tld --tld uip --timestamp 42              # idem, claim de TLD
scone tx sign <payload|tx-hex> --identity alice                   # tx complète signée (hex)
scone tx verify <tx-hex>                                          # validation locale complète
```

`sign` accepte en entrée le payload de `build` ou une transaction
complète ; dans tous les cas l'owner et la clé sont **recomputés**
depuis l'identité du keystore, jamais repris de l'entrée.

## Historique de version

| Version | Contenu | Statut |
|---|---|---|
| 1 | `public_key` + `signature` embarquées, payload `SCONE-TX-SIG-V1`, octet de version `0x01`, `RegisterDomain` porte le nom, `RegisterTld` (0x93), famille M8a : `TransferTld` (0x47), `RevokeTld` (0x6B), `SetTldOpen` (0xB8), `AssignDomain` (0xD4), `RenewDomain` (0x3C) — formats wire normatifs ; M8b : champ `network` signé en tête de chaque payload, `RegisterTld` porte le nom, règles d'état complètes, difficultés PoW par réseau | courante |
