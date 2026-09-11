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

### Discriminants (table normative)

Chaque discriminant est une **constante opaque, fixe et arbitraire** :
les valeurs sont choisies distinctes exprès, pour que le wire ne
suggère **jamais** d'ordre logique entre les types (aucune suite
0x01/0x02/0x03…). `0x00` n'est **jamais** un type valide (octet de
corruption typique). Les futurs types (`TransferTld`, `RevokeTld`,
`AssignDomain`, `RenewDomain`, …) prendront toute valeur libre non
utilisée, documentée une fois pour toutes dans cette table.

| Discriminant | Type | Rôle |
|---|---|---|
| `0x21` | `RegisterDomain` | claim d'un domaine |
| `0x52` | `UpdateDomain` | nouvelle version des données DNS d'un domaine |
| `0x93` | `RegisterTld` | claim d'un top-level domain (M7) |

Tout octet de version autre que `0x01` est rejeté explicitement
(`UnsupportedVersion(valeur reçue)`) : un format inconnu ou obsolète
n'est jamais analysé par accident.

## REGISTER_DOMAIN (0x21)

```text
name(str ≤ 253) domain_id[32] owner[32] timestamp.v proof(bytes ≤ 256) public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `name` | `str` ≤ 253 | nom canonique du domaine claimé, **porté en clair** (voir ci-dessous) |
| `domain_id` | 32 octets nus | **doit** valoir `DomainId(name)` (recomputé, jamais cru) |
| `owner` | 32 octets nus | **doit** être la dérivation de `public_key` (voir ci-dessous) |
| `timestamp` | varint | information d'ordre (Unix, secondes) |
| `proof` | `bytes` ≤ 256 | opaque, réservé au futur PoW de registration |
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
tld_id[32] owner[32] timestamp.v proof(bytes ≤ 256) public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `tld_id` | 32 octets nus | identité du TLD : `BLAKE3-256("SCONE-TLD-V1" || tld)` |
| `owner` | 32 octets nus | dérivation de `public_key` |
| `timestamp` | varint | information d'ordre (Unix, secondes) |
| `proof` | `bytes` ≤ 256 | opaque, réservé au futur PoW |
| `public_key` | 32 octets nus | clé Ed25519 du signataire |
| `signature` | **exactement 64 octets** | signature Ed25519 du payload signé |

L'espace des `TldId` est **disjoint** de celui des `DomainId`
(préfixes de dérivation distincts — voir `/docs/general/naming.md`) :
enregistrer le TLD `uip` (claim sur le namespace `*.uip`) ne peut
jamais squatter l'identité d'un domaine, ni l'inverse. Règle d'état à
l'application : le TLD doit être libre (registre séparé de celui des
domaines).

## UPDATE_DOMAIN (0x52)

```text
domain_id[32] owner[32] sequence.v record_hash[32] public_key[32] signature[64]
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
REGISTER_DOMAIN_sans_sig = disc(0x21) version(0x01) name domain_id[32] owner[32]
                            timestamp.v proof public_key[32]
REGISTER_TLD_sans_sig    = disc(0x93) version(0x01) tld_id[32] owner[32]
                            timestamp.v proof public_key[32]
UPDATE_DOMAIN_sans_sig   = disc(0x52) version(0x01) domain_id[32] owner[32]
                            sequence.v record_hash[32] public_key[32]
```

Propriétés :

- déterministe et pur : même transaction ⇒ même payload partout ;
- le préfixe ASCII `SCONE-TX-SIG-V1` (15 octets,
  hex `53434f4e452d54582d5349472d5631`) empêche toute réutilisation
  de la signature dans un autre domaine de hash du protocole ;
- tous les champs sauf `signature` sont couverts — **y compris le
  nom porté par un `RegisterDomain`** : modifier n'importe lequel
  invalide la signature.

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
5. **règles d'état** (à l'application dans un bloc) :
   RegisterDomain → TLD du nom **enregistré** (`UnknownTld` sinon — D1)
   puis domaine libre ; RegisterTld → TLD libre ;
   UpdateDomain → domaine existant, `owner` courant,
   `sequence == current + 1`.

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

## Exemples hex (vecteurs réels, reproductibles)

### RegisterDomain `example.uip`, timestamp 42, preuve vide

```text
21                                    disc REGISTER_DOMAIN (0x21)
01                                    version format
0b 6578616d706c652e756970             name (str, longueur 11)
e6a2cbe264f81ed7da4d901c4deec6a3579224b8080fad01cb7461b8c264f181  domain_id
<owner 32 o>                          dérivation de la pk embarquée
2a                                   timestamp (varint, 42)
00                                    proof (vide, longueur 0)
<pk 32 o>                             public_key
<64 octets de signature Ed25519>
```

Payload signé correspondant (vecteur épinglé, généré par
`scone tx build register-domain --name example.uip --timestamp 42`) :

```text
53434f4e452d54582d5349472d5631       préfixe SCONE-TX-SIG-V1
21010b6578616d706c652e756970
e6a2cbe264f81ed7da4d901c4deec6a3579224b8080fad01cb7461b8c264f181
7b2446dadddf640244ac8677a401f148b2b23d1c836d5ad3dd340f8ef2edbed8   owner (clé de build fixe)
2a
00
2a002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12  pk + début sig
```

### RegisterTld `uip`, timestamp 42

Payload signé (vecteur épinglé) — le `TldId` visible en tête est le
vecteur de dérivation épinglé dans `/docs/general/naming.md` :

```text
53434f4e452d54582d5349472d5631       préfixe SCONE-TX-SIG-V1
9301
ad5a86d68643d5c22d6a959bb1a315530c77dfda241f1ac1a8107450f3fab25e  tld_id ("uip")
7b2446dadddf640244ac8677a401f148b2b23d1c836d5ad3dd340f8ef2edbed8   owner
2a 00
2a002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12  pk
```

(Les valeurs complètes sont reproductibles via `scone tx build
register-domain --name example.uip --timestamp 42`,
`scone tx build register-tld --tld uip --timestamp 42` puis
`scone tx sign`.)

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
| 1 | `public_key` + `signature` embarquées, payload `SCONE-TX-SIG-V1`, octet de version `0x01`, `RegisterDomain` porte le nom, `RegisterTld` (0x93) | courante |
