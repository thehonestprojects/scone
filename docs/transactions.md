# Transactions signées (format v2)

Document de référence **normatif** du format de transaction signée v2
(jalon M2). Il spécifie les champs, l'ordre wire exact, les tailles,
le payload signé et les règles de validation, de manière à permettre
une implémentation indépendante sans lire le Rust. L'implémentation de
référence est [`scone-protocol`](../crates/scone-protocol)
(encodage) et [`scone-blockchain`](../crates/scone-blockchain)
(validation).

`PROTOCOL_VERSION` = **2** depuis ce format (la version 1 —
transactions non signées — est rejetée explicitement).

## Vue d'ensemble

```text
Transaction = disc u8 || version u8 || payload
```

| Champ | Taille | Rôle |
|---|---|---|
| `disc` | 1 o | `0x01` Register, `0x02` Update |
| `version` | 1 o | **exactement `0x02`** (version du format tx) |

L'octet `version` est nouveau en v2. Un flux v1 (qui n'a pas d'octet
de version) est détecté et rejeté avec `UnsupportedVersion(1)` : un
ancien format n'est jamais analysé comme du v2 par accident.

## REGISTER (0x01)

```text
domain_id[32] owner[32] timestamp.v proof(bytes ≤ 256) public_key[32] signature[64]
```

| Champ | Type | Contraintes |
|---|---|---|
| `domain_id` | 32 octets nus | identité du nom (voir `/docs/naming.md`) |
| `owner` | 32 octets nus | **doit** être la dérivation de `public_key` (voir ci-dessous) |
| `timestamp` | varint | information d'ordre (Unix, secondes) |
| `proof` | `bytes` ≤ 256 | opaque, réservé au futur PoW de registration |
| `public_key` | 32 octets nus | clé publique Ed25519 du signataire (RFC 8032) |
| `signature` | **exactement 64 octets** | signature Ed25519 du payload signé |

## UPDATE (0x02)

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

Note : `Update` ne porte **pas** de `timestamp` en v2 — l'ordre passe
par `sequence` (décision M2).

### Bornes strictes

- `public_key` : **exactement 32 octets bruts**, sans préfixe de
  longueur. Une pk qui ne se décode pas en point de courbe → erreur
  `InvalidTransactionKey` au décodage.
- `signature` : **exactement 64 octets bruts**, sans préfixe de
  longueur ni marge. Toute autre taille est une erreur dure de
  décodage (troncature rejetée).
- `proof` : varint longueur + octets, plafonné à 256
  (`MAX_PROOF_LEN`), vérifié avant allocation.

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
REGISTER_sans_sig = disc(0x01) version(0x02) domain_id[32] owner[32]
                    timestamp.v proof public_key[32]
UPDATE_sans_sig   = disc(0x02) version(0x02) domain_id[32] owner[32]
                    sequence.v record_hash[32] public_key[32]
```

Propriétés :

- déterministe et pur : même transaction ⇒ même payload partout ;
- le préfixe ASCII `SCONE-TX-SIG-V1` (15 octets,
  hex `53434f4e452d54582d5349472d5631`) empêche toute réutilisation
  de la signature dans un autre domaine de hash du protocole ;
- tous les champs sauf `signature` sont couverts : modifier
  n'importe lequel invalide la signature.

## Règles de validation

Une transaction est valide si et seulement si :

1. **décodage strict** : structure et bornes ci-dessus respectées
   (discriminant connu, version `0x02`, pk 32 o, signature 64 o,
   invariants core re-vérifiés au décodage) ;
2. **binding owner/pk** : `owner == OwnerId::from(public_key)`
   (recomputé) ;
3. **signature** : `verify_strict` Ed25519 de `signature` sur le
   payload signé **recomputé de zéro** (jamais pris d'un pair ni de
   la transaction telle que fournie) ;
4. **règles d'état** (à l'application dans un bloc) : Register →
   domaine libre ; Update → domaine existant, `owner` courant,
   `sequence == current + 1`.

La vérification utilise `verify_strict` (rejet des signatures
malléables et des clés faibles/non canoniques), comme exigé pour des
données non fiables.

## Ordre des opérations dans `push_block`

La validation cryptographique (2 et 3) a lieu pour chaque transaction
**avant** l'application d'état, sur un état de travail atomique par
bloc ; la moindre erreur laisse la chaîne rigoureusement inchangée.

## Assemblage de blocs

`BlockBuilder` (`scone-blockchain`) assemble un bloc depuis une queue
de transactions : `tx_root` recalculé sur la liste ordonnée, header
enchaîné sur le hash parent (`prev_hash`), `version` =
`PROTOCOL_VERSION`. Le payload consensus (PoW futur) et le timestamp
sont fournis par l'appelant ; le trait `Consensus` existant est
utilisé symétriquement à la validation.

## Exemples hex

### Register signé (extrait réel)

```text
01                                    disc REGISTER
02                                    version format v2
e6a2cbe2…4f181  (32 o)               domain_id (example.uip)
7ca7ebf0…a50bdf  (32 o)              owner (dérivé de la pk)
2a                                   timestamp (varint, 42)
00                                    proof (vide, longueur 0)
2d722d8b…6ea6fa3  (32 o)             public_key
<64 octets de signature Ed25519>
```

### Payload signé correspondant

```text
53434f4e452d54582d5349472d5631       préfixe SCONE-TX-SIG-V1
0102e6a2…db12                        tx sans signature (ci-dessus)
```

(Les valeurs complètes sont reproductibles via `scone tx build
register --name example.uip --timestamp 42` puis `scone tx sign`.)

## CLI de test et debug

```bash
scone tx build register --name example.uip --timestamp 42   # hex du payload à signer
scone tx sign <payload|tx-hex> --identity alice              # tx complète signée (hex)
scone tx verify <tx-hex>                                     # validation locale complète
```

`sign` accepte en entrée le payload de `build` ou une transaction
complète ; dans tous les cas l'owner et la clé sont **recomputés**
depuis l'identité du keystore, jamais repris de l'entrée.

## Historique de version

| Version | Contenu | Statut |
|---|---|---|
| 1 | transactions non signées (M1) | rejetée explicitement |
| 2 | `public_key` + `signature` embarquées, payload `SCONE-TX-SIG-V1`, octet de version | courante |
