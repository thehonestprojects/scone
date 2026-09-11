# Naming

## Alphabet

ASCII minuscules, chiffres et tirets (LDH, RFC 1123) : `[a-z0-9-]`, le
tiret ni en première ni en dernière position d'un label. Pas de majuscules,
pas d'underscore, pas d'unicode.

La validation est **stricte** : un nom non canonique est rejeté, jamais
corrigé. `"ABC"` → erreur (pas de lowercasing silencieux). Rationnel : une
frontière de protocole doit être déterministe ; la canonicalisation
implicite crée des ambiguïtés d'identité.

## TLD

Un TLD est un label DNS comme les autres : la limite générique des labels
(RFC 1035 : 63 octets) s'applique, pas une limite spécifique plus courte.

- motif : `[a-z0-9-]{1,63}` (LDH, pas de tiret initial/final)
- limite codée : `TldName::MAX_LEN = 63` octets
- valides : `uip`, `com`, `test`, `abc12`, `0x`, `a-b`, un TLD de 63
  octets exactement
- invalides : un TLD de 64 octets, `ABC`, `-ab`, `ab-`, `éxemple`,
  chaîne vide

## Domaines

- forme : `label[.label]*.tld` — au moins deux labels (`name.tld`) ;
- chaque label : LDH `[a-z0-9-]{1,63}`, tiret ni initial ni final ;
- longueur totale : ≤ 253 octets ;
- aucun label vide (`a..b`, `.a`, `a.` invalides) ;
- le dernier label doit être un TLD valide.

### Sous-domaines

Le type `DomainName` accepte d'emblée la hiérarchie complète :

```text
example.uip
shop.example.uip
api.shop.example.uip
```

Un sous-domaine a un `DomainId` **distinct** de celui de son parent. Les
règles d'allocation des sous-domaines (droits du propriétaire du parent,
etc.) sont futures.

## Canonicalisation

Un nom validé est déjà canonique : `canonical() == as_str()`. Sont donc
rejetés aujourd'hui : majuscules, ponctuation autre que le `.` séparateur,
espaces, unicode, caractères invisibles, etc.

## DomainId

```text
DomainId = BLAKE3-256("SCONE-DOMAIN-V1" || nom_canonique)
```

- déterministe : même nom canonique ⇒ même id, partout, pour toujours ;
- injectif en pratique : deux noms distincts ⇒ deux ids distincts ;
- le nom brut ne doit **jamais** servir d'identifiant interne (clés de
  blockchain, clés de DHT) — uniquement pour la saisie et l'affichage ;
- le préfixe `SCONE-DOMAIN-V1` isole les domaines de dérivation : changer
  la règle (alphabet, normalisation) revient à créer un nouvel espace de
  noms versionné (`SCONE-DOMAIN-V2`), sans réécrire l'existant.

### Représentation textuelle

Encodage hexadécimal **minuscule** (`0-9a-f`) des 32 octets bruts :
exactement 64 caractères, sans préfixe (`0x`), jamais tronqué.

```text
DomainId([0xab; 32]) → "ababababababababababababababababababababababababababababababababab"
DomainId([0x00; 32]) → "0000000000000000000000000000000000000000000000000000000000000000"
```

Cette forme est produite par `Display` (le `Debug` Rust affiche
`DomainId(<hex>)`, même chaîne). Toute sortie consommée par un humain ou
une machine hors du format binaire canonique — journaux, messages
d'erreur, CLI (`scone show`) — DOIT utiliser cette représentation et
aucune autre (pas de troncature, pas de préfixe, pas de majuscules).

## Limites et règles futures (non figées)

- noms internationalisés (IDN) via punycode ;
- longueur minimale des labels de second niveau ;
- expiration/renouvellement des claims de domaine.

## TLDId (M7a)

Un TLD enregistrable porte sa propre identité, distincte de celle de
tout domaine :

```text
TldId = BLAKE3-256("SCONE-TLD-V1" || tld)
```

- le préfixe `SCONE-TLD-V1` est **distinct** de `SCONE-DOMAIN-V1` :
  les espaces d'ids TLD et domaine sont disjoints par construction —
  enregistrer le TLD `uip` (une claim sur le namespace `*.uip`) ne
  peut jamais squatter l'identité d'un domaine, ni l'inverse ;
- mêmes règles d'affichage que `DomainId` : hex minuscule, 64
  caractères, jamais tronqué ;
- vecteur épinglé (dérivation figée par test) :
  `TldId("uip") = ad5a86d68643d5c22d6a959bb1a315530c77dfda241f1ac1a8107450f3fab25e`.

La transaction `RegisterTld` (claim signée d'un TLD, `owner` toujours
recomputé de la clé embarquée) fait partie de l'enum `Transaction` et
du format wire depuis M7b : discriminant `0x93` (constante opaque
arbitraire), payload signé `SCONE-TX-SIG-V1`, règles complètes dans
`/docs/technical/transactions.md`. Le `RegisterDomain` d'un domaine
porte parallèlement le nom canonique en clair.

## Réservation/gouvernance des TLDs

Ouverte par M7a : `RegisterTld` réclame un TLD libre au profit de
l'identité dérivée de la clé signataire. Règles de gouvernance
(dépôt, expiration, révocation) : non figées.
