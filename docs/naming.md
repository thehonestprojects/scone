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

- motif : `[a-z0-9-]{1,5}` (LDH, pas de tiret initial/final)
- valides : `uip`, `com`, `test`, `abc12`, `0x`, `a-b`
- invalides : `abcdef` (6 caractères), `ABC`, `-ab`, `ab-`, `éxemple`,
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

## Limites et règles futures (non figées)

- noms internationalisés (IDN) via punycode ;
- réservation/gouvernance des TLDs ;
- longueur minimale des labels de second niveau ;
- expiration/renouvellement des claims de domaine.
