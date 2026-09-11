# Serveur DNS UDP (M6) — `scone dns`

> Spécification normative de la surface DNS de Scone.
> Toute divergence doc/code = bug (corriger la source de vérité).

## Vue d'ensemble

Le **serveur DNS** est une surface optionnelle du relay : il répond
aux requêtes DNS UDP pour les noms Scone **uniquement à partir de
données vérifiées contre la chaîne**, et propose un **fallback
récursif optionnel** (`addr:port`) pour le reste. Il ne possède ni
chaîne, ni store, ni DHT : la résolution passe par le relay
(processus), via le RPC de contrôle local — le même chemin vérifié
que le CLI.

```text
              UDP :5353 (par défaut 127.0.0.1)
                    │
             scone relay --dns 127.0.0.1:5353
                    │  ┌────────────────────────────────┐
                    ├──┤ Cache borné (qname,qtype)      │
                    │  └────────────────────────────────┘
                    │  nom de forme Scone ?
                    │  ├─ OUI → recherche d'apex par suffixe
                    │  │        → RPC `resolve_local` (relay)
                    │  │           chaîne + record vérifié (hash,
                    │  │           owner, séquence) → réponses
                    │  │        apex inconnu sur toute la chaîne → NXDOMAIN
                    │  │        apex sans record publié → NODATA
                    │  └─ NON → fallback amont (si configuré)
                    │           sinon REFUSED
```

## Démarrage

```bash
scone relay --dns 127.0.0.1:5353            # surface DNS seule
scone relay --dns 0.0.0.0:53 \
            --dns-upstream 1.1.1.1:53 \
            --dns-upstream 8.8.8.8:53       # + fallback récursif
```

Le relay annonce l'adresse effective sur stdout (contrat
machine-lisible, comme `p2p:`) : une ligne `dns: <addr>` dès le bind.

Client de validation : `scone dig <name> --dns 127.0.0.1:5353
--qtype A` (A, AAAA, TXT, MX, NS, CNAME, ANY).

## Chemin de résolution (AUTORITÉ = la chaîne, toujours)

1. **Cache** : clé `(qname, qtype)`, capacité 1024 entrées, TTL 60 s
   (autoritaire) / clampé à 600 s (fallback). Le cache négatif
   (NXDOMAIN/NODATA) suit les mêmes règles ; chaque entrée porte son
   origine (autoritaire ou fallback) pour que le bit AA reste honnête
   sur un hit. **Jamais de cache pour SERVFAIL** (défaillance locale
   transitoire) **ni REFUSED** (état de configuration) : recalculés à
   chaque requête. Éviction FIFO à la capacité.
2. **Forme Scone ?** Pré-filtre strict : labels `[a-z0-9-_]` (1..63),
   ≥ 2 labels, TLD 1..63 octets `[a-z0-9-]` (cf. `TldName::MAX_LEN`),
   longueur totale ≤ 253.
   Un nom qui ne peut PAS être un nom Scone (ex. `www.foo_bar`,
   underscore dans le TLD) part au fallback ; un nom qui POURRAIT l'être
   (`absent.uip`) relève de la chaîne : non enregistré → NXDOMAIN
   autoritaire, même sans upstream.
3. **Recherche d'apex** : suffixes du plus long au plus court (min.
   2 labels). Premier suffixe dont le relay connaît l'état on-chain
   = apex ; le record set sert le qname entier (sous-noms inclus —
   comportement wildcard implicite, décision ouverte).
4. **`resolve_local` (RPC interne)** : un seul aller-retour, jamais
   de waiter DHT. État on-chain (`registered`, owner, séquence) +
   record du cache DHT local **revérifié** (owner, séquence,
   record_hash == engagement on-chain). Un record non conforme ne
   répond jamais — disponibilité ≠ autorité.
   - non enregistré → NXDOMAIN ;
   - enregistré sans record valide → NODATA (NOERROR, 0 réponses) ;
   - record vérifié → réponses filtrées par qtype.

## Codec (RFC 1035, sous-ensemble strict)

- Requête : 12 octets d'en-tête, **une** question, QCLASS = IN,
  **pas de compression** (pointeur = rejet). Labels lowercasés et
  validés. QR=1, QDCOUNT≠1, labels invalides → **silence** (le
  garbage ne coûte rien).
- Réponse : QR|RD(écho)|RA, **AA uniquement sur les réponses
  autoritaires** (chaîne, fraîches ou cachées — jamais sur le
  fallback ni les RCODEs d'erreur), question recopiée telle quelle,
  réponses **non compressées** (owner = qname), TTL 60.
- Types servis : A, AAAA, CNAME, NS, MX, TXT (+ Unknown re-encodé
  tel quel). Une requête A/AAAA inclut les CNAME du set (suivi
  d'alias). Requête ANY (255) : tout le set filtré par le codec.
- Limites : datagramme ≤ 4096 octets ; un set dépassant la borne est
  coupé au dernier record qui tient avec **TC=1** (troncature
  honnête, RFC 1035 §4.2.1 — le client sait qu'il doit retenter en
  TCP ou s'arrêter, pas se fier à une réponse raccourcie en
  silence ; pas de TCP — voir RECOMMENDATIONS).
- RCODEs : 0 NOERROR (avec ou sans réponses), 2 SERVFAIL (failure
  RPC locale), 3 NXDOMAIN (autoritaire), 5 REFUSED (hors Scone sans
  upstream).

## Fallback récursif

- Amonts `addr:port` (UDP), essayés dans l'ordre, timeout 2 s par
  amont, socket **connectée** à l'amont (filtrage noyau : un paquet
  d'une autre source n'est jamais accepté). La réponse amont n'est
  acceptée que si elle **matche la requête** : même TXID, QR=1,
  question (QNAME+QTYPE+QCLASS) recopiée octet pour octet. Une
  réponse non conforme → SERVFAIL, et rien n'est mis en cache.
- La réponse amont validée est renvoyée telle quelle ; ses réponses
  sont mises en cache avec l'origine `fallback` (AA jamais positionné,
  même sur un hit de cache) et le TTL clampé à 600 s. Les RCODEs
  d'erreur de l'amont (hors NOERROR/NXDOMAIN) ne sont pas cachés.
- **Privé par défaut** : pas d'amont = REFUSED sur les noms hors
  forme Scone.

## Bornes et garde-fous

| Garde-fou | Valeur |
|---|---|
| Paquet (req/rép) | 4096 octets |
| Cache | 1024 entrées (FIFO) |
| TTL autoritaire | 60 s |
| TTL fallback (clamp) | 600 s |
| Requêtes UDP en parallèle | 256 (sémaphore ; au-delà : drop, le client retente) |
| Timeout par amont | 2 s |

Règles projet respectées : jamais de panic sur données réseau ;
tout décodage strict ; le serveur ne touche ni chaîne ni store ni
DHT (le relay reste l'unique autorité de vérification).

## Tests

- Unitaires (`scone-network::dns`) : codec strict (rejets QR,
  compression, labels), réponses autoritaires, NODATA, NXDOMAIN,
  REFUSED sans amont, fallback vers un mock UDP, cache borné,
  chunking TXT, parsing des amonts ; M6 fix-up : honnêteté du bit AA
  (autoritaire vs fallback vs erreurs, y compris hit de cache),
  troncature TC=1 d'un set trop grand, rejet d'une réponse amont
  (TXID ou question ne matchant pas), non-cache de SERVFAIL/REFUSED.
- Intégration réelle (`tests/dns_server.rs`) : un relay complet
  (production devnet incluse) + enregistrement + UpdateDomain + PutRecord,
  puis requêtes UDP réelles : A vérifié (bit AA), TXT, NODATA AAAA,
  NXDOMAIN, fallback via mock, re-quête, sous-nom via apex.
- E2E binaire (`crates/scone/tests/dns_cli.rs`) : le binaire
  `scone` réel — `relay --dns`, `identity generate`, `domain
  register`, `domain update --file`, puis `scone dig` (A vérifié,
  TXT, NXDOMAIN, REFUSED) sur un vrai port UDP.

## Décisions ouvertes

- Pas de TCP (troncature honnête TC=1 si réponse > 4096) ; pas de EDNS.
- Le record set ne porte pas de nom par record : tout le set sert
  tout sous-nom de l'apex (wildcard implicite). Un adressage par
  enregistrement exigerait d'étendre `DnsRecord` (protocol).
- Le fallback transfère la requête brute : un amont malicieux peut
  répondre n'importe quoi (réponse non validée — c'est le modèle
  récursif standard ; les noms Scone ne passent JAMAIS par là).
