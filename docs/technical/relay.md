# Relay réseau (M4) — architecture, flux et RPC de contrôle

> Spécification normative du relais réseau Scone (`scone-network`).
> Toute divergence doc/code = bug (corriger la source de vérité).

## Vue d'ensemble

Le **relay** est le nœud P2P complet de Scone : il maintient la
blockchain canonique (RAM + `NodeStore` redb), relaie transactions et
blocs, produit des blocs (mode devnet), sert le protocole de sync,
publie et résout les `SignedDnsRecord` dans une DHT Kademlia, et
expose un **RPC de contrôle local** que le CLI interroge.

```text
                    ┌────────────────────────────────────────┐
                    │              scone relay               │
  P2P (libp2p)      │                                        │
  QUIC :4001 ◄──────┤  Swarm libp2p                          │
                    │  ├─ identify  (découverte d'adresses)  │
                    │  ├─ ping      (liveness)               │
                    │  ├─ kad       (DHT des records)        │
                    │  └─ reqres    (messages scone-prot.)   │
                    │                                        │
                    │  Relay core (une seule tâche)          │
                    │  ├─ Blockchain (validation totale)     │
                    │  ├─ Mempool (borné, dédup par TxId)    │
                    │  ├─ BlockBuilder (production devnet)   │
                    │  └─ Sync driver (rattrapage par lots)  │
                    │                                        │
  CLI ◄─────────────┤  RPC contrôle (TCP 127.0.0.1, JSON)    │
                    └────────────────┬───────────────────────┘
                                     │
                              NodeStore (redb)
```

`crates/scone-network` est la **seule crate async** du workspace :
tout ce qui est en dessous (crypto → core → protocol → blockchain →
storage) reste synchrone et pur.

## Transport et protocoles libp2p

| Protocole | Nom | Rôle |
|---|---|---|
| QUIC (quic-v1) | — | Transport principal (udp) |
| identify | `/scone/id/1` | Découverte des adresses des pairs (remplit la table Kademlia) |
| ping | libp2p standard | Liveness |
| Kademlia | `/scone/kad/1` | DHT : clé = `DomainId` (32 o), valeur = encodage canonique du `SignedDnsRecord` |
| request-response | `/scone/reqres/1` | Messages applicatifs scone-protocol |

### Cadre applicatif (`/scone/reqres/1`)

Chaque trame est `len: u32 BE || octets` où les octets sont l'encodage
canonique d'un `Message` de `scone-protocol` (le codec existant —
aucun second format). La longueur est bornée par
`limits::MAX_MESSAGE_LEN` **avant** toute lecture ou allocation : un
pair annonçant une trame plus grosse est rejeté sans coût mémoire.

Messages échangés (un par aller-retour request/response) :

| Message | Direction | Réponse |
|---|---|---|
| `Hello { version }` | handshake | `Hello` (version locale) |
| `Ping` / `Pong` | liveness | `Pong` |
| `GetBlock { hash }` | demande | `Block` (fenêtre RAM) ou `Pong` si inconnu |
| `GetBlocks { start, max }` | sync | **un** `Block` (hauteur `start`), ou `Pong` si rien |
| `Block (b)` | relais de bloc | `Pong` (ack) |
| `Transaction (tx)` | relais de tx | `Pong` (ack) |
| `GetRecord { domain_id }` | DHT locale | `Record` (cache local) ou `Pong` |
| `Record (r)` | publication | `Pong` si accepté, erreur sinon |

Règle : **une seule réponse par requête** ; les messages d'acquittement
sont `Pong`. Les réponses de sync portent un bloc à la fois — le
rattrapage itère côté demandeur (voir « Sync »). C'est volontairement
borné : jamais plus d'un bloc en vol par pair.

## Comportement du relay

### Démarrage

1. ouverture/creation du store redb (`<data-dir>/chain.redb`) ;
2. `load_chain` : tip en O(1) + états de domaines paginés
   (fenêtre RAM : genesis + tip) ;
3. construction du swarm (identité Ed25519 éphémère par session —
   la persistance de l'identité réseau est une décision ouverte) ;
4. dial des multiaddrs `--bootstrap` (doivent finir par
   `/p2p/<peer-id>`) et enregistrement dans la table Kademlia ;
5. bind du RPC de contrôle (127.0.0.1, port fixé par le CLI).

### Réception d'une transaction (P2P ou RPC `submit_tx`)

1. décodage strict borné (`MAX_MESSAGE_LEN`) ;
2. validation cryptographique complète (`validate_transaction` :
   binding owner/clé, `verify_strict` sur le payload canonique) ;
3. pré-contrôle d'état : `Register` → nom libre ; `Update` → domaine
   connu, séquence exacte `current + 1`, propriétaire ;
4. insertion au mempool (capacité fixe, dédup par `TxId` —
   re-soumettre une tx déjà en pool est un no-op) ;
5. broadcast aux pairs (sauf l'émetteur).

### Réception d'un bloc (P2P, sync ou auto-produit)

1. `push_block` : validation totale existante (parent = tip canonique,
   hauteur, Merkle recalculée, chaque transaction validée puis
   appliquée — atomique par bloc) ;
2. si accepté : `store_block` (append delta atomique : bloc + tip +
   états modifiés) ;
3. réconciliation du mempool (les tx incluses sont retirées) ;
4. broadcast aux pairs (sauf l'émetteur).

Un bloc invalide est rejeté avec une erreur typée ; le relay continue
de tourner. Aucun panic sur données réseau.

### Production de blocs (mode devnet)

Toutes les `produce_interval` secondes (2 s par défaut) : si le
mempool est non-vide, un bloc est assemblé par `BlockBuilder`
(`timestamp = now`, consensus permissif — le vrai consensus PoW
remacera ce mode) et suit exactement le chemin d'acceptation d'un
bloc reçu. Un relay sans tx ne produit rien.

### Sync (rattrapage)

À chaque connexion à un pair, le relay demande
`GetBlocks(start = height_locale + 1)`. Chaque `Block` reçu qui
complète exactement la hauteur attendue déclenche la demande de la
hauteur suivante, jusqu'à épuisement (`Pong` = rien de plus) ou
`MAX_SYNC_ROUNDS` (10 000) lots — borne absolue même contre un pair
menteur. Les blocs reçus passent par la validation complète : un pair
malveillant ne peut faire accepter quoi que ce soit d'invalide.

### DHT des records

- **put** (RPC `put_record`) : décodage strict borné
  (`MAX_DHT_CACHE_ENTRY`), vérification contre l'état on-chain
  (propriétaire, séquence, `record_hash` recalculé — voir
  « Vérification des records »), puis `kad.put_record` (stockage
  local + réplication aux pairs les plus proches, `Quorum::Majority`
  du facteur de réplication) et cache persistant redb.
- **get** (RPC `get_record`) : `kad.get_record` ; le waiter est lié
  à son `QueryId` et au `DomainId` demandé — une réponse ne résout
  que la requête correspondante, et la clé du record doit être
  exactement le domaine demandé (vérifié **avant** la vérification
  on-chain). Le résultat est ensuite vérifié contre la chaîne avant
  d'être retourné. Plafond de requêtes simultanées :
  `MAX_DHT_WAITERS` (256) ; au-delà, erreur immédiate. Une
  résolution vérifiée avec succès est écrite dans le cache persistant
  (M5) : les lectures locales (`domain_info`) la servent ensuite
  sans nouvelle requête DHT.
- Kademlia fonctionne en mode serveur, sans TTL de records (la chaîne
  gouverne la validité, pas le temps).

### Vérification des records (règle « la chaîne est l'autorité »)

Un `SignedDnsRecord` résolu ou reçu n'est accepté/retourné que si :

1. le domaine est enregistré on-chain ;
2. `record.owner` = propriétaire on-chain actuel ;
3. `record.sequence` = séquence on-chain actuelle ;
4. `record_hash(record.record)` (BLAKE3 recalculé) = le
   `record_hash` engagé on-chain.

Sinon : rejet silencieux côté P2P, erreur explicite côté RPC. La
signature Ed25519 du record est transportée pour les vérificateurs
futurs (le DNS resolver M5 la vérifiera avec la clé publique du
propriétaire) — l'engagement on-chain reste le contrôle d'intégrité
primaire.

## RPC de contrôle local

Socket TCP **127.0.0.1 uniquement** (le CLI tourne sur la même
machine). Une requête par connexion.

### Format de trame (les deux sens)

```text
len: u32 big-endian || JSON UTF-8 || '\n'
```

`len` inclut le `\n` final. Borne : 512 Kio (`MAX_RPC_LEN`) — au-delà,
erreur typée sans lecture du corps.

### Requêtes

Toutes en JSON, discriminées par `"method"` :

```json
{"method": "status"}
{"method": "submit_tx", "tx_hex": "<hex canonique de la Transaction signée>"}
{"method": "lookup", "name": "example.uip"}
{"method": "put_record", "record_hex": "<hex canonique du SignedDnsRecord>"}
{"method": "get_record", "name": "example.uip"}
{"method": "domain_info", "name": "example.uip"}
```

### Réponses

```json
{"status": "ok", "data": { … }}
{"status": "error", "message": "…"}
```

Formes de `data` par méthode :

- **status** : `{"peer_id", "tip" (hex 64), "height", "peers",
  "domain_count", "mempool"}`
- **submit_tx** : `{"txid": "<hex 64>"}` (tx acceptée au mempool ; la
  production intervient au tick suivant)
- **lookup** : `{"name", "domain_id", "registered": bool, "owner",
  "sequence", "record_hash"}` (champs on-chain absents si non
  enregistré)
- **put_record** : `{"published": "<domain_id hex 64>"}`
- **get_record** : `{"record": "<hex canonique>", "verified": true}`
  — la réponse n'est **jamais** émise sans vérification on-chain
  réussie ; non trouvé / non vérifié → `error`.
- **domain_info** (M5) : `{"name", "domain_id", "registered": bool,
  ["owner", "sequence", "record_hash"], "dns": [ … ]}`. Exploration
  riche en **lecture locale uniquement** (aucune requête réseau,
  aucun waiter DHT) : la partie `dns` n'est remplie que si ce nœud
  détient en cache local un `SignedDnsRecord` qui vérifie
  intégralement contre l'état on-chain courant (règles de
  « Vérification des records ») ; sinon `dns: []`. Chaque entrée
  `dns` est un objet `{"type": "A"|"AAAA"|"CNAME"|"NS"|"MX"|"TXT"|"TYPE<code>",
  "value": …}` (MX ajoute `"preference"`).

### Sémantique temporelle

`status`, `submit_tx`, `lookup`, `put_record` et `domain_info`
répondent immédiatement. `get_record` lance une requête Kademlia
asynchrone : la connexion RPC reste ouverte jusqu'à résolution
(borne 30 s côté relay, 60 s côté client).

## CLI

```
scone relay [--data-dir DIR] [--listen MULTIADDR] [--bootstrap MULTIADDR]... [--rpc ADDR]
scone status [--rpc ADDR]
scone submit tx --hex HEX [--rpc ADDR]
scone lookup NAME [--rpc ADDR]
scone domain register NAME --identity ID [--dir DIR] [--passphrase-env VAR] [--rpc ADDR]
scone domain update NAME --file FILE --identity ID [--dir DIR] [--passphrase-env VAR] [--rpc ADDR]
scone domain info NAME [--rpc ADDR]
scone record put NAME --file FILE [--rpc ADDR]      # FILE = hex canonique
scone record get NAME [--rpc ADDR]
```

`--rpc` défaut `127.0.0.1:7474` (le port que `scone relay` bind par
défaut ; deux relays sur une même machine passent chacun leur
`--rpc`). Relay absent → message clair « cannot reach the relay — is
'scone relay' running? », exit non nul.

### `domain register|update` (M5) — transactions signées en une commande

Ces commandes enchaînent build → sign (keystore) → submit →
(confirmation) en une seule invocation ; elles suppriment le
pipe-shell `tx build | tx sign | submit tx` du devnet M4.

- **register** : construit une `Register` signée (timestamp = now,
  proof vide en devnet), la soumet, attend la confirmation on-chain
  (séquence ≥ 0, timeout 30 s). Un nom déjà enregistré est refusé
  côté client ET côté relay.
- **update** : le fichier de records est l'unique source de vérité.
  La séquence (on-chain + 1) et le `record_hash` (BLAKE3 canonique
  des records du fichier) sont **dérivés**, jamais saisis : signataire
  et vérificateurs ne peuvent pas diverger. Après confirmation de
  l'Update, le `SignedDnsRecord` (records du fichier + owner +
  signature Ed25519 sur l'encodage canonique) est publié dans la
  DHT via `put_record` (qui revérifie contre la chaîne). Un domaine
  non enregistré, une identité non-propriétaire ou une erreur de
  fichier échouent proprement, sans toucher à la chaîne.

#### Fichier de records

Texte, un record par ligne, `#` = commentaire, lignes vides
ignorées ; l'encodage canonique trié rend l'ordre du fichier sans
effet sur le hash engagé. Le fichier est le set COMPLET (un update
remplace, il ne fusionne pas). Types :

```text
A 192.0.2.1
AAAA 2001:db8::1
CNAME www.example.uip
NS ns1.example.uip
MX 10 mail.example.uip
TXT texte libre (espaces normalisés)
```

Erreurs typées : type inconnu, IP/nom invalide (avec numéro de
ligne), set vide, doublon, > `MAX_RECORDS_PER_SET`.

## Limites et garanties mémoire

| Ressource | Borne |
|---|---|
| Trame P2P | `MAX_MESSAGE_LEN` (1 Mio) avant parsing |
| Trame RPC | 512 Kio avant parsing |
| Connexions RPC simultanées | `MAX_RPC_CONNECTIONS` (64, sémaphore) |
| Waiters DHT simultanés | `MAX_DHT_WAITERS` (256) |
| Mempool | 4096 tx (rejet typé au-delà) |
| Blocs par réponse sync | 1 par aller-retour ; ≤ 10 000 lots par pair |
| Record DHT | `MAX_DHT_CACHE_ENTRY` (64 Kio) |
| Chaîne en RAM | fenêtre genesis + tip (historique servi par le store) |

Règle anti-boucle (H2) : une transaction n'est re-diffusée que si elle
vient d'être **réellement insérée** au mempool (première vue) ; un
doublon (déjà en pool ou déjà en chaîne) n'est jamais re-relayé. Un
bloc déjà canonique est détecté et ignoré avant `push_block` (aucun
re-store, aucun re-broadcast).

Décisions ouvertes : identité réseau persistante du relay, fork
choice réel, consensus PoW, DNS resolver, gossip de diffusion
(actuellement : request-response unicast vers chaque pair connu).
