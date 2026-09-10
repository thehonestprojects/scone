# Scone

Scone est un protocole DNS décentralisé P2P.

Le DNS traditionnel repose sur des registrars, des registres et une chaîne
de délégation centralisée. Scone supprime le registrar central : la
propriété d'un nom est cryptographique, inscrite sur une blockchain, et les
données DNS elles-mêmes sont servies depuis une DHT par des nœuds pairs.

- **Pas de registrar central** — un nom se réclame, il ne s'achète pas auprès d'une autorité.
- **Propriété cryptographique** — un nom appartient à qui détient la clé qui l'a enregistré ; toute mise à jour doit être signée.
- **Blockchain pour l'autorité et l'ordre** — ownership, autorisation, séquences et record hashes relèvent du consensus. La chaîne est la source de vérité sur *qui possède quoi* et *dans quel ordre*.
- **DHT pour les données DNS** — les enregistrements complets sont répliqués entre pairs ; la DHT fournit de la disponibilité, pas de l'autorité. Un nœud considère les données DHT comme non fiables tant qu'elles ne sont pas vérifiées cryptographiquement contre la chaîne.
- **Nœuds P2P** — tout nœud peut résoudre, servir et répliquer.
- **Local-first** — chaque nœud conserve son état, ses index et ses caches localement et peut opérer de façon autonome.
- **Très grande échelle** — la chaîne reste fine (des hashs, pas des payloads) ; la DHT absorbe le volume.

```text
                 Scone
                   │
       ┌───────────┴───────────┐
       │                       │
  Blockchain                  DHT
       │                       │
 ownership/order          DNS records
       │                       │
       └───────────┬───────────┘
                   │
                Node
                   │
                  DNS
```

## Crates

| Crate | Rôle |
|---|---|
| `scone-core` | Types purs du protocole : noms, identifiants, records DNS, transactions |
| `scone-crypto` | Primitives cryptographiques (hash BLAKE3, clés/signatures Ed25519 RFC 8032) |
| `scone-protocol` | Format binaire canonique wire/blockchain : encodage/décodage des transactions, records DNS, blocs et messages P2P |
| `scone-blockchain` | Logique de chaîne et état canonique en RAM (validation des transactions, Merkle, chaîne de blocs) |
| `scone-storage` | Persistance locale (trait `NodeStore` + backend redb) |
| `scone-keystore` | Clés Ed25519 chiffrées sur disque (Argon2id + XChaCha20-Poly1305) |
| `scone-network` | Relay P2P libp2p (swarm QUIC, sync blocs, DHT Kademlia, RPC de contrôle) |
| `scone` | Binaire / CLI (`scone relay/status/submit/lookup/record`, `scone identity …`, `scone tx build/sign/verify`) |

Documentation détaillée : [`docs/architecture.md`](docs/architecture.md),
[`docs/protocol.md`](docs/protocol.md), [`docs/naming.md`](docs/naming.md).

## Status

Early development — **Jalon M4 (relay réseau) atteint**.

En place :

- **Types purs** (`scone-core`) : noms, `DomainId`, records DNS,
  transactions **signées v2** (`public_key` + `signature`,
  owner recomputé), `OwnerId`.
- **Primitives cryptographiques** (`scone-crypto`) : `hash256`
  (BLAKE3), clés et signatures **Ed25519** (`ed25519-dalek` 3.0,
  vecteurs de test RFC 8032, vérification stricte).
- **Format binaire canonique** (`scone-protocol`) : transactions
  **signées v2** (payload `SCONE-TX-SIG-V1`, bornes strictes pk
  32 o / signature 64 o, rejet explicite du format v1), records DNS,
  blocs, messages P2P, limites, version 2.
- **Blockchain** (`scone-blockchain`) : chaîne, état canonique en
  RAM, racines Merkle, bloc genesis, **validation cryptographique des
  transactions** (binding owner/clé + `verify_strict`), BlockBuilder,
  cadre de consensus (le consensus réel — PoW/difficulté/fork choice
  — reste à implémenter).
- **Keystore chiffré** (`scone-keystore`) : keyfiles `.sconekey`
  (Argon2id + XChaCha20-Poly1305), voir
  [`docs/development/keystore.md`](docs/development/keystore.md).
- **Stockage persistant** (`scone-storage`, M3) : trait `NodeStore` +
  backend redb (appends delta atomiques, états paginés), voir
  [`docs/development/storage.md`](docs/development/storage.md).
- **Relay réseau** (`scone-network`, M4) : nœud libp2p complet —
  QUIC, identify, ping, Kademlia (records DNS signés), sync de blocs
  bornée, mempool, production devnet, RPC de contrôle local. Voir
  [`docs/development/relay.md`](docs/development/relay.md).
- **CLI** (`scone`) : `scone show <name>`, `scone identity …`,
  `scone tx build/sign/verify`, **`scone relay`** (daemon) et
  **`scone status / submit tx / lookup / record put|get`** (parlent
  au RPC du relay).

Non implémentés : PoW/consensus réel, serveur DNS, gouvernance des
forks, identité réseau persistante du relay.

## Essayer le relay (devnet)

```bash
# Terminal 1 — le nœud
scone relay --data-dir /tmp/node-a

# Terminal 2 — enregistrer un nom
scone identity generate --name alice
scone tx build register --name example.uip | tail -1   # payload à signer
scone tx sign <payload> --identity alice | tail -1      # hex de la tx signée
scone submit tx --hex <tx-hex>
sleep 2                                                  # production devnet
scone status                                             # height: 1
scone lookup example.uip
```

## Développement

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
