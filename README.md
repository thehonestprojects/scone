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
| `scone-crypto` | Primitives cryptographiques (hash BLAKE3 ; signatures, PoW, Merkle à venir) |
| `scone-protocol` | Format binaire canonique wire/blockchain : encodage/décodage des transactions, records DNS, blocs et messages P2P |
| `scone-storage` | Abstraction de stockage local (backend redb à venir) |
| `scone` | Binaire / CLI |

Documentation détaillée : [`docs/architecture.md`](docs/architecture.md),
[`docs/protocol.md`](docs/protocol.md), [`docs/naming.md`](docs/naming.md).

## Status

Early development

Le socle est en place : types purs (`scone-core`), primitives
cryptographiques (`scone-crypto` : `hash256`) et format binaire
canonique (`scone-protocol` : transactions, records DNS, blocs,
messages P2P, limites, version). La blockchain, le consensus, le PoW,
la DHT, le réseau et le serveur DNS **ne sont pas implémentés**.

## Développement

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
