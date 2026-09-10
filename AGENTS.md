# Scone — contexte projet (agents)

Protocole DNS décentralisé P2P en Rust. Repo : `~/Developpement/scone`.

## Vision

Sans registrar central : propriété cryptographique d'un nom inscrite sur une
blockchain, données DNS servies par une DHT. La chaîne = autorité (qui possède
quoi, dans quel ordre) ; la DHT = disponibilité, jamais autorité. Toute donnée
DHT est non fiable tant qu'elle n'est pas vérifiée contre la chaîne.

## Stack (workspace, edition 2024)

```
scone-crypto    ← primitives (BLAKE3 hash256 ; signatures/PoW/Merkle à venir)
scone-core      ← types purs : noms, DomainId (32 o), records DNS, transactions
scone-protocol  ← format binaire canonique wire/blockchain
scone-blockchain← logique chaîne, état canonique en RAM
scone-storage   ← persistance locale (trait NodeStore + backend redb)
scone           ← binaire
```

## Règles dures du projet

- DomainId = 32 octets, JAMAIS tronqué (identité consensus, pas une clé
  d'accélération).
- Aucune crypto maison : uniquement des implémentations auditées.
- Les couches basses (crypto/core/protocol) ne font NI réseau NI filesystem
  NI async.
- Jamais de panic sur données non fiables : tout décodage strict, erreurs
  typées (thiserror).
- Les hashs fournis (tx_root, etc.) sont toujours recalculés, jamais crus.
- Déterminisme : deux nœuds qui appliquent les mêmes blocs atteignent le même
  état bit à bit.
- Domaines : Register (nom libre requis) / Update (owner + séquence exacte
  current+1). Pas de Transfer ni d'expiration pour l'instant — décisions
  ouvertes.

## Commandes de validation (preuves exigées)

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Documentation = spécification

`docs/` (architecture, protocol, naming, blockchain) est NORMATIF : la doc du
protocole doit permettre une implémentation indépendante sans lire le Rust.
Toute divergence doc/code = bug (identifier la source de vérité, corriger).

## État (2026-09-10)

Socle v2 en place (commit b0dbdc0) : ~184 tests verts, clippy propre.
Signatures Ed25519, PoW, consensus réel, DHT, réseau et serveur DNS non
implémentés. Pas de remote git configuré.
