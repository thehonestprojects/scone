# Scone

**DNS décentralisé, sans registrar.** Un nom se réclame, il ne s'achète
pas : la propriété est cryptographique, inscrite sur une blockchain,
les données DNS sont servies par un réseau de pairs.

## Pourquoi c'est génial

- **Personne à payer, personne à convaincre** — un nom appartient à
  qui détient la clé qui l'a enregistré. Toute modification doit être
  signée par cette clé.
- **Infalsifiable** — la chaîne est la seule source de vérité ; les
  records qui circulent sur la DHT sont toujours re-vérifiés contre
  elle avant d'être servis. Un record falsifié est ignoré.
- **Sans point de défaillance** — chaque nœud est autonome. Plus de
  relays, plus de résilience pour tous.
- **Prêt pour l'échelle** — état en KV paginé, engagement SMT O(1),
  finalité par checkpoints : des centaines de milliards de noms sur
  des machines ordinaires.

## Démarrage rapide

```bash
# Un nœud (relay) — c'est tout
scone relay

# Vos identités (clés chiffrées sur disque)
scone identity generate --name alice

# Enregistrer un domaine et publier ses records
scone domain register example.uip --identity alice
printf 'A 192.0.2.1\n' > records.txt
scone domain update example.uip --file records.txt --identity alice

# Résoudre
scone dig example.uip --dns <addr>   # ou n'importe quel dig/kdig du système
```

Statut : testnet fonctionnelle de bout en bout — PoS avec finalité
par checkpoints, DNS UDP+TCP, réseau multi-nœuds. Documentation
complète : [`docs/`](docs/README.md).

## Développement

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
