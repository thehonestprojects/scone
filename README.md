# Scone

**DNS décentralisé, sans registrar.** Un nom de domaine se réclame, il ne
s'achète pas : la propriété est cryptographique, inscrite sur une blockchain,
et les données DNS sont servies par un réseau de pairs.

## Pourquoi Scone

- **Pas d'autorité centrale à payer ou à convaincre** — le registrar est
  remplacé par une chaîne : un nom appartient à qui détient la clé qui l'a
  enregistré, point final. Toute modification doit être signée par cette clé.
- **Impossible à falsifier silencieusement** — la chaîne est la source de
  vérité (*qui possède quoi, dans quel ordre*) ; les records circulant sur la
  DHT ne sont jamais crus : chaque nœud les re-vérifie cryptographiquement
  contre la chaîne avant de les servir. Un record falsifié est simplement
  ignoré.
- **Résistant et local-first** — pas de serveur à abattre : chaque nœud est
  autonome (état, index, caches locaux), tout nœud peut résoudre, servir et
  répliquer.
- **Conçu pour l'échelle** — la chaîne reste fine (des hashs, pas des
  payloads) ; la DHT absorbe le volume. Empreinte mémoire maîtrisée :
  persistance redb avec curseurs, jamais tout en RAM.

## Pourquoi laisser tourner un relay

Chaque relay fait vivre le réseau :

- **Vous servez le DNS décentralisé** — votre nœud répond aux requêtes DNS
  des autres (serveur UDP intégré) et réplique les records : plus de relays,
  plus de disponibilité et de résilience pour tout le monde.
- **Vous renforcez la sécurité collective** — chaque relay est un validateur
  de plus : blocs et transactions re-validés intégralement, données DHT
  re-vérifiées contre la chaîne. Un réseau de relays honnêtes rend la
  censure et la corruption pratiquement impossibles.
- **C'est léger et sûr** — un process unique, stockage local borné, clés
  chiffrées au repos, aucune donnée personnelle. Vous gardez le contrôle :
  tout est local, rien n'est téléphoné.

```bash
scone relay              # c'est tout. Logs sur stderr, adresse p2p sur stdout.
```

## Utiliser le CLI

```bash
# Identités (clés Ed25519 chiffrées sur disque)
scone identity generate --name alice
scone identity list
scone identity show --name alice

# Domaines
scone domain register example.uip --identity alice
printf 'A 192.0.2.1\nTXT "hello scone"\n' > records.txt
scone domain update example.uip --file records.txt --identity alice
scone domain info example.uip      # exploration : état chaîne + records vérifiés
scone lookup example.uip           # état on-chain seul
scone show example.uip             # DomainId (hex)

# Records DNS (DHT)
scone record get example.uip       # résolution + vérification cryptographique
scone record put <hex>

# Réseau
scone relay                        # lancer un nœud (voir ci-dessus)
scone status                       # tip, hauteur, pairs, domaines
scone dig example.uip --dns <addr> # requête DNS réelle au serveur du relay

# Transactions (avancé / hors-ligne)
scone tx build | sign | verify
scone submit tx --hex <hex>
```

La mise à jour des records est **atomique** : le fichier est l'unique source
de vérité, l'ensemble remplace le précédent en une transaction signée.

Documentation complète : [`docs/README.md`](docs/README.md) — volet
[général](docs/general/architecture.md) (« comment ça marche ») et volet
[technique](docs/technical/protocol.md) (formats, invariants, développeurs).

## Statut

Devnet fonctionnel de bout en bout : identités, transactions signées,
blockchain locale, stockage persistant, réseau P2P multi-nœuds, serveur DNS
UDP. Consensus réel (PoW/sélection de producteur) non implémenté — voir
[docs](docs/README.md) pour l'état détaillé.

## Développement

```bash
cargo check --workspace && cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
