# CLI (`scone`) — logging et verbosité

> Comportement normatif du logging du binaire `scone`. Toute divergence
> doc/code = bug (corriger la source de vérité).

## Principes

- **stdout est réservé aux sorties de commandes** (`scone show`,
  `identity list`, `status`, …). Un script peut rediriger stdout sans
  jamais y trouver de logs — le piping reste fiable. Exception
  assumée : `scone relay` émet **une** ligne de données
  `p2p: <multiaddr>` sur stdout dès que l'écouteur est lié (donnée
  exploitable pour `--bootstrap`, pas un log ; émise une seule fois,
  flushée immédiatement).
- **Tous les logs vont sur stderr** (format compact `tracing`), y
  compris ceux du relay — le relay loggait déjà sur stderr avant la
  migration.
- Les messages d'erreur utilisateur du CLI (`scone: <erreur>`) restent
  sur stderr : c'est de l'UX, pas des logs.

## Niveaux et `--verbose` / `-v`

| Invocation | Niveau effectif |
|---|---|
| `scone <cmd>` (sans `-v`) | `warn` |
| `scone relay` (sans `-v`) | `info` |
| `scone -v <cmd>` / `scone relay -v` | `info` |
| `scone -vv …` | `debug` |
| `scone -vvv …` (et plus) | `trace` |

`-v`/`--verbose` est un drapeau **global et répétable** : il s'accepte
avant ou après la sous-commande (`scone -vv identity list` et
`scone identity list -vv` sont équivalents).

**Pourquoi `scone relay` reste à INFO par défaut** : le relay est un
daemon — il doit logger son activité (écoute RPC/p2p, blocs acceptés
et produits, pairs connectés, rejets) pour être opérable, sans exiger
un drapeau. Les commandes one-shot, elles, restent silencieuses (WARN)
pour ne pas polluer un terminal ou un script.

## `RUST_LOG` (override)

Si la variable d'environnement `RUST_LOG` est définie, elle **remplace
entièrement** le niveau dérivé de `-v` (syntaxe `env-filter`) :

```bash
RUST_LOG=debug scone identity list        # debug sans -v
RUST_LOG=error scone -vv relay            # error gagne sur -vv
RUST_LOG=scone_network=trace,info scone relay   # par-cible
```

## Sémantique des niveaux (convention du code)

- `error!` : échecs (aucun site aujourd'hui — les échecs réseau sont
  avalés comme `warn!` et seuls les échecs locaux fatals remontent en
  erreur typée du `run()`) ;
- `warn!` : entrées réseau hostiles ou malveillantes écartées, tx
  périmées éjectées du mempool, tx conflictuelles abandonnées en
  production, échecs outbound/inbound, key mismatch DHT ;
- `info!` : bloc accepté/produit, écoute RPC/p2p, pair connecté,
  démarrage du relay (checkpoints d'état) ;
- `debug!` : détails internes (tx acceptée, pair déconnecté, round
  trip RPC, listing keystore, événements kad sous `SCONE_KAD_DEBUG`) ;
- `trace!` : réservé aux payloads (aucun site aujourd'hui).

Les crates lib (`scone-network`, …) émettent des macros `tracing`
mais **n'initialisent aucun subscriber** : l'initialisation vit
uniquement dans le binaire `scone` (avant le dispatch des
sous-commandes — le relay a besoin de ses logs dès le boot).
