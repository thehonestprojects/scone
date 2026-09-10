# Keystore — spécification du format keyfile `.sconekey`

> Document normatif. Toute divergence entre ce document et
> `crates/scone-keystore/src/lib.rs` est un bug (identifier la source
> de vérité, corriger). Référence d'implémentation : crate
> `scone-keystore` (v1).

## Objectif

Stocker une clé privée Ed25519 (le *seed*, 32 octets) sur disque,
chiffrée par une passphrase. La clé ne touche **jamais** le disque en
clair ; tous les secrets (passphrase, matériau dérivé) sont zeroizés
en mémoire après usage.

## Vue d'ensemble

- **KDF** : Argon2id (v0x13), paramètres par défaut `m_cost` = 64 MiB,
  `t_cost` = 3, `p_cost` = 1 (défaut de la crate `argon2`).
- **Chiffrement** : XChaCha20-Poly1305 (AEAD), clé de 32 octets dérivée
  du KDF, nonce de 24 octets aléatoire par fichier.
- **Contenu chiffré** : exactement le seed Ed25519 (32 octets) ; le tag
  Poly1305 (16 octets) est stocké en suffixe du ciphertext (sortie
  standard de l'API AEAD `encrypt`).

## Format binaire (v1) — 100 octets exactement

```text
Offset  Taille      Champ
0       9           magic : "SCONEKEY1" (ASCII)
9       1           version : u8 = 1
10      1           m_cost_mib : u8 (m_cost en MiB ; m_cost_kib = valeur × 1024)
11      1           t_cost : u8 (itérations Argon2id)
12      16          salt Argon2id (aléatoire par fichier)
28      24          nonce XChaCha20-Poly1305 (aléatoire par fichier)
52      48          ciphertext (32 octets seed chiffré) || tag Poly1305 (16 octets)
```

Tous les entiers sont des octets bruts, non signés, sans endianness
(champs d'un octet uniquement). Longueur totale : 100 octets.

### Choix de conception

- **Paramètres KDF dans le fichier** : `m_cost_mib` et `t_cost` sont
  lus depuis l'en-tête (pas codés en dur à la lecture), ce qui permet
  de les augmenter dans de futures versions sans casser les fichiers
  existants.
- **Bornes de sécurité à la lecture** : un fichier déclarant
  `m_cost_mib` > 64 ou `t_cost` = 0 ou > 10 est rejeté
  (`Error::InvalidParams`) *avant* toute allocation — un fichier
  malveillant ne peut pas forcer un nœud à allouer des gigaoctets ou
  boucler indéfiniment. La valeur par défaut à l'écriture est
  `m_cost_mib` = 64, `t_cost` = 3.
- **Magic + version explicites** : un fichier qui n'est pas un keyfile
  (`Error::InvalidFile`) ou d'une version non supportée
  (`Error::UnsupportedVersion`) est rejeté proprement, sans panic.
- **Mauvaise passphrase** : l'échec d'authentification Poly1305
  n'indique pas *pourquoi* il échoue ; mauvaise passphrase et ciphertext
  corrompu sont donc indistinguables et remontent la même erreur
  distincte `Error::WrongPassphrase`.

## Dérivation de la clé de chiffrement

```text
key = Argon2id(passphrase, salt, m_cost = m_cost_mib × 1024 KiB,
               t_cost = t_cost, p_cost = 1, output = 32 octets)
```

Puis :

```text
ciphertext || tag = XChaCha20-Poly1305-Seal(key, nonce, plaintext = seed)
```

Pas de données associées (AAD) en v1. Le nonce de 24 octets, aléatoire
par fichier, rend négligeable le risque de réutilisation de nonce
(les keyfiles sont écrits une seule fois).

## API (`scone-keystore`)

| Fonction | Rôle |
|---|---|
| `create(path, passphrase) -> GeneratedKey` | Génère une clé, écrit le keyfile chiffré (crée les répertoires parents) ; **refuse d'écraser** un fichier existant (`Error::KeyfileExists`) ; retourne la clé en mémoire |
| `create_overwriting(path, passphrase) -> GeneratedKey` | Idem, mais remplace explicitement un keyfile existant |
| `open(path, passphrase) -> SigningKey` | Déchiffre et retourne la clé de signature |
| `list(dir) -> Vec<KeyEntry>` | Liste les fichiers `*.sconekey` d'un répertoire (triés par nom) ; répertoire absent = liste vide |

`GeneratedKey.signing_key` est zeroizé au drop par `ed25519-dalek`
(feature `zeroize` par défaut). La clé AEAD dérivée, le seed et le
plaintext déchiffré sont enveloppés dans `zeroize::Zeroizing` :
le Drop couvre tous les chemins de sortie, y compris les erreurs
propagées par `?`.

## Permissions du fichier

Sur Unix, le keyfile est créé avec les permissions `0600`
(lecture/écriture par le propriétaire uniquement), via
`OpenOptions` + `set_permissions` — indépendamment du umask du
processus. L'existence et la création sont atomiques (`create_new`,
`O_EXCL`) : deux générations concurrentes ne peuvent pas s'écraser
silencieusement.

## CLI

```bash
scone identity generate --name <n> [--dir <répertoire>] [--passphrase-env VAR] [--force]
scone identity list [--dir <répertoire>]
scone identity show --name <n> [--dir <répertoire>] [--passphrase-env VAR]
```

- Répertoire par défaut : `$HOME/.scone/keys`.
- Le nom d'identité est validé strictement : vide, `.`, `..`, `/`,
  `\`, NUL, point initial et suffixe `.sconekey` sont rejetés
  (le nom devient un nom de fichier dans le répertoire keys — aucun
  composant de chemin ne peut s'échapper du keystore).
- Sans `--passphrase-env`, la passphrase est demandée sur le terminal
  **en saisie masquée** (`rpassword` : pas d'écho ; deux fois avec
  confirmation pour `generate`).
- `identity generate` **refuse d'écraser** un keyfile existant ;
  `--force` remplace explicitement (nouveau salt/nonce, nouvelle clé).
- `identity show` affiche la clé publique et l'`OwnerId` en hex
  minuscule (64 caractères, même convention que `DomainId`),
  recalculés via `scone-core` (`PublicKeyRef` → `OwnerId`) — jamais
  dupliqués.

## Ce que ce format ne fait pas (volontairement)

- Pas de plusieurs clés par fichier (un seed par fichier).
- Pas de changement de passphrase (à venir le cas échéant : réécrire le
  fichier avec nouveau salt/nonce).
- Pas de métadonnées (date de création, commentaire) : garder l'empreinte
  disque et la surface d'attaque minimales.
