# Modèle de sécurité — sélection de comité et anti-grinding

> Document normatif. Toute divergence doc/code = bug.

## Vue d'ensemble

Le comité de l'epoch N+1 est tiré de la seed
`next_seed(hash(checkpoint N)) = blake3("SCONE-SEED-V1" || hash(checkpoint N))`,
sur le **pool d'éligibilité gelé au bloc finalisé par le checkpoint N**.

## Menace : grinding de la seed du comité

Un attaquant veut influencer la composition du comité. Trois fenêtres
d'attaque existent ; toutes trois sont fermées structurellement :

### 1. Avant la seed — impossible de grinder sa position

La seed de l'epoch N+1 dérive du **hash du checkpoint N**, signé par
quorum (⌈2n/3⌉ du comité N). Le checkpoint N engage le `state_root`
d'un état qui **fixe le pool** (base PoS = état exact au bloc finalisé,
`FinalizedBase.pool`). Produire une autre seed exigerait un autre
checkpoint quorum-signé — c'est-à-dire corrompre ≥ 1/3 du comité N,
ce qui est la hypothèse de faute exclue par le modèle BFT.

### 2. Après la seed — trop tard pour entrer

Toute inscription (claim de domaine/TLD, apparition d'une nouvelle
clé owner) ne compte que pour les epochs suivantes, dont les seeds ne
sont pas encore connues. Le pool est gelé dans `FinalizedBase` AVANT
que quiconque (y compris les signataires du checkpoint N) ne puisse
calculer la seed de N+1.

### 3. Sélection « best-of-m » sans avantage

La position d'une clé dans le tirage =
`blake3("SCONE-COMMITTEE-V1" || seed || pk)` (uniforme), dont le seul
degré de liberté est `pk`. Un grinder qui génère m clés et
n'enregistre que la mieux positionnée doit d'abord **connaître la
seed** — or à ce moment le pool est déjà figé. Enregistrer m
candidates « au cas où » coûte m preuves de travail (une par
domaine/TLD) et donne exactement m/|pool| de présence en espérance :
**aucun avantage sur m enregistrements directs**. La stratégie
adaptive (voir la seed, puis choisir quoi enregistrer) est
temporellement impossible.

### 4. Last-producer bias (attaque par retenue)

Le producteur du dernier bloc avant un checkpoint pourrait retenir
son bloc pour influencer `hash(checkpoint N)` et donc la seed. Deux
garde-fous :

- le checkpoint signe un état à la hauteur H, et le **pool est évalué
  au timestamp du bloc H** — retenir un bloc retarde le checkpoint
  mais ne change pas le pool d'une epoch déjà gelée par le checkpoint
  N−1 (les pools se chevauchent peu d'epoch en epoch) ;
- la retenue coûte à l'attaquant sa propre récompense de production
  et n'affecte que la LIVENESS (checkpoint retardé), jamais la
  SAFETY : deux checkpoints finaux incompatibles exigeraient ≥ 1/3 de
  double-signatures, prouvables par `SlashTx` et punies de
  bannissement.

Conclusion : un VRF ou un commit-reveal n'apporterait rien ici — la
seed est déjà une fonction d'un événement quorum-signé
imprévisible-retardable-mais-pas-falsifiable, et le gel du pool
supprime le seul levier adaptatif. Ne pas complexifier le protocole
(contrainte P1.7 : « si nécessaire » — analyse : non nécessaire).

## Équivocation et slashing

Un anchor qui signe deux checkpoints conflictuels à la même epoch
peut être prouvé par quiconque détient les deux signatures
(`SlashTx`, discriminant `0x15`) : bannissement du pool PoS
(journalisé, annulable au reorg). Les domaines/TLD de l'accusé ne
sont pas saisis (sanction minimale — décision M9).

## Propriétés vérifiées par tests

- `checkpoint_hash_engages_signatures` : le hash du checkpoint
  couvre les signatures (pas de falsification post-hoc) ;
- `seed_chain_and_recovery` : la chaîne de seeds dérive
  exactement, recovery k compris ;
- `small_committee_never_finalizes` : garde BFT — un comité sous
  `MIN_FINALITY_COMMITTEE_SIZE` ne finalise jamais ;
- e2e 4 relais : un checkpoint se finalise et se propage, même
  epoch sur tous les nœuds.

## Limites connues (documentées, non corrigées)

- Le pool éligible inclut les owners de TLD vivants (claim = PoW
  dépensé) — surface Sybil bornée par le coût du PoW par clé ;
- Le `state_root` du checkpoint n'est vérifié en RAM que lorsque le
  checkpoint vise la pointe ; le rejeu rétroactif est un chemin
  storage/relay (voir `docs/technical/blockchain.md`).
