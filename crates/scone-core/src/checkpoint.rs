//! Checkpoints finalisés par le comité d'Anchors (PoS) — la finalité du
//! protocole.
//!
//! # Chaînage
//!
//! `CheckpointData.prev_checkpoint_hash` = `hash(checkpoint N-1)` : un
//! checkpoint finalisé engage tout l'historique au-dessus du précédent. La
//! seed de sélection du comité suivant est dérivée du checkpoint : impossible
//! de choisir la seed sans finaliser un checkpoint (qui exige un quorum).
//!
//! # Sélection PoS (§ seed)
//!
//! Éligibilité = être owner d'au moins un domaine VIVANT à l'état du dernier
//! checkpoint (coût d'entrée : PoW REGISTER + renewal — anti-Sybil économique,
//! sans token ni récompense). Comité = top-N des éligibles triés par
//! `blake3("SCONE-COMMITTEE-V1" || seed || pubkey)` : déterministe,
//! vérifiable par tout nœud ayant rejoué la chaîne jusqu'au checkpoint.
//!
//! # Recovery
//!
//! Si le comité ne parvient plus au quorum, chaque epoch écoulée k donne un
//! NOUVEAU tirage `blake3("SCONE-RECOVERY-V1" || seed || k)` sur le même pool
//! d'éligibles : le remplacement des absents est pré-déterminé (avant les
//! pannes), jamais choisi par un acteur. Un checkpoint recovery
//! (`recovery = k >= 1`) exige le même quorum sur son tirage — la sécurité ne
//! baisse jamais (§ quorum constant).
//!
//! # Immuabilité
//!
//! Un checkpoint finalisé n'est JAMAIS réécrit : ni Anchors, ni recovery, ni
//! procédure externe ne peuvent produire un checkpoint contredisant un
//! `prev_checkpoint_hash` déjà finalisé (règle appliquée dans `Chain`).
//!
//! # Encodage
//!
//! Ce module est **pur** : pas d'encodage wire (délégué à `scone-protocol`,
//! M-wire). Seul [`CheckpointData::signing_bytes`] définit un préimage
//! canonique — c'est un format de signature stable, pas un format réseau.

use std::collections::{BTreeSet, HashSet};

use scone_crypto::{PublicKey, Signature, hash256};

/// Domain separation du contenu signé d'un checkpoint.
pub const CHECKPOINT_TAG: &[u8] = b"SCONE-CKPT-V1";
/// Domain separation du tirage de comité.
pub const COMMITTEE_TAG: &[u8] = b"SCONE-COMMITTEE-V1";
/// Domain separation du tirage recovery.
pub const RECOVERY_TAG: &[u8] = b"SCONE-RECOVERY-V1";
/// Domain separation de la seed d'epoch.
pub const SEED_TAG: &[u8] = b"SCONE-SEED-V1";

/// Hash 32 octets (BLAKE3-256), en tableau nu : `scone-core` n'a pas de
/// wrapper `Hash`, les primitives de `scone-crypto` échangent `[u8; 32]`.
pub type Hash = [u8; 32];

/// Hash du genesis des checkpoints (aucun prédécesseur).
pub const GENESIS_CHECKPOINT_HASH: Hash = [0; 32];

/// Contenu engagé par les signatures des Anchors — §5 du protocole : un
/// Anchor signe `epoch || height || prev || state_root` (et le bloc), jamais
/// « j'accepte ce bloc ».
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CheckpointData {
    /// Compteur d'epochs (checkpoint N → epoch N). Genesis : epoch 0 non
    /// signée.
    pub epoch: u64,
    /// Hauteur du bloc finalisé (strictement croissante).
    pub height: u64,
    /// Hash du bloc finalisé.
    pub block_hash: Hash,
    /// Hash du checkpoint précédent (chaînage ; genesis des checkpoints =
    /// [`GENESIS_CHECKPOINT_HASH`]).
    pub prev_checkpoint_hash: Hash,
    /// Engagement de l'état après application du bloc (recalculé par chaque
    /// Anchor).
    pub state_root: Hash,
    /// 0 = comité élu normal ; k ≥ 1 = k-ième tirage recovery depuis le
    /// checkpoint précédent.
    pub recovery: u32,
}

impl CheckpointData {
    /// Préimage canonique signée par les Anchors (116 B + tag).
    ///
    /// Champs ordonnés fixes, entiers little-endian, hash en tableau nu —
    /// format de signature stable, indépendant du futur encodage wire.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CHECKPOINT_TAG.len() + 116);
        buf.extend_from_slice(CHECKPOINT_TAG);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.recovery.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.prev_checkpoint_hash);
        buf.extend_from_slice(&self.state_root);
        buf
    }

    /// Hash signé par les Anchors (domain separation :
    /// [`CHECKPOINT_TAG`]).
    #[must_use]
    pub fn signing_hash(&self) -> Hash {
        hash256(&[&self.signing_bytes()])
    }
}

/// Checkpoint + signatures agrégées du comité. Finalisé ⇔
/// [`Checkpoint::verify_quorum`] passe contre le comité élu pour son epoch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    pub data: CheckpointData,
    /// Signatures des Anchors, triées par clé publique (canonique).
    pub signatures: Vec<(PublicKey, Signature)>,
}

impl Checkpoint {
    /// Hash du checkpoint (identifiant de chaînage :
    /// `prev_checkpoint_hash` du suivant) — engage le contenu ET l'ensemble
    /// des signatures.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut buf = Vec::with_capacity(32 + 4 + self.signatures.len() * 96);
        buf.extend_from_slice(&self.data.signing_hash());
        // Varint LEB128 minimal du nombre de signatures (encodage canonique,
        // identique au futur format wire).
        let mut n = self.signatures.len() as u64;
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                buf.push(b);
                break;
            }
            buf.push(b | 0x80);
        }
        for (pk, sig) in &self.signatures {
            buf.extend_from_slice(&pk.to_bytes());
            buf.extend_from_slice(&sig.to_bytes());
        }
        hash256(&[&buf])
    }

    /// Vérifie le quorum : signatures valides du message signé, signataires
    /// distincts membres du comité fourni, en nombre ≥ quorum. Ne fait
    /// AUCUNE confiance à la liste déclarée — chaque signature est vérifiée
    /// (`verify_strict` via `scone-crypto`).
    #[must_use]
    pub fn verify_quorum(&self, committee: &[PublicKey], quorum: usize) -> bool {
        let committee_set: HashSet<&PublicKey> = committee.iter().collect();
        let mut signers: HashSet<[u8; 32]> = HashSet::new();
        let msg = self.data.signing_hash();
        let mut valid = 0usize;
        for (pk, sig) in &self.signatures {
            if !committee_set.contains(pk) {
                continue; // hors comité : ignoré (le wire peut porter du bruit)
            }
            if !signers.insert(pk.to_bytes()) {
                continue; // doublon : jamais compté deux fois
            }
            if pk.verify(&msg, sig) {
                valid += 1;
            }
        }
        valid >= quorum
    }
}

/// Seed de sélection de l'epoch suivant : dérivée du checkpoint finalisé.
/// Déterministe après finalisation, non choisissable par un acteur isolé
/// (produire une autre seed exigerait un autre checkpoint quorum-signé).
#[must_use]
pub fn next_seed(checkpoint_hash: &Hash) -> Hash {
    hash256(&[SEED_TAG, checkpoint_hash])
}

/// Seed du tirage recovery k (k ≥ 1) dérivée de la seed de l'epoch.
#[must_use]
pub fn recovery_seed(epoch_seed: &Hash, k: u32) -> Hash {
    hash256(&[RECOVERY_TAG, epoch_seed, &k.to_le_bytes()])
}

/// Sélection PoS : top-`size` des éligibles triés par
/// `blake3(COMMITTEE_TAG || seed || pk)`.
///
/// Déterministe ; déduplique les clés ; le tri final par rang de hash (puis
/// par clé en cas d'égalité — impossible en pratique) rend le tirage
/// reproductible partout.
#[must_use]
pub fn select_committee(
    seed: &Hash,
    eligible: impl IntoIterator<Item = PublicKey>,
    size: usize,
) -> Vec<PublicKey> {
    let mut ranked: Vec<(Hash, PublicKey)> = BTreeSet::from_iter(eligible)
        .into_iter()
        .map(|pk| (hash256(&[COMMITTEE_TAG, seed, &pk.to_bytes()]), pk))
        .collect();
    ranked.sort();
    ranked.truncate(size);
    ranked.into_iter().map(|(_, pk)| pk).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_crypto::SigningKey;

    fn sks(n: u8) -> Vec<SigningKey> {
        (1..=n).map(|i| SigningKey::from_bytes([i; 32])).collect()
    }

    fn data(epoch: u64, height: u64, root: u8) -> CheckpointData {
        CheckpointData {
            epoch,
            height,
            block_hash: [root; 32],
            prev_checkpoint_hash: [0; 32],
            state_root: [root; 32],
            recovery: 0,
        }
    }

    fn signed(data: &CheckpointData, keys: &[SigningKey]) -> Checkpoint {
        let msg = data.signing_hash();
        let mut signatures: Vec<(PublicKey, Signature)> = keys
            .iter()
            .map(|sk| (sk.public_key(), sk.sign(&msg)))
            .collect();
        signatures.sort_by_key(|s| s.0);
        Checkpoint {
            data: data.clone(),
            signatures,
        }
    }

    #[test]
    fn signing_bytes_canonical_and_binding() {
        let d = data(3, 300, 7);
        // Préimage canonique : taille fixe, déterministe.
        assert_eq!(d.signing_bytes().len(), CHECKPOINT_TAG.len() + 116);
        assert_eq!(d.signing_bytes(), d.signing_bytes());
        // Chaque champ modifié change le hash signé.
        let base = d.signing_hash();
        let mut d2 = d.clone();
        d2.state_root = [8; 32];
        assert_ne!(d2.signing_hash(), base);
        let mut d3 = d.clone();
        d3.recovery = 1;
        assert_ne!(d3.signing_hash(), base, "recovery engage la signature");
        let mut d4 = d.clone();
        d4.epoch += 1;
        assert_ne!(d4.signing_hash(), base);
        let mut d5 = d.clone();
        d5.height += 1;
        assert_ne!(d5.signing_hash(), base);
        let mut d6 = d.clone();
        d6.block_hash = [9; 32];
        assert_ne!(d6.signing_hash(), base);
        let mut d7 = d.clone();
        d7.prev_checkpoint_hash = [9; 32];
        assert_ne!(d7.signing_hash(), base);
    }

    #[test]
    fn quorum_exact_and_edge() {
        let keys = sks(5);
        let d = data(1, 10, 1);
        // 4/5 signatures : quorum 4 atteint, quorum 5 non.
        let cp = signed(&d, &keys[..4]);
        let committee: Vec<PublicKey> = keys.iter().map(|k| k.public_key()).collect();
        assert!(cp.verify_quorum(&committee, 4));
        assert!(!cp.verify_quorum(&committee, 5));
        // signature hors comité ignorée
        let outsider = sks(1);
        let mut mix = signed(&d, &keys[..4]);
        let msg = d.signing_hash();
        mix.signatures
            .push((outsider[0].public_key(), outsider[0].sign(&msg)));
        assert_eq!(mix.signatures.len(), 5);
        assert!(!mix.verify_quorum(&committee, 5));
        assert!(mix.verify_quorum(&committee, 4));
        // doublon jamais compté deux fois
        let mut dup = signed(&d, &keys[..3]);
        dup.signatures.push(dup.signatures[0]);
        assert!(!dup.verify_quorum(&committee, 4));
        assert!(dup.verify_quorum(&committee, 3));
    }

    #[test]
    fn quorum_two_thirds_dynamic() {
        // Sémantique 2/3 du protocole : ⌈2n/3⌉ signatures parmi n membres.
        for n in 3..=9usize {
            let keys = sks(n as u8);
            let d = data(1, 10, 1);
            let committee: Vec<PublicKey> = keys.iter().map(|k| k.public_key()).collect();
            let quorum = (2 * n).div_ceil(3); // ⌈2n/3⌉
            let cp_ok = signed(&d, &keys[..quorum]);
            assert!(
                cp_ok.verify_quorum(&committee, quorum),
                "n={n}, quorum={quorum} atteint"
            );
            let cp_ko = signed(&d, &keys[..quorum - 1]);
            assert!(
                !cp_ko.verify_quorum(&committee, quorum),
                "n={n}, quorum-1 insuffisant"
            );
        }
    }

    #[test]
    fn signature_binds_data() {
        let keys = sks(3);
        let d = data(1, 10, 1);
        let mut cp = signed(&d, &keys);
        // checkpoint altéré après signature → quorum perdu
        cp.data.height += 1;
        assert!(!cp.verify_quorum(&keys.iter().map(|k| k.public_key()).collect::<Vec<_>>(), 1));
    }

    #[test]
    fn checkpoint_hash_engages_signatures() {
        let keys = sks(4);
        let d = data(2, 20, 5);
        let cp = signed(&d, &keys);
        // Hash chaîné déterministe.
        assert_eq!(cp.hash(), cp.hash());
        // Mêmes données, moins de signatures → hash différent : le hash de
        // chaînage engage l'ensemble des signatures.
        let cp_fewer = signed(&d, &keys[..3]);
        assert_ne!(cp.hash(), cp_fewer.hash());
        // Une signature différente (signataire autre) → hash différent.
        let outsider = sks(1);
        let mut cp_swapped = signed(&d, &keys[..3]);
        let msg = d.signing_hash();
        cp_swapped.signatures[0] = (outsider[0].public_key(), outsider[0].sign(&msg));
        cp_swapped.signatures.sort_by_key(|s| s.0);
        assert_ne!(cp.hash(), cp_swapped.hash());
        // Données différentes → hash différent.
        let d2 = data(2, 21, 5);
        assert_ne!(cp.hash(), signed(&d2, &keys).hash());
    }

    #[test]
    fn committee_selection_deterministic_and_seeded() {
        let pool: Vec<PublicKey> = sks(40).iter().map(|k| k.public_key()).collect();
        let seed = [9; 32];
        let a = select_committee(&seed, pool.iter().copied(), 31);
        let b = select_committee(&seed, pool.iter().rev().copied(), 31);
        assert_eq!(a, b, "ordre d'entrée sans effet");
        assert_eq!(a.len(), 31);
        // seed différente → comité différent (tirage)
        let c = select_committee(&[8; 32], pool.iter().copied(), 31);
        assert_ne!(a, c);
        // doublons d'entrée dédupliqués
        let dup = select_committee(
            &seed,
            pool.iter()
                .take(5)
                .copied()
                .chain(pool.iter().take(5).copied()),
            31,
        );
        assert_eq!(dup.len(), 5);
        // pool plus petit que la taille demandée : comité = pool entier
        let small = select_committee(&seed, pool.iter().take(3).copied(), 31);
        assert_eq!(small.len(), 3);
    }

    #[test]
    fn seed_chain_and_recovery() {
        let cp_hash = [4; 32];
        let s = next_seed(&cp_hash);
        assert_ne!(s, cp_hash);
        assert_eq!(s, next_seed(&cp_hash), "déterministe");
        assert_ne!(
            recovery_seed(&s, 1),
            recovery_seed(&s, 2),
            "tirages distincts"
        );
        assert_eq!(recovery_seed(&s, 1), recovery_seed(&s, 1));
        assert_ne!(next_seed(&[5; 32]), s, "seed liée au checkpoint");
    }

    #[test]
    fn genesis_checkpoint_hash_is_zero() {
        assert_eq!(GENESIS_CHECKPOINT_HASH, [0; 32]);
        let genesis = data(0, 0, 0);
        assert_eq!(genesis.prev_checkpoint_hash, GENESIS_CHECKPOINT_HASH);
    }
}
