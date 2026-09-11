//! Sécurité du signataire (crash safety) : un Anchor ne doit JAMAIS signer
//! deux checkpoints incompatibles, même après crash/restart. Règle : une clé
//! = un vote par epoch — tout contenu d'epoch inférieure ou égale au dernier
//! signé est refusé, sauf re-signature exacte du même hash (idempotente).
//! La vérification a lieu AVANT la signature, et le contexte signé est
//! persisté durablement (write + fsync + rename + fsync dir) AVANT que la
//! signature ne soit rendue à l'appelant — une signature non enregistrée
//! n'est jamais diffusée.
//!
//! Fichier `signer-state.dat` : enregistrements fixes de 96 B (tag + clé +
//! signing_hash + epoch + height), un par clé ayant signé, réécrit
//! atomiquement. Illisible = fail closed : plus AUCUNE signature tant que
//! l'opérateur n'a pas tranché — double-signer vaut bannissement à vie
//! (SlashTx, détecté par les pairs témoins).
//!
//! Exception assumée au « no filesystem » de ce crate : ce fichier n'est pas
//! un backend de stockage de la chaîne, c'est une garde locale du signataire
//! (même robustesse que `scone-storage`, pour un fichier hors store).

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use scone_core::checkpoint::{CheckpointData, Hash};
use scone_crypto::{PublicKey, Signature, SigningKey};

use crate::error::{BlockchainError, Result};

const SIGNER_TAG: &[u8] = b"SCONE-SIGNER-V1";
/// tag(16) + pk(32) + signing_hash(32) + epoch(8) + height(8)
const RECORD_LEN: usize = SIGNER_TAG.len() + 32 + 32 + 8 + 8;
const FILE_NAME: &str = "signer-state.dat";

/// Dernier contexte signé par une clé : suffit à prouver l'equivocation
/// éventuelle ET à la refuser localement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedContext {
    pub signer: PublicKey,
    pub signing_hash: Hash,
    pub epoch: u64,
    pub height: u64,
}

impl SignedContext {
    fn to_bytes(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[..SIGNER_TAG.len()].copy_from_slice(SIGNER_TAG);
        let mut p = SIGNER_TAG.len();
        out[p..p + 32].copy_from_slice(&self.signer.to_bytes());
        p += 32;
        out[p..p + 32].copy_from_slice(&self.signing_hash);
        p += 32;
        out[p..p + 8].copy_from_slice(&self.epoch.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.height.to_le_bytes());
        out
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != RECORD_LEN || &b[..SIGNER_TAG.len()] != SIGNER_TAG {
            return Err(BlockchainError::Signer("bad signer record".into()));
        }
        let mut p = SIGNER_TAG.len();
        // Invariants : b.len() == RECORD_LEN vérifié ci-dessus, offsets
        // croissants ≤ RECORD_LEN par construction de to_bytes.
        let signer = PublicKey::from_bytes(
            b[p..p + 32]
                .try_into()
                .expect("RECORD_LEN vérifié : 32 octets disponibles"),
        )
        .map_err(|_| BlockchainError::Signer("bad signer public key".into()))?;
        p += 32;
        let signing_hash: Hash = b[p..p + 32]
            .try_into()
            .expect("RECORD_LEN vérifié : 32 octets disponibles");
        p += 32;
        let epoch = u64::from_le_bytes(
            b[p..p + 8]
                .try_into()
                .expect("RECORD_LEN vérifié : 8 octets disponibles"),
        );
        p += 8;
        let height = u64::from_le_bytes(
            b[p..p + 8]
                .try_into()
                .expect("RECORD_LEN vérifié : 8 octets disponibles"),
        );
        Ok(Self {
            signer,
            signing_hash,
            epoch,
            height,
        })
    }
}

/// Garde du signataire : règle vérifiée avant chaque signature, état persisté
/// avant chaque diffusion. `Send` (aucun verrou : la boucle d'événements du
/// nœud est le seul signataire).
pub struct SignerGuard {
    path: PathBuf,
    last: HashMap<PublicKey, SignedContext>,
    /// Fichier illisible : toute signature refusée (fail closed). Supprimer le
    /// fichier n'est acceptable qu'en acceptant le risque de slashing.
    sealed: bool,
}

impl SignerGuard {
    /// Charge l'état depuis `dir/signer-state.dat`. Absent = vierge ; présent
    /// mais illisible = scellé (fail closed).
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE_NAME);
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self {
                    path,
                    last: HashMap::new(),
                    sealed: false,
                };
            }
            Err(e) => {
                tracing::error!(error = %e, "signer state unreadable — signing DISABLED (fail closed)");
                return Self {
                    path,
                    last: HashMap::new(),
                    sealed: true,
                };
            }
        };
        if data.is_empty() || data.len() % RECORD_LEN != 0 {
            tracing::error!("signer state corrupted — signing DISABLED (fail closed)");
            return Self {
                path,
                last: HashMap::new(),
                sealed: true,
            };
        }
        let mut last = HashMap::new();
        for chunk in data.chunks(RECORD_LEN) {
            match SignedContext::from_bytes(chunk) {
                Ok(ctx) => {
                    last.insert(ctx.signer, ctx);
                }
                Err(_) => {
                    tracing::error!("signer state holds a bad record — signing DISABLED");
                    return Self {
                        path,
                        last: HashMap::new(),
                        sealed: true,
                    };
                }
            }
        }
        Self {
            path,
            last,
            sealed: false,
        }
    }

    /// Règle AVANT signature : jamais deux contenus d'une même epoch (ou
    /// d'une epoch passée) pour une même clé. Idempotent sur le même hash.
    pub fn may_sign(&self, signer: &PublicKey, data: &CheckpointData) -> Result<()> {
        if self.sealed {
            return Err(BlockchainError::Signer(
                "signer state sealed (unreadable) — refusing to sign anything".into(),
            ));
        }
        if let Some(ctx) = self.last.get(signer) {
            let h = data.signing_hash();
            if data.epoch < ctx.epoch || (data.epoch == ctx.epoch && h != ctx.signing_hash) {
                return Err(BlockchainError::Signer(format!(
                    "key already signed epoch {} (height {}) — refusing conflicting checkpoint of epoch {} (double-signing is slashable)",
                    ctx.epoch, ctx.height, data.epoch
                )));
            }
        }
        Ok(())
    }

    /// Signature autorisée : vérifie la règle, signe, enregistre le contexte
    /// puis persiste AVANT de rendre la signature. Un échec de persistance
    /// laisse le contexte en mémoire (la session reste protégée) et retourne
    /// Err — l'appelant ne doit PAS diffuser.
    pub fn authorize(&mut self, sk: &SigningKey, data: &CheckpointData) -> Result<Signature> {
        let pk = sk.public_key();
        self.may_sign(&pk, data)?;
        let h = data.signing_hash();
        let sig = sk.sign(&h);
        self.last.insert(
            pk,
            SignedContext {
                signer: pk,
                signing_hash: h,
                epoch: data.epoch,
                height: data.height,
            },
        );
        if let Err(e) = self.persist() {
            return Err(BlockchainError::Signer(format!(
                "signer state persist failed ({e}) — signature withheld, do not broadcast"
            )));
        }
        Ok(sig)
    }

    /// Réécriture atomique complète (l'état tient en quelques centaines
    /// d'octets : un enregistrement par clé ayant signé).
    fn persist(&self) -> std::io::Result<()> {
        let mut ctxs: Vec<&SignedContext> = self.last.values().collect();
        ctxs.sort_by_key(|c| c.signer);
        let mut buf = Vec::with_capacity(ctxs.len() * RECORD_LEN);
        for c in ctxs {
            buf.extend_from_slice(&c.to_bytes());
        }
        atomic_write(&self.path, &buf)
    }
}

/// Écriture atomique : write → fsync fichier → rename → fsync répertoire
/// (même robustesse que `scone-storage`, pour un fichier hors store).
fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent()
        && let Ok(d) = File::open(parent)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("scone-signer-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cp(epoch: u64, salt: u8) -> CheckpointData {
        CheckpointData {
            epoch,
            height: epoch * 4 + 1,
            block_hash: [salt; 32],
            prev_checkpoint_hash: [0; 32],
            state_root: [salt.wrapping_add(1); 32],
            recovery: 0,
        }
    }

    /// Scénario §16 : signer → crash → restart → proposition contradictoire
    /// → refus. Le redémarrage recharge l'état depuis le disque.
    #[test]
    fn conflicting_checkpoint_refused_after_restart() {
        let dir = tmpdir("restart");
        let sk = SigningKey::from_bytes([9; 32]);
        {
            let mut g = SignerGuard::load(&dir);
            g.authorize(&sk, &cp(5, 1)).unwrap();
        }
        // crash : nouvelle instance, état relu depuis le disque
        let mut g2 = SignerGuard::load(&dir);
        let pk = sk.public_key();
        assert!(
            g2.may_sign(&pk, &cp(5, 2)).is_err(),
            "même epoch, autre contenu"
        );
        assert!(g2.may_sign(&pk, &cp(4, 1)).is_err(), "epoch passée");
        assert!(
            g2.may_sign(&pk, &cp(5, 1)).is_ok(),
            "même hash : idempotent"
        );
        assert!(g2.may_sign(&pk, &cp(6, 1)).is_ok(), "epoch suivante");
        g2.authorize(&sk, &cp(6, 1)).unwrap();
        assert!(
            g2.may_sign(&pk, &cp(6, 2)).is_err(),
            "la nouvelle epoch est verrouillée"
        );
    }

    /// Clés indépendantes : le vote d'une clé ne contraint pas l'autre.
    #[test]
    fn keys_are_independent() {
        let dir = tmpdir("keys");
        let a = SigningKey::from_bytes([1; 32]);
        let b = SigningKey::from_bytes([2; 32]);
        let mut g = SignerGuard::load(&dir);
        g.authorize(&a, &cp(5, 1)).unwrap();
        assert!(g.may_sign(&b.public_key(), &cp(5, 2)).is_ok());
    }

    /// Fichier corrompu : fail closed — aucune signature possible.
    #[test]
    fn corrupt_state_fails_closed() {
        let dir = tmpdir("corrupt");
        fs::write(dir.join(FILE_NAME), b"garbage-not-96b").unwrap();
        let g = SignerGuard::load(&dir);
        let sk = SigningKey::from_bytes([3; 32]);
        assert!(g.may_sign(&sk.public_key(), &cp(1, 1)).is_err());
    }

    /// Échec disque : la signature est retenue (Err), mais le contexte reste
    /// en mémoire — la session refuse quand même le conflit.
    #[test]
    fn disk_failure_withholds_signature_but_protects_memory() {
        let dir = tmpdir("diskfail");
        let sk = SigningKey::from_bytes([4; 32]);
        let mut g = SignerGuard::load(&dir);
        // <file>.tmp est un répertoire → File::create échoue
        fs::create_dir(dir.join(FILE_NAME).with_extension("tmp")).unwrap();
        assert!(g.authorize(&sk, &cp(7, 1)).is_err(), "signature retenue");
        assert!(
            g.may_sign(&sk.public_key(), &cp(7, 2)).is_err(),
            "le contexte en mémoire protège la session"
        );
    }

    /// L'état persisté relit bit à bit : enregistrements 96 B, un par clé,
    /// et la signature produite vérifie contre la clé publique.
    #[test]
    fn persisted_state_roundtrips_and_signature_verifies() {
        let dir = tmpdir("roundtrip");
        let sk = SigningKey::from_bytes([5; 32]);
        let data = cp(3, 7);
        let sig = {
            let mut g = SignerGuard::load(&dir);
            let s = g.authorize(&sk, &data).unwrap();
            // persistance effective avant retour
            assert_eq!(fs::read(dir.join(FILE_NAME)).unwrap().len(), RECORD_LEN);
            s
        };
        let g2 = SignerGuard::load(&dir);
        let ctx = g2.last.get(&sk.public_key()).unwrap();
        assert_eq!(ctx.signing_hash, data.signing_hash());
        assert_eq!(ctx.epoch, data.epoch);
        assert_eq!(ctx.height, data.height);
        assert!(sk.public_key().verify(&data.signing_hash(), &sig));
        // re-signature idempotente du même hash : autorisée
        assert!(g2.may_sign(&sk.public_key(), &data).is_ok());
    }

    /// Répertoire inexistant à la lecture = état vierge (pas scellé).
    #[test]
    fn missing_state_is_virgin_not_sealed() {
        let dir = tmpdir("missing");
        let g = SignerGuard::load(&dir.join("nonexistent-subdir"));
        let sk = SigningKey::from_bytes([6; 32]);
        assert!(g.may_sign(&sk.public_key(), &cp(1, 1)).is_ok());
    }
}
