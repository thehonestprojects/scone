//! Enveloppe chiffrée des groupes de records DNS (M10).
//!
//! `nonce(24) ‖ XChaCha20-Poly1305(DEK, canonical(records))` —
//! même primitive que le keystore `.sconekey`. Une DEK par groupe,
//! générée par l'owner ; le chiffrement est indépendant par groupe.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Nonce XChaCha20 (24 octets).
pub const NONCE_LEN: usize = 24;
/// DEK (32 octets).
pub const DEK_LEN: usize = 32;

/// Génère une DEK depuis l'entropie fournie (32 octets exactement).
#[must_use]
pub fn new_dek(entropy: &[u8; DEK_LEN]) -> [u8; DEK_LEN] {
    *entropy
}

/// Scelle `plaintext` sous `dek` : `nonce ‖ ciphertext+tag`.
///
/// # Errors
///
/// Erreur AEAD (n'arrive que sur défaillance interne de la primitive).
pub fn seal(dek: &[u8; DEK_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&chacha20poly1305::Key::from(*dek));
    let n = XNonce::from(*nonce);
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + 16);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&cipher.encrypt(&n, plaintext).expect("XChaCha20 encrypt"));
    out
}

/// Ouvre une enveloppe : vérifie le tag Poly1305 (authenticité) et
/// retourne le clair. `None` = clé fausse OU blob falsifié.
#[must_use]
pub fn open(dek: &[u8; DEK_LEN], envelope: &[u8]) -> Option<Vec<u8>> {
    if envelope.len() < NONCE_LEN + 16 {
        return None;
    }
    let (nonce, ct) = envelope.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(&chacha20poly1305::Key::from(*dek));
    let Ok(n) = <[u8; 24]>::try_from(nonce) else {
        return None;
    };
    cipher.decrypt(&XNonce::from(n), ct).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dek = [7u8; 32];
        let nonce = [3u8; 24];
        let env = seal(&dek, &nonce, b"internal 10.0.0.1");
        assert_eq!(open(&dek, &env).as_deref(), Some(&b"internal 10.0.0.1"[..]));
    }

    #[test]
    fn wrong_key_is_none() {
        let env = seal(&[7u8; 32], &[3u8; 24], b"secret");
        assert!(open(&[8u8; 32], &env).is_none());
    }

    #[test]
    fn tampered_blob_is_none() {
        let mut env = seal(&[7u8; 32], &[3u8; 24], b"secret");
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(open(&[7u8; 32], &env).is_none());
    }

    #[test]
    fn truncated_is_none() {
        let env = seal(&[7u8; 32], &[3u8; 24], b"secret");
        assert!(open(&[7u8; 32], &env[..20]).is_none());
    }
}
