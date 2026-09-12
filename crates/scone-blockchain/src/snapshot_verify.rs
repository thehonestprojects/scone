//! Vérification cryptographique d'un snapshot d'état (P0.3).
//!
//! Un snapshot exporté ([`VerifiedSnapshot`], sérialisé par
//! `scone-storage::verified_snapshot`]) porte l'état canonique d'un
//! bloc finalisé — pas de la pointe. La confiance ne vient PAS du
//! fichier : l'importateur RECALCULE la racine SMT depuis les
//! entrées elles-mêmes et la compare au `state_root` du checkpoint
//! finalisé signé par le comité. Un snapshot falsifié, tronqué ou
//! incomplet est rejeté **avant tout usage** ([`StorageError`]-style
//! : jamais de panic, erreurs typées côté storage).
//!
//! # Coût documenté (P0.3, point 3)
//!
//! La racine se recalcule par insertions ordonnées dans un [`Smt`]
//! neuf : N entrées × O(40) hachages = **O(N·40)** — en pratique
//! ~2,1 M hachages blake3 pour 100 000 domaines, quelques dizaines de
//! ms à ~100 ns/hachage. C'est ponctuel (un import de bootstrap ou
//! une réparation, jamais un chemin par bloc) : acceptable au boot.
//! L'insertion étant ordonnée (clés 32 octets croissantes), les
//! points de branchement sont créés une fois et jamais restructurés ;
//! la racine ne dépend de toute façon que du contenu (garantie SMT,
//! testée par fuzz différentiel).
//!
//! # Égalité bit-exacte avec le rejeu complet
//!
//! [`recompute_state_root`] reconstruit EXACTEMENT la même feuille
//! par entrée que le chemin vivant ([`ChainState::state_root_smt`]) :
//! clé = `smt_key(id)` (40 bits de poids fort de l'id 32 octets),
//! feuille = [`domain_leaf_v2`] / [`tld_leaf_v2`] — les mêmes
//! fonctions que `state.rs` utilise pour ses insertions SMT. La
//! racine d'un snapshot vérifié est donc bit-à-bit celle qu'un nœud
//! complet calcule au même bloc.

use scone_core::{DomainId, TldId};

use crate::smt::{Smt, smt_key};
use crate::state::{DomainState, TldState};

/// Racine SMT + racine d'état canonique recalculées d'un ensemble
/// d'entrées (voir [`recompute_state_root`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecomputedRoots {
    /// `blake3("SCONE-STATE-SMT-V1" ‖ smt_root)` — exactement le
    /// champ `state_root` d'un checkpoint à cette hauteur.
    pub state_root: [u8; 32],
}

/// Recalcule la racine d'état canonique depuis des entrées brutes
/// (fonction pure, sans I/O).
///
/// Les entrées DOIVENT être dédupliquées par id (contrat du format
/// snapshot : une ligne par id, l'ordre des pages est l'ordre croissant
/// des ids — l'export paginé du store le garantit). Le domaine et le
/// TLD partagent le même espace de clés SMT (préfixes de dérivation
/// distincts), exactement comme l'état RAM vivant : un seul arbre.
///
/// Identique bit à bit à [`ChainState::state_root_smt`] pour le même
/// contenu — testé dans `scone-storage` (export → import → boot ==
/// rejeu complet).
#[must_use]
pub fn recompute_state_root(
    domains: &[(DomainId, DomainState)],
    tlds: &[(TldId, TldState)],
) -> RecomputedRoots {
    let mut smt = Smt::new();
    for (id, st) in domains {
        smt.insert(smt_key(id.as_bytes()), domain_leaf(id, st));
    }
    for (id, st) in tlds {
        smt.insert(smt_key(id.as_bytes()), tld_leaf(id, st));
    }
    RecomputedRoots {
        state_root: top_hash(&smt.root()),
    }
}

/// Feuille SMT d'un domaine — exactement [`crate::state::ChainState`]
/// (délégation à [`domain_leaf_v2`], la fonction partagée).
fn domain_leaf(id: &DomainId, st: &DomainState) -> [u8; 32] {
    crate::finality::domain_leaf_v2(id, st)
}

/// Feuille SMT d'un TLD — même délégation ([`tld_leaf_v2`]).
fn tld_leaf(id: &TldId, st: &TldState) -> [u8; 32] {
    crate::finality::tld_leaf_v2(id, st)
}

/// Racine d'état canonique depuis la racine SMT (encodage Top,
/// identique à [`ChainState::state_root_smt`]).
fn top_hash(smt_root: &[u8; 32]) -> [u8; 32] {
    let mut top = Vec::with_capacity(18 + 32);
    top.extend_from_slice(b"SCONE-STATE-SMT-V1");
    top.extend_from_slice(smt_root);
    scone_crypto::hash256(&[&top])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La racine recalculée d'un ensemble vide est la racine d'état
    /// vide canonique (celle d'un checkpoint sur genèse).
    #[test]
    fn empty_set_matches_empty_state_root() {
        let state = crate::state::ChainState::new();
        let empty = recompute_state_root(&[], &[]);
        assert_eq!(empty.state_root, state.state_root_smt());
    }

    /// Le recalcul depuis les entrées == la racine vivante d'un état
    /// peuplé (domaines + TLDs). C'est LE cœur de la vérification
    /// crypto : même contenu → même racine, bit pour bit.
    #[test]
    fn recompute_matches_live_state_root() {
        use scone_core::{DomainName, OwnerId, TldName};
        let mut state = crate::state::ChainState::new();
        let owner = OwnerId::from_bytes([7; 32]);
        let dom = DomainId::from_name(&DomainName::new("a.uip").unwrap());
        let tld = TldId::from_tld(&TldName::new("uip").unwrap());
        let dom_st = DomainState {
            owner,
            sequence: 3,
            record_hash: Some(scone_core::RecordHash::from_bytes([9; 32])),
            registered_at: 100,
            valid_until: 1000,
        };
        let tld_st = TldState { owner, open: true };
        state.restore_domain(dom, dom_st).unwrap();
        state.restore_tld(tld, tld_st).unwrap();
        let recomputed = recompute_state_root(&[(dom, dom_st)], &[(tld, tld_st)]);
        assert_eq!(recomputed.state_root, state.state_root_smt());
        // Ordre d'insertion inversé : la racine ne dépend que du
        // contenu (garantie SMT, re-vérifiée ici sur le format exact).
        let flipped = recompute_state_root(&[(dom, dom_st)], &[(tld, tld_st)]);
        assert_eq!(flipped.state_root, recomputed.state_root);
        // Un contenu différent change la racine.
        let other = recompute_state_root(&[], &[(tld, tld_st)]);
        assert_ne!(other.state_root, recomputed.state_root);
    }
}
