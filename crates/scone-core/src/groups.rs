//! Groupes de records DNS — split-horizon cryptographique (M10).
//!
//! Un domaine possède une CARTE DE GROUPES :
//! - `public` : texte clair, servi à tous (comportement historique) ;
//! - N groupes chiffrés, chacun avec sa PROPRE clé (DEK) — un
//!   chiffrement indépendant par groupe.
//!
//! Publication : UN SEUL enregistrement composite sur la DHT (une
//! clé = un fetch = une entrée de cache par domaine). Le serveur DNS
//! déchiffre les groupes pour lesquels il détient une clé et sert
//! l'union — « sert ce qu'il a pu déchiffrer ».
//!
//! Collisions entre groupes : l'owner définit un ORDRE DE PRIORITÉ
//! (liste ordonnée des ids de groupes) ; pour un (nom, type) donné,
//! le premier groupe qui matche gagne.
//!
//! Engagements : voir [`group_domain_hash`]. Les groupes chiffrés
//! engagent le CIPHERTEXT (jamais le clair — résistance au
//! dictionnaire), le groupe public engage le clair.

use crate::error::SconeError;
use crate::record::RecordData;
use scone_crypto::hash256;

/// Domain-separation : engagement d'un groupe.
pub const GROUP_TAG: &[u8] = b"SCONE-GROUP-V1";
/// Domain-separation : racine d'engagement multi-groupes (le
/// `record_hash` vu par la chaîne).
pub const GROUPS_ROOT_TAG: &[u8] = b"SCONE-GROUPS-V1";

/// Identifiant d'un groupe : label `[a-z0-9-]{1,32}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(String);

/// Le groupe public — toujours présent, toujours en clair.
pub const PUBLIC_GROUP: &str = "public";

impl GroupId {
    /// Valide et construit un id de groupe.
    ///
    /// # Errors
    ///
    /// [`SconeError::InvalidRecord`] si le label est mal formé.
    pub fn new(label: &str) -> Result<Self> {
        let ok = (1..=32).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(SconeError::InvalidRecord(format!(
                "group id '{label}' must be [a-z0-9-]{{1,32}}"
            )));
        }
        Ok(Self(label.to_owned()))
    }

    /// Le label (canonique).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Un groupe de records : clair (public) ou ciphertext (chiffré).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupContent {
    /// Records en clair — groupe public uniquement.
    Clear(Vec<RecordData>),
    /// `nonce ‖ XChaCha20-Poly1305(DEK, canonical(records))`.
    /// Jamais du clair : l'engagement porte ces octets.
    Encrypted(Vec<u8>),
}

/// Un groupe complet : contenu + engagement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordGroup {
    pub id: GroupId,
    pub content: GroupContent,
}

impl RecordGroup {
    /// Engagement du groupe : hash du clair (public) ou du ciphertext
    /// (chiffré — résistance au dictionnaire).
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        match &self.content {
            GroupContent::Clear(records) => hash256(&[
                GROUP_TAG,
                self.id.as_str().as_bytes(),
                b"clear",
                &canonical_records(records),
            ]),
            GroupContent::Encrypted(ct) => {
                hash256(&[GROUP_TAG, self.id.as_str().as_bytes(), b"enc", ct])
            }
        }
    }

    /// Est-ce le groupe public ?
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.id.as_str() == PUBLIC_GROUP
    }
}

/// La carte des groupes d'un domaine + l'ordre de priorité
/// (premier qui matche gagne en cas de collision de (nom, type)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMap {
    /// Ordre de priorité DÉCROISSANT : `priority[0]` surcharge tous
    /// les autres. Doit contenir chaque groupe exactement une fois.
    pub priority: Vec<GroupId>,
    pub groups: Vec<RecordGroup>,
}

impl GroupMap {
    /// Une carte avec le seul groupe public (cas historique).
    #[must_use]
    pub fn public_only(records: Vec<RecordData>) -> Self {
        Self {
            priority: vec![GroupId(PUBLIC_GROUP.to_owned())],
            groups: vec![RecordGroup {
                id: GroupId(PUBLIC_GROUP.to_owned()),
                content: GroupContent::Clear(records),
            }],
        }
    }

    /// Valide les invariants : `public` présent et en clair, priorité
    /// = permutation exacte des groupes, ids uniques.
    ///
    /// # Errors
    ///
    /// [`SconeError::InvalidRecord`] en cas de violation.
    pub fn validate(&self) -> Result<()> {
        let public = self
            .groups
            .iter()
            .find(|g| g.is_public())
            .ok_or_else(|| SconeError::InvalidRecord("missing public group".into()))?;
        if !matches!(public.content, GroupContent::Clear(_)) {
            return Err(SconeError::InvalidRecord(
                "public group must be cleartext".into(),
            ));
        }
        if self.groups.len() != self.priority.len() {
            return Err(SconeError::InvalidRecord(
                "priority list must list every group exactly once".into(),
            ));
        }
        for g in &self.groups {
            if self.priority.iter().filter(|p| **p == g.id).count() != 1 {
                return Err(SconeError::InvalidRecord(format!(
                    "group '{}' not listed exactly once in priority",
                    g.id.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Racine d'engagement : ce hash devient le `record_hash` vu par
    /// la chaîne (`UpdateDomain`). Ordonné par id de groupe —
    /// déterministe, indépendant de l'ordre de priorité.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut tagged: Vec<([u8; 32], &str)> = self
            .groups
            .iter()
            .map(|g| (g.commitment(), g.id.as_str()))
            .collect();
        tagged.sort_by(|a, b| a.1.cmp(b.1));
        let mut buf = Vec::with_capacity(GROUPS_ROOT_TAG.len() + tagged.len() * 33);
        buf.extend_from_slice(GROUPS_ROOT_TAG);
        for (c, id) in tagged {
            buf.extend_from_slice(id.as_bytes());
            buf.push(b'\0');
            buf.extend_from_slice(&c);
        }
        hash256(&[&buf])
    }

    /// Sélectionne les réponses pour un (type) selon la priorité :
    /// premier groupe MATCHANT (clair ou déchiffré) qui possède le
    /// type gagne ; les suivants ne surchargent pas.
    ///
    /// `decrypt` fournit le clair d'un groupe chiffré quand le
    /// resolver a la clé (retourne None sinon — le groupe est
    /// simplement invisible).
    #[must_use]
    pub fn select(&self, rtype: u16, decrypt: &DecryptFn) -> Vec<RecordData> {
        for id in &self.priority {
            let Some(group) = self.groups.iter().find(|g| &g.id == id) else {
                continue;
            };
            let records = match &group.content {
                GroupContent::Clear(r) => Some(r.clone()),
                GroupContent::Encrypted(ct) => decrypt(&group.id, ct),
            };
            if let Some(mut r) = records {
                r.retain(|rec| record_type(rec) == rtype);
                if !r.is_empty() {
                    return r;
                }
            }
        }
        Vec::new()
    }
}

/// Encodage canonique (déterministe) d'un set de records pour le
/// chiffrement et les engagements clairs. Délégué à scone-protocol
/// côté wire ; ici : l'ordre est préservé, chaque record encodé
/// via son Display canonique (stable, testé par vecteurs).
#[must_use]
pub fn canonical_records(records: &[RecordData]) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut out = String::new();
    for r in records {
        // Encodage canonique stable (une ligne par record) — le
        // même sert au chiffrement et à l'engagement clair.
        match r {
            RecordData::A(ip) => {
                let _ = writeln!(out, "A {ip}");
            }
            RecordData::Aaaa(ip) => {
                let _ = writeln!(out, "AAAA {ip}");
            }
            RecordData::Cname(n) => {
                let _ = writeln!(out, "CNAME {}", n.canonical());
            }
            RecordData::Mx {
                preference,
                exchange,
            } => {
                let _ = writeln!(out, "MX {preference} {}", exchange.canonical());
            }
            RecordData::Txt(t) => {
                let _ = writeln!(out, "TXT {t}");
            }
            RecordData::Ns(n) => {
                let _ = writeln!(out, "NS {}", n.canonical());
            }
            RecordData::Unknown { type_code, data } => {
                let _ = writeln!(out, "TYPE{type_code} {}", data.len());
            }
        }
    }
    out.into_bytes()
}

/// Code de type wire DNS d'un record (RFC 1035 §3.2.2).
#[must_use]
pub fn record_type(r: &RecordData) -> u16 {
    match r {
        RecordData::A(_) => 1,
        RecordData::Ns(_) => 2,
        RecordData::Cname(_) => 5,
        RecordData::Mx { .. } => 15,
        RecordData::Txt(_) => 16,
        RecordData::Aaaa(_) => 28,
        RecordData::Unknown { type_code, .. } => *type_code,
    }
}

use crate::error::Result;

/// Callback de déchiffrement d'un groupe : retourne le clair quand
/// le resolver détient la DEK, `None` sinon (groupe invisible).
pub type DecryptFn = dyn Fn(&GroupId, &[u8]) -> Option<Vec<RecordData>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn a(ip: &str) -> RecordData {
        RecordData::A(ip.parse().unwrap())
    }

    #[test]
    fn group_id_validation() {
        assert!(GroupId::new("internal").is_ok());
        assert!(GroupId::new("prod-eu-1").is_ok());
        assert!(GroupId::new("").is_err());
        assert!(GroupId::new(&"x".repeat(33)).is_err());
        assert!(GroupId::new("Invalide").is_err());
        assert!(GroupId::new("esp ace").is_err());
    }

    #[test]
    fn public_only_map_validates() {
        let m = GroupMap::public_only(vec![a("192.0.2.1")]);
        assert!(m.validate().is_ok());
        // Root déterministe.
        let m2 = GroupMap::public_only(vec![a("192.0.2.1")]);
        assert_eq!(m.root(), m2.root());
    }

    #[test]
    fn encrypted_commitment_binds_ciphertext_not_plaintext() {
        let g1 = RecordGroup {
            id: GroupId::new("internal").unwrap(),
            content: GroupContent::Encrypted(vec![1, 2, 3]),
        };
        let g2 = RecordGroup {
            id: GroupId::new("internal").unwrap(),
            content: GroupContent::Encrypted(vec![1, 2, 4]),
        };
        assert_ne!(g1.commitment(), g2.commitment());
        // Le clair ne permet PAS de recalculer l'engagement.
        let clear = RecordGroup {
            id: GroupId::new("internal").unwrap(),
            content: GroupContent::Clear(vec![a("10.0.0.1")]),
        };
        assert_ne!(g1.commitment(), clear.commitment());
    }

    #[test]
    fn root_is_order_independent_for_priority() {
        let mk = |priority: Vec<&str>| GroupMap {
            priority: priority.iter().map(|p| GroupId::new(p).unwrap()).collect(),
            groups: vec![
                RecordGroup {
                    id: GroupId::new("public").unwrap(),
                    content: GroupContent::Clear(vec![a("203.0.113.5")]),
                },
                RecordGroup {
                    id: GroupId::new("internal").unwrap(),
                    content: GroupContent::Encrypted(vec![9; 40]),
                },
            ],
        };
        let m1 = mk(vec!["internal", "public"]);
        let m2 = mk(vec!["public", "internal"]);
        assert!(m1.validate().is_ok());
        assert!(m2.validate().is_ok());
        assert_eq!(m1.root(), m2.root());
    }

    #[test]
    fn validate_rejects_bad_maps() {
        // public chiffré
        let m = GroupMap {
            priority: vec![GroupId::new("public").unwrap()],
            groups: vec![RecordGroup {
                id: GroupId::new("public").unwrap(),
                content: GroupContent::Encrypted(vec![1]),
            }],
        };
        assert!(m.validate().is_err());
        // priorité incomplète
        let m = GroupMap {
            priority: vec![],
            groups: vec![RecordGroup {
                id: GroupId::new("public").unwrap(),
                content: GroupContent::Clear(vec![a("1.2.3.4")]),
            }],
        };
        assert!(m.validate().is_err());
    }

    #[test]
    fn select_respects_priority_and_encryption() {
        let m = GroupMap {
            priority: vec![
                GroupId::new("internal").unwrap(),
                GroupId::new("public").unwrap(),
            ],
            groups: vec![
                RecordGroup {
                    id: GroupId::new("public").unwrap(),
                    content: GroupContent::Clear(vec![a("203.0.113.5")]),
                },
                RecordGroup {
                    id: GroupId::new("internal").unwrap(),
                    content: GroupContent::Encrypted(vec![9; 40]),
                },
            ],
        };
        // Sans clé : internal invisible -> public sert.
        let got = m.select(1, &|_, _| None);
        assert_eq!(got, vec![a("203.0.113.5")]);
        // Avec clé : internal surcharge.
        let got = m.select(1, &|_, _| Some(vec![a("10.0.0.1")]));
        assert_eq!(got, vec![a("10.0.0.1")]);
        // Type absent partout -> vide.
        assert!(m.select(16, &|_, _| Some(vec![a("10.0.0.1")])).is_empty());
    }
}
