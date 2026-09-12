//! Snapshots d'état **vérifiés** (P0.3) + bootstrap d'état (P0.4).
//!
//! # Modèle de confiance
//!
//! Un [`VerifiedSnapshotManifest`] + ses pages sérialisées
//! ([`SnapshotPage`]) transportent l'état canonique d'un bloc
//! **finalisé** (un checkpoint signé par le comité), pas de la
//! pointe. La confiance ne vient PAS du fichier :
//!
//! 1. chaque page porte `(index, hauteur, state_root du checkpoint,
//!    entrées)` et son hash est engagé dans le manifest ;
//! 2. [`import_verified_snapshot`] RECALCULE la racine SMT depuis
//!    les entrées importées et la compare au `state_root` du
//!    checkpoint (`scone_blockchain::snapshot_verify`) — un snapshot
//!    falsifié, tronqué ou incomplet est rejeté **avant toute
//!    écriture** ;
//! 3. hauteurs/tip incohérents (manifest ↔ checkpoint) sont rejetés.
//!
//! L'authenticité du checkpoint lui-même (quorum de signatures) est
//! validée par la couche chaîne AVANT l'import — l'import vérifie
//! l'adhérence snapshot ↔ checkpoint, pas la chaîne de signatures.
//!
//! # Chemin d'export
//!
//! [`export_verified_snapshot`] sérialise l'état du dernier snapshot
//! finalisé persisté (tables `snapshot_v3_*` du store, écrites dans
//! la transaction du bloc d'intervalle — jamais la pointe), en pages
//! bornées via la pagination curseur existante
//! ([`NodeStore::snapshot_domains`] / [`NodeStore::snapshot_tlds`]).
//!
//! # Chemin d'import (bootstrap P0.4)
//!
//! L'import écrit dans UNE transaction redb : les tables vivantes
//! (`domains`/`tlds` + compteurs + tip = `(H, hash du checkpoint)`),
//! les tables gelées (`snapshot_v3_*`, ancrées au même bloc — le
//! boot M6b rejouera le suffixe au-dessus de H) et un marqueur
//! (`meta["verified_snapshot_v1"]`). Le bloc d'ancrage H lui-même
//! arrive ensuite du réseau (relay) via
//! [`RedbStore::append_bootstrap_anchor`], puis les blocs H+1.. par
//! l'append atomique ordinaire — hauteur strictement croissante.
//! Au boot, [`load_chain`](crate::integration::load_chain) rejoue
//! SEULEMENT les blocs au-dessus de H : l'historique complet devient
//! optionnel pour un nœud non-archive (voir `/docs/technical/
//! storage.md`, section Bootstrap). Le comportement par défaut ne
//! change pas : ce chemin n'est actif que si l'opérateur l'a
//! explicitement déclenché (l'import est une action dédiée, jamais
//! automatique) ; un nœud archive continue de tout garder.
//!
//! # Coût de la vérification
//!
//! Le recalcul de racine reconstruit un SMT par insertions ordonnées
//! : O(N·40) hachages, PONCTUEL à l'import (jamais un chemin par
//! bloc) — documenté dans `scone-blockchain::snapshot_verify`.

use scone_core::checkpoint::Checkpoint;
use scone_core::{DomainId, TldId};
use scone_protocol::{Block, decode_complete};

use crate::NodeStore as _;
use crate::RedbStore;
use crate::error::{Result, StorageError};
use crate::state_bytes::{
    DOMAIN_STATE_LEN_NONE, DOMAIN_STATE_LEN_SOME, DomainStateBytes, TLD_STATE_LEN, TldStateBytes,
};

/// Domain-separation du manifest sérialisé.
pub const MANIFEST_TAG: &[u8] = b"SCONE-SNAP-MAN-V1";
/// Domain-separation d'une page sérialisée.
pub const PAGE_TAG: &[u8] = b"SCONE-SNAP-PAGE-V1";
/// Domain-separation du hash d'une page (le hash couvre l'encodage
/// intégral de la page).
pub const PAGE_HASH_TAG: &[u8] = b"SCONE-SNAP-PAGE-HASH";
/// Domain-separation du hash du manifest.
pub const MANIFEST_HASH_TAG: &[u8] = b"SCONE-SNAP-MAN-HASH";

/// Clé `meta` du marqueur d'import vérifié (réservée — écrasable par
/// personne via `meta_set`).
pub const META_VERIFIED_SNAPSHOT: &[u8] = b"verified_snapshot_v1";

/// Nombre d'entrées par page à l'export (les pages d'un même
/// snapshot sont homogènes et bornées).
pub const VERIFIED_SNAPSHOT_PAGE_ENTRIES: usize = 256;

/// Borne supérieure d'entrées par page ACCEPTÉE à l'import (garde
/// DoS : une page hostile ne peut pas forcer une allocation
/// démesurée avant sa vérification).
pub const MAX_VERIFIED_SNAPSHOT_PAGE_ENTRIES: usize = 10_000;

/// Borne supérieure du nombre de pages d'un manifest accepté.
pub const MAX_VERIFIED_SNAPSHOT_PAGES: u32 = 1 << 20;

/// Longueur exacte du marqueur `meta` : `height(8 BE) ‖ tip_hash(32)
/// ‖ manifest_hash(32)` = 72 octets.
const MARKER_LEN: usize = 8 + 32 + 32;

// ------------------------------------------------------------- manifest

/// Manifest d'un snapshot vérifié : ancre (hauteur + hash du bloc
/// finalisé), racine d'état engagée par le checkpoint, compteurs
/// d'entrées et hash de chaque page.
///
/// Encodage canonique (strict, big-endian, sans champ variable autre
/// que les hashs de pages) :
///
/// ```text
/// manifest = "SCONE-SNAP-MAN-V1"
///          ‖ height(8 BE) ‖ tip_hash(32) ‖ state_root(32)
///          ‖ page_count(4 BE) ‖ domain_count(8 BE) ‖ tld_count(8 BE)
///          ‖ page_hashes(page_count × 32)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshotManifest {
    /// Hauteur du bloc finalisé (état transporté).
    pub height: u64,
    /// Hash du bloc finalisé (ancre — recalculé par l'importateur
    /// contre le bloc fourni par le réseau).
    pub tip_hash: [u8; 32],
    /// Racine d'état canonique (`state_root_smt`) engagée par le
    /// checkpoint — ce que la vérification crypto doit retrouver.
    pub state_root: [u8; 32],
    /// Nombre de pages du snapshot.
    pub page_count: u32,
    /// Nombre total d'entrées domaine.
    pub domain_count: u64,
    /// Nombre total d'entrées TLD.
    pub tld_count: u64,
    /// Hash de chaque page, dans l'ordre des index.
    pub page_hashes: Vec<[u8; 32]>,
}

impl VerifiedSnapshotManifest {
    /// Encodage canonique (voir le format ci-dessus).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MANIFEST_TAG.len() + 64 + 32 * self.page_hashes.len());
        out.extend_from_slice(MANIFEST_TAG);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.tip_hash);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.page_count.to_be_bytes());
        out.extend_from_slice(&self.domain_count.to_be_bytes());
        out.extend_from_slice(&self.tld_count.to_be_bytes());
        for hash in &self.page_hashes {
            out.extend_from_slice(hash);
        }
        out
    }

    /// Décodage strict : tag exact, longueurs exactes, aucun octet
    /// en excès, cohérence `page_count == page_hashes.len()`, bornes
    /// DoS respectées.
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] sur tout écart.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupted =
            |what: &str| StorageError::Corrupted(format!("verified snapshot manifest: {what}"));
        let header = MANIFEST_TAG.len() + 8 + 32 + 32 + 4 + 8 + 8;
        if bytes.len() < header || &bytes[..MANIFEST_TAG.len()] != MANIFEST_TAG {
            return Err(corrupted("bad tag or short header"));
        }
        let mut at = MANIFEST_TAG.len();
        let take8 = |bytes: &[u8], at: &mut usize| {
            let v = u64::from_be_bytes(bytes[*at..*at + 8].try_into().expect("sliced to 8"));
            *at += 8;
            v
        };
        let height = take8(bytes, &mut at);
        let tip_hash: [u8; 32] = bytes[at..at + 32].try_into().expect("sliced to 32");
        at += 32;
        let state_root: [u8; 32] = bytes[at..at + 32].try_into().expect("sliced to 32");
        at += 32;
        let page_count = u32::from_be_bytes(bytes[at..at + 4].try_into().expect("sliced to 4"));
        at += 4;
        let domain_count = take8(bytes, &mut at);
        let tld_count = take8(bytes, &mut at);
        if page_count > MAX_VERIFIED_SNAPSHOT_PAGES {
            return Err(corrupted("page count beyond the DoS bound"));
        }
        let expected = header + 32 * page_count as usize;
        if bytes.len() != expected {
            return Err(corrupted("length does not match the page count"));
        }
        let mut page_hashes = Vec::with_capacity(page_count as usize);
        for _ in 0..page_count as usize {
            page_hashes.push(bytes[at..at + 32].try_into().expect("sliced to 32"));
            at += 32;
        }
        Ok(Self {
            height,
            tip_hash,
            state_root,
            page_count,
            domain_count,
            tld_count,
            page_hashes,
        })
    }

    /// Hash canonique du manifest (engage tout son contenu).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        scone_crypto::hash256(&[MANIFEST_HASH_TAG, &self.encode()])
    }
}

// ----------------------------------------------------------------- page

/// Une entrée d'état du snapshot : domaine ou TLD, dans les formats
/// de stockage stricts existants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotEntry {
    /// Un domaine (`DomainStateBytes`, 57 ou 89 octets).
    Domain {
        /// Identité consensus (32 octets, jamais tronquée).
        id: DomainId,
        /// État au format de stockage canonique.
        state: DomainStateBytes,
    },
    /// Un TLD (`TldStateBytes`, 34 octets).
    Tld {
        /// Identité consensus.
        id: TldId,
        /// État au format de stockage canonique.
        state: TldStateBytes,
    },
}

/// Une page du snapshot : `(index, hauteur, state_root du checkpoint,
/// entrées)`. L'ordre des pages est : toutes les entrées domaine (ids
/// croissants), puis toutes les entrées TLD (ids croissants) —
/// l'ordre de la pagination curseur du store.
///
/// ```text
/// page    = "SCONE-SNAP-PAGE-V1"
///         ‖ index(4 BE) ‖ height(8 BE) ‖ state_root(32)
///         ‖ entry_count(4 BE) ‖ entries
/// entry   = kind(0x01 domaine | 0x02 TLD) ‖ id(32) ‖ len(2 BE) ‖ état
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPage {
    /// Index de la page (0-based, sans trou).
    pub index: u32,
    /// Hauteur du bloc finalisé (identique sur toutes les pages).
    pub height: u64,
    /// Racine d'état du checkpoint (identique sur toutes les pages —
    /// chaque page est auto-identifiée).
    pub state_root: [u8; 32],
    /// Entrées de la page (≤ [`VERIFIED_SNAPSHOT_PAGE_ENTRIES`] à
    /// l'export, ≤ [`MAX_VERIFIED_SNAPSHOT_PAGE_ENTRIES`] à l'import).
    pub entries: Vec<SnapshotEntry>,
}

impl SnapshotPage {
    /// Encodage canonique (voir le format ci-dessus).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PAGE_TAG);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            let (kind, id, state) = match entry {
                SnapshotEntry::Domain { id, state } => (0x01u8, id.as_bytes(), state.as_encoded()),
                SnapshotEntry::Tld { id, state } => (0x02u8, id.as_bytes(), state.as_encoded()),
            };
            out.push(kind);
            out.extend_from_slice(id);
            out.extend_from_slice(&(state.len() as u16).to_be_bytes());
            out.extend_from_slice(state);
        }
        out
    }

    /// Décodage strict : tag exact, compte d'entrées dans la borne
    /// DoS, longueurs d'états canoniques (57/89 pour un domaine, 34
    /// pour un TLD), aucun octet en excès.
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] sur tout écart structurel (la
    /// validité des états eux-mêmes — tag, décodage — est vérifiée
    /// à l'import).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupted = |what: &str| StorageError::Corrupted(format!("snapshot page: {what}"));
        let header = PAGE_TAG.len() + 4 + 8 + 32 + 4;
        if bytes.len() < header || &bytes[..PAGE_TAG.len()] != PAGE_TAG {
            return Err(corrupted("bad tag or short header"));
        }
        let mut at = PAGE_TAG.len();
        let index = u32::from_be_bytes(bytes[at..at + 4].try_into().expect("sliced to 4"));
        at += 4;
        let height = u64::from_be_bytes(bytes[at..at + 8].try_into().expect("sliced to 8"));
        at += 8;
        let state_root: [u8; 32] = bytes[at..at + 32].try_into().expect("sliced to 32");
        at += 32;
        let entry_count =
            u32::from_be_bytes(bytes[at..at + 4].try_into().expect("sliced to 4")) as usize;
        at += 4;
        if entry_count > MAX_VERIFIED_SNAPSHOT_PAGE_ENTRIES {
            return Err(corrupted("entry count beyond the DoS bound"));
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let kind = *bytes.get(at).ok_or_else(|| corrupted("truncated entry"))?;
            at += 1;
            let id: [u8; 32] = bytes
                .get(at..at + 32)
                .ok_or_else(|| corrupted("truncated entry id"))?
                .try_into()
                .expect("sliced to 32");
            at += 32;
            let len = usize::from(u16::from_be_bytes(
                bytes
                    .get(at..at + 2)
                    .ok_or_else(|| corrupted("truncated entry length"))?
                    .try_into()
                    .expect("sliced to 2"),
            ));
            at += 2;
            let state_bytes = bytes
                .get(at..at + len)
                .ok_or_else(|| corrupted("truncated entry state"))?;
            at += len;
            match kind {
                0x01 => {
                    if len != DOMAIN_STATE_LEN_SOME && len != DOMAIN_STATE_LEN_NONE {
                        return Err(corrupted("domain state length not canonical"));
                    }
                    let mut raw = [0u8; DOMAIN_STATE_LEN_SOME];
                    raw[..len].copy_from_slice(state_bytes);
                    entries.push(SnapshotEntry::Domain {
                        id: DomainId::from_bytes(id),
                        state: DomainStateBytes(raw),
                    });
                }
                0x02 => {
                    if len != TLD_STATE_LEN {
                        return Err(corrupted("tld state length not canonical"));
                    }
                    let mut raw = [0u8; TLD_STATE_LEN];
                    raw.copy_from_slice(state_bytes);
                    entries.push(SnapshotEntry::Tld {
                        id: TldId::from_bytes(id),
                        state: TldStateBytes(raw),
                    });
                }
                other => return Err(corrupted(&format!("unknown entry kind {other:#04x}"))),
            }
        }
        if at != bytes.len() {
            return Err(corrupted("trailing bytes"));
        }
        Ok(Self {
            index,
            height,
            state_root,
            entries,
        })
    }

    /// Hash canonique de la page (engage l'encodage intégral).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        scone_crypto::hash256(&[PAGE_HASH_TAG, &self.encode()])
    }
}

// --------------------------------------------------------- marker (meta)

/// Marqueur d'import vérifié lu dans `meta` (P0.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSnapshotMarker {
    /// Hauteur du bloc d'ancrage importé.
    pub height: u64,
    /// Hash du bloc d'ancrage importé.
    pub tip_hash: [u8; 32],
    /// Hash du manifest vérifié à l'import.
    pub manifest_hash: [u8; 32],
}

impl VerifiedSnapshotMarker {
    /// Encodage : `height(8 BE) ‖ tip_hash(32) ‖ manifest_hash(32)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MARKER_LEN);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.tip_hash);
        out.extend_from_slice(&self.manifest_hash);
        out
    }

    /// Décodage strict (72 octets exactement).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] sur toute autre longueur.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MARKER_LEN {
            return Err(StorageError::Corrupted(
                "verified_snapshot_v1 marker: not 72 bytes".into(),
            ));
        }
        Ok(Self {
            height: u64::from_be_bytes(bytes[..8].try_into().expect("sliced to 8")),
            tip_hash: bytes[8..40].try_into().expect("sliced to 32"),
            manifest_hash: bytes[40..72].try_into().expect("sliced to 32"),
        })
    }
}

// ---------------------------------------------------------------- export

/// Exporte l'état du dernier checkpoint finalisé en pages vérifiées
/// (P0.3) : `(manifest, pages encodées)`.
///
/// Prérequis (sinon [`StorageError::SnapshotUnavailable`]) : le store
/// détient un snapshot d'état persisté (tables `snapshot_v3_*`,
/// écrites à l'intervalle M6b dans la transaction du bloc) ET il
/// siège exactement à la hauteur du `checkpoint` fourni. L'ancre est
/// recalculée : le hash du bloc stocké à cette hauteur doit égaler
/// `checkpoint.data.block_hash` (jamais cru).
///
/// Sérialise l'état du checkpoint finalisé — PAS la pointe : la
/// fenêtre `CHECKPOINT_KEEP` et l'intervalle de snapshot font que ce
/// chemin sert un état stable, re-vérifiable cryptographiquement par
/// tout importateur.
///
/// # Errors
///
/// [`StorageError::SnapshotUnavailable`] si le store n'a pas de
/// snapshot utilisable à la hauteur du checkpoint ;
/// [`StorageError::Corrupted`] sur octets indécodables ou ancre
/// invalide.
pub fn export_verified_snapshot(
    store: &RedbStore,
    checkpoint: &Checkpoint,
) -> Result<(VerifiedSnapshotManifest, Vec<Vec<u8>>)> {
    let unavailable = |what: &str| StorageError::SnapshotUnavailable(format!("export: {what}"));
    let meta = store
        .snapshot_meta()?
        .ok_or_else(|| unavailable("no persisted state snapshot in this store"))?;
    if meta.height == 0 {
        return Err(unavailable("persisted snapshot sits at genesis"));
    }
    if meta.height != checkpoint.data.height {
        let what = format!(
            "persisted snapshot at height {} but checkpoint finalizes height {}",
            meta.height, checkpoint.data.height
        );
        return Err(unavailable(&what));
    }
    if meta.tip_hash != checkpoint.data.block_hash {
        return Err(unavailable(
            "persisted snapshot anchor hash differs from the checkpoint block hash",
        ));
    }
    // Ancre recalculée depuis les octets du bloc stocké (règle
    // projet : les hashs fournis sont toujours recalculés).
    let anchor_bytes = store
        .block_at_height(meta.height)?
        .ok_or_else(|| unavailable("anchor block missing below the persisted tip"))?;
    let anchor: Block = decode_complete(&anchor_bytes)
        .map_err(|e| StorageError::Corrupted(format!("anchor block: {e}")))?;
    if anchor.header.height != meta.height {
        return Err(StorageError::Corrupted(format!(
            "blocks_by_height[{}]: block announces height {}",
            meta.height, anchor.header.height
        )));
    }
    let recomputed = scone_blockchain::block_hash(&anchor.header)
        .map_err(|e| StorageError::Corrupted(format!("anchor block hash: {e}")))?;
    if recomputed.as_bytes() != &meta.tip_hash {
        return Err(unavailable(
            "recomputed anchor hash differs from the snapshot tip hash",
        ));
    }

    // Pagination curseur : domaines (ids croissants) puis TLDs.
    let mut pages: Vec<SnapshotPage> = Vec::new();
    let mut domain_count: u64 = 0;
    let mut tld_count: u64 = 0;
    let mut cursor: Option<DomainId> = None;
    loop {
        let (page_entries, next) =
            store.snapshot_domains(cursor, VERIFIED_SNAPSHOT_PAGE_ENTRIES)?;
        let page_len = page_entries.len();
        for (id, state) in page_entries {
            domain_count += 1;
            page_entry_slot(&mut pages, checkpoint, meta.height)
                .push(SnapshotEntry::Domain { id, state });
        }
        cursor = next;
        if page_len < VERIFIED_SNAPSHOT_PAGE_ENTRIES {
            break;
        }
    }
    let mut tld_cursor: Option<TldId> = None;
    loop {
        let (page_entries, next) =
            store.snapshot_tlds(tld_cursor, VERIFIED_SNAPSHOT_PAGE_ENTRIES)?;
        let page_len = page_entries.len();
        for (id, state) in page_entries {
            tld_count += 1;
            page_entry_slot(&mut pages, checkpoint, meta.height)
                .push(SnapshotEntry::Tld { id, state });
        }
        tld_cursor = next;
        if page_len < VERIFIED_SNAPSHOT_PAGE_ENTRIES {
            break;
        }
    }

    let page_hashes: Vec<[u8; 32]> = pages.iter().map(SnapshotPage::hash).collect();
    let manifest = VerifiedSnapshotManifest {
        height: meta.height,
        tip_hash: meta.tip_hash,
        state_root: checkpoint.data.state_root,
        page_count: pages.len() as u32,
        domain_count,
        tld_count,
        page_hashes,
    };
    let encoded: Vec<Vec<u8>> = pages.iter().map(SnapshotPage::encode).collect();
    Ok((manifest, encoded))
}

/// Assure qu'une page courante existe et peut recevoir une entrée de
/// plus (en ouvre une neuve sinon) ; retourne le slot d'entrées.
fn page_entry_slot<'a>(
    pages: &'a mut Vec<SnapshotPage>,
    checkpoint: &Checkpoint,
    height: u64,
) -> &'a mut Vec<SnapshotEntry> {
    let needs_new = pages
        .last()
        .is_none_or(|p| p.entries.len() >= VERIFIED_SNAPSHOT_PAGE_ENTRIES);
    if needs_new {
        pages.push(SnapshotPage {
            index: pages.len() as u32,
            height,
            state_root: checkpoint.data.state_root,
            entries: Vec::with_capacity(VERIFIED_SNAPSHOT_PAGE_ENTRIES),
        });
    }
    let last = pages.last_mut().expect("just pushed or existing");
    &mut last.entries
}

// ---------------------------------------------------------------- import

/// Applique un snapshot vérifié dans un store VIDE (P0.3/P0.4) :
/// vérifie TOUT avant d'écrire, puis persiste l'état en une seule
/// transaction redb.
///
/// Vérifications (dans l'ordre, avant toute écriture) :
///
/// 1. manifest auto-cohérent (`page_count == pages.len() ==
///    page_hashes.len()`, compteurs dans le budget borné) ;
/// 2. cohérence manifest ↔ checkpoint : `height`, `tip_hash ==
///    checkpoint.data.block_hash`, `state_root ==
///    checkpoint.data.state_root` ;
/// 3. chaque page : décodage strict, `index` séquentiel,
///    `height`/`state_root` portés == manifest, **hash recalculé ==
///    manifest** ;
/// 4. ids strictement croissants (aucun doublon, ordre canonique) ;
/// 5. somme des entrées == compteurs du manifest ;
/// 6. **vérification cryptographique** : la racine SMT recalculée
///    depuis les entrées importées
///    (`scone_blockchain::snapshot_verify::recompute_state_root`)
///    doit égaler `checkpoint.data.state_root` ;
/// 7. store cible vide (tip à la genèse).
///
/// Écriture atomique unique : tables vivantes `domains`/`tlds` +
/// compteurs + `tip = (H, hash)`, tables gelées `snapshot_v3_*`
/// ancrées à `(H, hash)` (le boot rejouera le suffixe au-dessus de H
/// via le chemin M6b), et marqueur `meta["verified_snapshot_v1"]` =
/// `height ‖ tip_hash ‖ manifest_hash`.
///
/// Le bloc d'ancrage H n'est PAS dans le snapshot : le relay le
/// demande au réseau et le pose via
/// [`RedbStore::append_bootstrap_anchor`], puis les blocs suivants
/// par l'append atomique ordinaire.
///
/// # Errors
///
/// [`StorageError::SnapshotRejected`] sur toute vérification échouée
/// (page falsifiée, page manquante, mauvaise racine, hauteurs/tip
/// incohérents, doublons, compteurs faux) — le store reste alors
/// STRICTEMENT inchangé ; [`StorageError::Corrupted`] sur les octets
/// indécodables ; [`StorageError::SnapshotUnavailable`] si le store
/// cible n'est pas vide.
pub fn import_verified_snapshot(
    store: &mut RedbStore,
    checkpoint: &Checkpoint,
    manifest: &VerifiedSnapshotManifest,
    pages: &[Vec<u8>],
) -> Result<()> {
    let reject = |what: &str| StorageError::SnapshotRejected(what.to_owned());
    // (1) manifest auto-cohérent + budget total borné (garde DoS).
    if manifest.page_count as usize != pages.len() || manifest.page_hashes.len() != pages.len() {
        return Err(reject("page count does not match the pages provided"));
    }
    let budget = MAX_VERIFIED_SNAPSHOT_PAGE_ENTRIES as u64 * pages.len() as u64;
    if manifest.domain_count.saturating_add(manifest.tld_count) > budget {
        return Err(reject("manifest counters exceed the pages' entry budget"));
    }
    // (2) cohérence manifest ↔ checkpoint.
    if manifest.height != checkpoint.data.height {
        return Err(reject("manifest height differs from the checkpoint height"));
    }
    if manifest.tip_hash != checkpoint.data.block_hash {
        return Err(reject(
            "manifest tip hash differs from the checkpoint block hash",
        ));
    }
    if manifest.state_root != checkpoint.data.state_root {
        return Err(reject(
            "manifest state root differs from the checkpoint state root",
        ));
    }
    if manifest.height == 0 {
        return Err(reject("a snapshot at genesis carries nothing"));
    }
    // (7) store cible vide, vérifié AVANT tout travail lourd.
    let (tip_height, _) = store.tip()?;
    if tip_height != 0 {
        return Err(StorageError::SnapshotUnavailable(
            "import target store is not empty".into(),
        ));
    }

    // (3)(4)(5) pages : structure, hash, ordre canonique, compteurs.
    // Les états bruts (octets canoniques) servent à l'écriture ; les
    // états décodés à la vérification crypto.
    let mut domains: Vec<(DomainId, DomainStateBytes)> = Vec::new();
    let mut tlds: Vec<(TldId, TldStateBytes)> = Vec::new();
    let mut domains_dec: Vec<(DomainId, scone_blockchain::DomainState)> = Vec::new();
    let mut tlds_dec: Vec<(TldId, scone_blockchain::TldState)> = Vec::new();
    let mut last_domain: Option<[u8; 32]> = None;
    let mut last_tld: Option<[u8; 32]> = None;
    for (i, raw) in pages.iter().enumerate() {
        let page = SnapshotPage::decode(raw)?;
        if page.index != i as u32 {
            return Err(reject("page index is not sequential"));
        }
        if page.height != manifest.height {
            return Err(reject("page height differs from the manifest height"));
        }
        if page.state_root != manifest.state_root {
            return Err(reject(
                "page state root differs from the manifest state root",
            ));
        }
        if page.hash() != manifest.page_hashes[i] {
            return Err(reject("page hash does not match the manifest"));
        }
        for entry in &page.entries {
            match entry {
                SnapshotEntry::Domain { id, state } => {
                    let id_bytes = *id.as_bytes();
                    if last_domain.is_some_and(|prev| id_bytes <= prev) {
                        return Err(reject("domain ids are not strictly ascending"));
                    }
                    last_domain = Some(id_bytes);
                    let decoded = DomainStateBytes::decode(state.as_encoded())?;
                    domains.push((*id, *state));
                    domains_dec.push((*id, decoded));
                }
                SnapshotEntry::Tld { id, state } => {
                    let id_bytes = *id.as_bytes();
                    if last_tld.is_some_and(|prev| id_bytes <= prev) {
                        return Err(reject("tld ids are not strictly ascending"));
                    }
                    last_tld = Some(id_bytes);
                    let decoded = TldStateBytes::decode(state.as_encoded())?;
                    tlds.push((*id, *state));
                    tlds_dec.push((*id, decoded));
                }
            }
        }
    }
    if domains.len() as u64 != manifest.domain_count {
        return Err(reject("domain entry count does not match the manifest"));
    }
    if tlds.len() as u64 != manifest.tld_count {
        return Err(reject("tld entry count does not match the manifest"));
    }

    // (6) vérification cryptographique : la racine recalculée depuis
    // les ENTRÉES doit égaler celle que le comité a signée.
    let roots = scone_blockchain::snapshot_verify::recompute_state_root(&domains_dec, &tlds_dec);
    if roots.state_root != manifest.state_root {
        return Err(reject(
            "recomputed state root does not match the checkpoint state root",
        ));
    }

    // Écriture atomique : tout ou rien.
    let marker = VerifiedSnapshotMarker {
        height: manifest.height,
        tip_hash: manifest.tip_hash,
        manifest_hash: manifest.hash(),
    };
    store.write_verified_snapshot(&domains, &tlds, &marker)
}
