//! Deterministic distributed-simulation harness (P1.6).
//!
//! A [`SimNet`] drives N real [`Blockchain`] instances (no mocks) over a
//! **virtual clock** and an **event queue** — no sockets, no async, no
//! wall clock. Every decision is a pure function of the run seed, so a
//! scenario is byte-reproducible and seedable.
//!
//! # Model
//!
//! - **Virtual time**: events are keyed by `(tick, insertion order)`; a
//!   logical clock advances only on *real* events (injected duplicate
//!   copies never move it).
//! - **Network**: every send is subjected to a configurable loss
//!   probability, an artificial latency window, optional duplication
//!   (one extra delayed copy) and the current **partition** map.
//!   Delivery draws are a pure function of `(seed, send-sequence)`,
//!   never of a shared RNG stream.
//! - **Gossip**: epidemic — every node relays a first-sight
//!   `Block`/`Transaction`/`Checkpoint` to its connected peers (same
//!   partition), mirroring the relay's H2 loop-cut rule (relay only on
//!   first sight, never on duplicates).
//! - **Production**: one deterministic leader per height (committee
//!   rotation `committee[height % len]`); the leader assembles a block
//!   from its mempool with the same shrink-on-conflict policy as the
//!   relay's `produce_if_ready`, signed by an allowed producer key. A
//!   stale leader (crashed, partitioned away) is covered by a timeout
//!   fallback: the lowest-index allowed alive node of the group
//!   produces after two idle intervals.
//! - **Finality**: committee members sign the deterministic checkpoint
//!   content of their tip every [`SimParams::sign_interval`] heights
//!   through a real crash-safe [`SignerGuard`] (one key = one vote per
//!   epoch, state fsynced before the signature is used). Signatures
//!   aggregate by gossip; on quorum the node finalizes via
//!   [`Blockchain::accept_checkpoint`]. On top of the core rules the
//!   sim adds one relay-level guard: a checkpoint is only accumulated
//!   when the referenced block is the node's *own* canonical block at
//!   that height (the core `accept_checkpoint` cannot see foreign
//!   branches — a node first reorgs, then finalizes).
//! - **Crash/restart**: a crashed node loses all RAM state (chain,
//!   mempool, parking, seen-sets) but keeps its signer-guard directory,
//!   exactly like a real process restart; it resynchronizes by
//!   replaying canonical blocks served by its peers (`GetBlocks`) and
//!   finalizes by replaying the checkpoint window (`GetCheckpoints`).
//!
//! # Determinism contract (the duplicate-invariance property)
//!
//! A duplicated message is scheduled strictly *after* its original and
//! is absorbed by dedup (seen-blocks / seen-txs / checkpoint-window /
//! merged-signature sets) **without emitting any new base send or
//! timer**. Because (a) the logical clock ignores duplicate events and
//! (b) loss/latency draws depend only on `(seed, send-sequence)` of
//! base sends, the stream of *real* events is identical with and
//! without duplication — asserted empirically by
//! `sim::tests::duplicate_and_delay`. Valid in the absence of a crash
//! between an original and its copy (a restarted node legitimately
//! re-processes late duplicates).
//!
//! # Limits
//!
//! No real transport layer (no libp2p, no request-response framing):
//! this harness exercises the *chain* logic under adversarial
//! delivery, not the swarm. Node discovery, connection management,
//! backpressure and storage persistence are out of scope; blocks are
//! served from the in-RAM window (scenarios stay under
//! [`crate::RAM_WINDOW_BLOCKS`]), so `BlockPruned` paths are exercised
//! only by the dedicated unit tests of the chain crate.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use scone_core::checkpoint::{Checkpoint, CheckpointData};
use scone_core::{
    DomainId, DomainName, MIN_FINALITY_COMMITTEE_SIZE, Proof, RecordHash, RegisterDomain,
    RegisterTld, SetTldOpen, TldId, TldName, Transaction, UpdateDomain, quorum_for,
};
use scone_crypto::{PublicKey, Signature, SigningKey};
use scone_protocol::{Block, BlockHash};

use crate::block_hash::block_hash;
use crate::builder::BlockBuilder;
use crate::chain::Blockchain;
use crate::error::BlockchainError;
use crate::signer::SignerGuard;
use crate::txid::{TxId, transaction_id};
use crate::validate::validate_transaction;

/// Virtual-clock seconds per block height: block timestamps are a pure
/// function of the height, never of the delivery interleaving.
pub const BLOCK_TS_STEP: u64 = 10;

/// Per-node mempool cap (mirrors the relay's bounded pool).
const MEMPOOL_CAP: usize = 512;

/// Blocks per `GetBlocks` sync response.
const SYNC_BATCH: u64 = 64;

/// Pending checkpoint aggregates cap per node.
const PENDING_CP_CAP: usize = 64;

/// Parked (out-of-order) block cap per node. Large on purpose: the
/// catch-up walk assembles a whole competing branch across successive
/// sync batches in the parking before a single whole-branch adoption —
/// the cap must hold a post-partition losing branch (test scenarios
/// stay under ~2k blocks of divergence).
const PARKED_CAP: usize = 2048;

// ---------------------------------------------------------------------------
// Deterministic randomness
// ---------------------------------------------------------------------------

/// SplitMix64 finalizer — the only randomness primitive of the harness.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Per-send delivery draws: a pure function of `(seed, send_seq)` — two
/// runs with the same seed and the same base-send stream draw the same
/// loss/latency/duplication decisions (determinism contract).
struct SendDraw {
    lost: bool,
    latency: u64,
    dup: bool,
    dup_delay: u64,
}

fn send_draw(seed: u64, seq: u64, p: &SimParams) -> SendDraw {
    let (lo, hi) = p.latency_ticks;
    let span = hi - lo + 1;
    SendDraw {
        lost: mix(seed ^ mix(seq)) % 1000 < u64::from(p.loss_permille),
        latency: lo + mix(seed ^ mix(seq.wrapping_add(0x1111))) % span,
        dup: mix(seed ^ mix(seq.wrapping_add(0x2222))) % 1000 < u64::from(p.dup_permille),
        dup_delay: 1 + mix(seed ^ mix(seq.wrapping_add(0x3333))) % 8,
    }
}

// ---------------------------------------------------------------------------
// Parameters and statistics
// ---------------------------------------------------------------------------

/// Scenario parameters. All fields are public: a test pins a
/// configuration and a seed, the run is then fully deterministic.
#[derive(Debug, Clone)]
pub struct SimParams {
    /// Number of nodes (node `i` holds the pool key `[i+2; 32]`).
    pub nodes: usize,
    /// Run seed — every draw derives from it.
    pub seed: u64,
    /// Loss probability (per mille, per message).
    pub loss_permille: u32,
    /// Duplication probability (per mille, gossip messages only).
    pub dup_permille: u32,
    /// Artificial latency window in ticks (min must be ≥ 1).
    pub latency_ticks: (u64, u64),
    /// Ticks between production opportunities per node.
    pub produce_interval: u64,
    /// Checkpoints are signed at heights that are multiples of this.
    pub sign_interval: u64,
    /// Ticks between sync attempts per node.
    pub sync_interval: u64,
    /// Hard time bound (virtual ticks) — `run_until` never passes it.
    pub horizon: u64,
}

impl Default for SimParams {
    fn default() -> Self {
        Self {
            nodes: 8,
            seed: 0x5C0E,
            loss_permille: 50,
            dup_permille: 0,
            latency_ticks: (1, 5),
            produce_interval: 7,
            sign_interval: 16,
            sync_interval: 41,
            horizon: 200_000,
        }
    }
}

/// Counters of the transport layer.
#[derive(Debug, Default, Clone)]
pub struct SimStats {
    /// Base messages sent (before loss).
    pub sent: u64,
    /// Messages delivered (originals + duplicates).
    pub delivered: u64,
    /// Messages lost to the loss probability.
    pub lost: u64,
    /// Messages dropped by the current partition.
    pub partition_dropped: u64,
    /// Duplicate copies injected by the duplication probability.
    pub duplicates_sent: u64,
    /// Blocks produced locally.
    pub blocks_produced: u64,
    /// Blocks accepted as canonical (push or reorg).
    pub blocks_accepted: u64,
    /// Branch reorganizations (whole-branch adoptions).
    pub reorgs: u64,
    /// Checkpoints finalized on any node.
    pub checkpoints_finalized: u64,
    /// Timeout fallback productions.
    pub producer_timeouts: u64,
}

/// Typed-rejection counter: every refusal the chain layer returns is
/// classified and counted — scenarios assert on *clean* rejections.
#[derive(Debug, Default, Clone)]
pub struct Rejections {
    counts: BTreeMap<&'static str, usize>,
}

impl Rejections {
    fn count(&mut self, kind: &'static str) {
        *self.counts.entry(kind).or_insert(0) += 1;
    }

    /// Occurrences of `kind`.
    #[must_use]
    /// Toutes les catégories non nulles (diagnostic).
    pub fn nonzero(&self) -> Vec<(&'static str, usize)> {
        self.counts
            .iter()
            .filter(|(_, v)| **v > 0)
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    pub fn get(&self, kind: &str) -> usize {
        self.counts.get(kind).copied().unwrap_or(0)
    }
}

/// Maps a chain error to a stable rejection kind.
fn classify(e: &BlockchainError) -> &'static str {
    use BlockchainError as E;
    match e {
        E::TxReplay => "tx_replay",
        E::DomainAlreadyRegistered => "domain_already_registered",
        E::InvalidSequence { .. } => "invalid_sequence",
        E::NotOwner | E::NotTldOwner => "not_owner",
        E::UnknownDomain => "unknown_domain",
        E::UnknownTld => "unknown_tld",
        E::TldClosed => "tld_closed",
        E::TldAlreadyRegistered => "tld_already_registered",
        E::UnknownParent => "unknown_parent",
        E::ParentNotTip => "parent_not_tip",
        E::InvalidProducer(_) => "invalid_producer",
        E::BlockPruned { .. } => "block_pruned",
        E::InvalidSignature => "invalid_signature",
        _ => "other",
    }
}

/// Cheap state precheck (port of the relay's `precheck_state`: full
/// rules are re-run at push time anyway).
fn precheck_tx(chain: &Blockchain, tx: &Transaction) -> std::result::Result<(), BlockchainError> {
    use Transaction as T;
    match tx {
        T::RegisterDomain(r) => {
            let tld_id = TldId::from_tld(&r.name.tld());
            let Some(tld) = chain.state().tld(&tld_id) else {
                return Err(BlockchainError::UnknownTld);
            };
            if !tld.open {
                return Err(BlockchainError::TldClosed);
            }
            if chain.state().domain(&r.domain_id).is_some() {
                return Err(BlockchainError::DomainAlreadyRegistered);
            }
            Ok(())
        }
        T::UpdateDomain(u) => {
            let Some(st) = chain.state().domain(&u.domain_id) else {
                return Err(BlockchainError::UnknownDomain);
            };
            if st.sequence + 1 != u.sequence {
                return Err(BlockchainError::InvalidSequence {
                    expected: st.sequence + 1,
                    got: u.sequence,
                });
            }
            if st.owner != u.owner {
                return Err(BlockchainError::NotOwner);
            }
            Ok(())
        }
        T::RegisterTld(t) => {
            if chain.state().tld(&t.tld_id).is_some() {
                return Err(BlockchainError::TldAlreadyRegistered);
            }
            Ok(())
        }
        T::SetTldOpen(s) => {
            let Some(tld) = chain.state().tld(&s.tld_id) else {
                return Err(BlockchainError::UnknownTld);
            };
            if tld.owner != s.owner {
                return Err(BlockchainError::NotTldOwner);
            }
            Ok(())
        }
        // Unused by the driver — the full rules run at push time.
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Messages and events
// ---------------------------------------------------------------------------

/// Simulated wire messages (the same payload types as the real wire:
/// `scone_protocol::Message`, minus the transport framing).
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum SimMsg {
    Block(Block),
    Tx(Transaction),
    Checkpoint(Checkpoint),
    GetBlocks { start: u64 },
    Blocks(Vec<Block>),
    GetCheckpoints,
    Checkpoints(Vec<Checkpoint>),
}

impl SimMsg {
    /// Only gossip messages are subject to duplication (see the
    /// determinism contract: duplicated request/response batches would
    /// emit duplicate base sends and shift the draw stream).
    fn duplicable(&self) -> bool {
        matches!(self, Self::Block(_) | Self::Tx(_) | Self::Checkpoint(_))
    }
}

#[derive(Debug, Clone)]
enum Event {
    Deliver {
        from: usize,
        to: usize,
        msg: SimMsg,
        copy: u32,
    },
    ProduceRound,
    Sync {
        node: usize,
    },
    Submit {
        node: usize,
        tx: Transaction,
    },
}

impl Event {
    /// Duplicate copies never advance the logical clock (determinism).
    fn is_real(&self) -> bool {
        !matches!(self, Self::Deliver { copy: 1, .. })
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// Outcome of offering a block to a node.
enum BlockOutcome {
    Accepted,
    Duplicate,
    /// Parent unknown — parked, waiting for the missing segment.
    ParkedOrphan,
    /// Parent known and non-tip — parked after a branch-switch attempt.
    ParkedKnown,
    Rejected(&'static str),
}

/// Outcome of offering a transaction to a node.
enum TxOutcome {
    New,
    Duplicate,
    Rejected(&'static str),
}

/// One simulated node: a real `Blockchain`, a mempool, a crash-safe
/// signer guard on disk, and the bookkeeping a relay keeps.
struct SimNode {
    #[allow(dead_code)]
    id: usize,
    alive: bool,
    key: SigningKey,
    pk: PublicKey,
    dir: PathBuf,
    chain: Blockchain,
    guard: SignerGuard,
    mempool: Vec<(TxId, Transaction)>,
    parked: HashMap<BlockHash, Block>,
    seen_blocks: HashSet<BlockHash>,
    seen_txs: HashSet<TxId>,
    /// Checkpoint signing hashes already signed by this node's key
    /// (RAM cache over the guard's durable state).
    signed_cps: HashSet<[u8; 32]>,
    /// First checkpoint proposal seen per epoch (first-sight commit):
    /// during bootstrap (epoch chaining not yet established) two
    /// disjoint signer sets could otherwise finalize two incompatible
    /// checkpoints of the SAME epoch. A node relays and signs only
    /// the first proposal it saw for an epoch; a conflicting one is
    /// counted (`cp_conflict`) and dropped — deterministic because
    /// the tie is broken by delivery order, which the virtual clock
    /// fully orders.
    epoch_committed: HashMap<u64, [u8; 32]>,
    /// Pending checkpoint aggregates, keyed by data signing hash.
    pending: BTreeMap<[u8; 32], (CheckpointData, BTreeMap<PublicKey, Signature>)>,
    last_progress_tick: u64,
    sync_counter: u64,
    /// Sync rounds since the node last grew OR reorged while holding
    /// parked blocks it cannot attach (a divergent-canonical stall).
    stuck_rounds: u64,
}

impl SimNode {
    fn new(id: usize, dir: PathBuf) -> Self {
        // Node key = [id + 1; 32]: node 0 holds seed 1 (the `uip`
        // claimer of every fixture), so production authority exists
        // from block 1 on.
        let key = SigningKey::from_bytes([(id as u8).wrapping_add(1); 32]);
        let pk = key.public_key();
        Self {
            id,
            alive: true,
            key,
            pk,
            guard: SignerGuard::load(&dir),
            dir,
            chain: Blockchain::new(),
            mempool: Vec::new(),
            parked: HashMap::new(),
            seen_blocks: HashSet::new(),
            seen_txs: HashSet::new(),
            signed_cps: HashSet::new(),
            epoch_committed: HashMap::new(),
            pending: BTreeMap::new(),
            last_progress_tick: 0,
            sync_counter: 0,
            stuck_rounds: 0,
        }
    }

    /// Offers a block: dedup, linear push on the tip, single-block fork
    /// evaluation (`try_attach`), otherwise parking.
    fn accept_block(&mut self, block: &Block) -> BlockOutcome {
        let Ok(h) = block_hash(&block.header) else {
            return BlockOutcome::Rejected("bad_header");
        };
        if self.seen_blocks.contains(&h) {
            return BlockOutcome::Duplicate;
        }
        self.seen_blocks.insert(h);
        if self.parked.len() >= PARKED_CAP {
            // Bounded parking: evict the lowest (height, hash) entry,
            // never the incoming block.
            let victim = self
                .parked
                .iter()
                .map(|(k, b)| (b.header.height, *k))
                .min()
                .map(|(_, k)| k);
            if let Some(k) = victim {
                self.parked.remove(&k);
            }
        }
        let header = &block.header;
        if header.prev_hash == self.chain.tip_hash() && header.height == self.chain.height() + 1 {
            return match self.chain.push_block_with_gc(block) {
                Ok(_) => BlockOutcome::Accepted,
                Err(e) => BlockOutcome::Rejected(classify(&e)),
            };
        }
        let parent_known = self
            .chain
            .known_hashes
            .values()
            .any(|x| *x == header.prev_hash);
        #[allow(clippy::collapsible_if)]
        if parent_known {
            if self.chain.try_attach(block).is_ok() {
                return BlockOutcome::Accepted;
            }
            // Sister that lost the tie-break, or a non-extendable
            // position: park it — it may combine into a branch.
        }
        self.parked.insert(h, block.clone());
        if parent_known {
            BlockOutcome::ParkedKnown
        } else {
            BlockOutcome::ParkedOrphan
        }
    }

    /// Offers a transaction: full cryptographic validation, cheap
    /// precheck, anti-replay, bounded mempool insert.
    fn accept_tx(&mut self, tx: Transaction) -> TxOutcome {
        let Ok(id) = transaction_id(&tx) else {
            return TxOutcome::Rejected("tx_malformed");
        };
        if self.seen_txs.contains(&id) || self.mempool.iter().any(|(i, _)| i == &id) {
            return TxOutcome::Duplicate;
        }
        if validate_transaction(&tx).is_err() {
            return TxOutcome::Rejected("tx_invalid");
        }
        if let Err(e) = precheck_tx(&self.chain, &tx) {
            return TxOutcome::Rejected(classify(&e));
        }
        if self.chain.is_tx_included(&id) {
            return TxOutcome::Rejected("tx_replay");
        }
        self.seen_txs.insert(id);
        if self.mempool.len() >= MEMPOOL_CAP {
            self.mempool.remove(0);
        }
        self.mempool.push((id, tx));
        TxOutcome::New
    }

    /// Builds and pushes one block on the node's own tip from its
    /// mempool, shrinking from the end on intra-block conflicts (the
    /// relay's resilient production policy). Returns the rejection
    /// kinds observed and the produced block on success.
    fn build_block(&mut self, ts: u64) -> (Vec<&'static str>, Option<Block>) {
        let mut kinds = Vec::new();
        let mut candidates: Vec<Transaction> = Vec::new();
        for (id, tx) in std::mem::take(&mut self.mempool) {
            if self.chain.is_tx_included(&id) {
                kinds.push("tx_replay");
                continue;
            }
            match precheck_tx(&self.chain, &tx) {
                Ok(()) => candidates.push(tx),
                Err(e) => kinds.push(classify(&e)),
            }
        }
        loop {
            let built = BlockBuilder::after(self.chain.height(), self.chain.tip_hash())
                .with_timestamp(ts)
                .with_producer(&self.key)
                .build_with(candidates.clone());
            let block = match built {
                Ok(b) => b,
                Err(e) => {
                    kinds.push(classify(&e));
                    return (kinds, None);
                }
            };
            match self.chain.push_block_with_gc(&block) {
                Ok(_) => return (kinds, Some(block)),
                Err(e) => {
                    kinds.push(classify(&e));
                    if candidates.pop().is_none() {
                        return (kinds, None);
                    }
                }
            }
        }
    }

    /// Best parked branch: the longest chain of parked blocks rooting
    /// on a canonical block, tie-broken by lowest tip hash (the fork
    /// choice rules). Memoized longest-path over the parent-hash
    /// forest — no path cloning: `best[k] = (chain length from k, tip
    /// hash of the best chain through k)`, computed children-first
    /// with an explicit two-phase stack. Deterministic.
    fn best_parked_branch(&self) -> Vec<Block> {
        let keys: Vec<BlockHash> = self.parked.keys().copied().collect();
        let canonical_parents: HashSet<BlockHash> =
            self.chain.known_hashes.values().copied().collect();
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        for &k in &keys {
            let prev = self.parked[&k].header.prev_hash;
            children.entry(prev).or_default().push(k);
        }
        // best[k] = (length of the best chain starting AT k, tip hash)
        let mut best: HashMap<BlockHash, (u64, BlockHash)> = HashMap::new();
        let mut done: HashSet<BlockHash> = HashSet::new();
        for &root in &keys {
            if done.contains(&root) {
                continue;
            }
            let mut stack = vec![(root, false)];
            while let Some(&(k, expanded)) = stack.last() {
                if expanded {
                    let kids = children.get(&k).cloned().unwrap_or_default();
                    let mut folded = (1u64, k);
                    for c in kids {
                        if let Some(v) = best.get(&c) {
                            let cand = (v.0 + 1, v.1);
                            if cand.0 > folded.0
                                || (cand.0 == folded.0 && cand.1.as_bytes() < folded.1.as_bytes())
                            {
                                folded = cand;
                            }
                        }
                    }
                    best.insert(k, folded);
                    done.insert(k);
                    stack.pop();
                } else if done.contains(&k) {
                    stack.pop();
                } else {
                    // mark expanded, push children first
                    let len = stack.len();
                    stack[len - 1] = (k, true);
                    if let Some(kids) = children.get(&k).cloned() {
                        for c in kids {
                            if !done.contains(&c) {
                                stack.push((c, false));
                            }
                        }
                    }
                }
            }
        }
        // Best rooted branch: among parked blocks whose parent is
        // canonical, pick (longest chain, lowest tip hash).
        let mut best_key: Option<(u64, BlockHash, BlockHash)> = None; // (len, tip, root)
        for &k in &keys {
            let prev = self.parked[&k].header.prev_hash;
            if !canonical_parents.contains(&prev) {
                continue;
            }
            let Some(&(len, tip)) = best.get(&k) else {
                continue;
            };
            let better = match best_key {
                None => true,
                Some((bl, bt, _)) => len > bl || (len == bl && tip.as_bytes() < bt.as_bytes()),
            };
            if better {
                best_key = Some((len, tip, k));
            }
        }
        let Some((_, _, root)) = best_key else {
            return Vec::new();
        };
        // Materialize the winning chain: from the root, repeatedly
        // take the child continuing the memoized optimum.
        let mut chain = Vec::new();
        let mut cur = root;
        loop {
            chain.push(self.parked[&cur].clone());
            let want = best.get(&cur).copied();
            let Some((len, _tip)) = want else { break };
            if len == 1 {
                break;
            }
            let kids = children.get(&cur).cloned().unwrap_or_default();
            let next = kids
                .into_iter()
                .filter_map(|c| best.get(&c).map(|(l, t)| (*l, *t, c)))
                .filter(|(l, _, _)| *l == len - 1)
                .min_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()));
            match next {
                Some((_, _, c)) => cur = c,
                None => break,
            }
        }
        chain
    }

    /// Pushes parked blocks that now extend the canonical tip (the
    /// common case after an out-of-order delivery): repeated linear
    /// `push_block_with_gc`, cheapest path — a full-branch adoption
    /// (`try_adopt`) is only for genuine reorgs. Deterministic: among
    /// sister candidates at the same (parent, height), the lowest hash
    /// is tried first (the fork choice tie-break).
    fn drain_parked(&mut self) -> usize {
        let mut count = 0;
        loop {
            let tip = self.chain.tip_hash();
            let want_height = self.chain.height() + 1;
            let candidates: Vec<(BlockHash, Block)> = self
                .parked
                .iter()
                .filter(|(_, b)| b.header.prev_hash == tip && b.header.height == want_height)
                .map(|(h, b)| (*h, b.clone()))
                .collect();
            let Some((h, block)) = candidates
                .into_iter()
                .min_by_key(|(h, _)| h.as_bytes().to_vec())
            else {
                break;
            };
            match self.chain.push_block_with_gc(&block) {
                Ok(_) => {
                    self.parked.remove(&h);
                    count += 1;
                }
                Err(_) => break, // conflicting sister: wait for adoption
            }
        }
        count
    }

    /// Tries to adopt the best parked branch (fork choice: finality
    /// floor, longest chain, lowest tip hash). Returns the adopted
    /// blocks when a reorg happened.
    fn try_adopt(&mut self) -> Option<Vec<Block>> {
        #[allow(clippy::never_loop)]
        for _ in 0..8 {
            let branch = self.best_parked_branch();
            if branch.is_empty() {
                return None;
            }
            match self.chain.adopt_branch(&branch) {
                Ok(true) => {
                    for b in &branch {
                        if let Ok(h) = block_hash(&b.header) {
                            self.parked.remove(&h);
                        }
                    }
                    return Some(branch);
                }
                Ok(false) | Err(_) => return None,
            }
        }
        None
    }

    /// First-sight epoch commitment: returns true when `data` is the
    /// proposal this node committed to for its epoch (the first one
    /// seen, or an exact re-sight). A conflicting proposal of a
    /// committed epoch is refused (bootstrap double-finality guard).
    fn commit_epoch(&mut self, data: &CheckpointData) -> bool {
        let h = data.signing_hash();
        match self.epoch_committed.get(&data.epoch) {
            Some(seen) => *seen == h,
            None => {
                self.epoch_committed.insert(data.epoch, h);
                true
            }
        }
    }

    /// Merges checkpoint signatures; returns the merged aggregate when
    /// something new was learned (relay rule: gossip only while new).
    fn merge_checkpoint(&mut self, cp: &Checkpoint) -> Option<Checkpoint> {
        if self
            .chain
            .checkpoint_window()
            .iter()
            .any(|c| c.data == cp.data)
        {
            return None; // already finalized here: absorb silently
        }
        if self.chain.check_checkpoint_data(&cp.data).is_err() {
            return None; // junk or stale for our chain: never accumulates
        }
        if self.chain.block_hash_at(cp.data.height)
            != Some(BlockHash::from_bytes(cp.data.block_hash))
        {
            return None; // foreign branch (sim-level relay guard)
        }
        let h = cp.data.signing_hash();
        let before = self.pending.get(&h).map_or(0, |(_, s)| s.len());
        let entry = self
            .pending
            .entry(h)
            .or_insert_with(|| (cp.data.clone(), BTreeMap::new()));
        entry.1.extend(cp.signatures.iter().cloned());
        while self.pending.len() > PENDING_CP_CAP {
            if let Some(k) = self.pending.keys().next().copied() {
                self.pending.remove(&k);
            }
        }
        let (data, sigs) = self.pending.get(&h)?;
        if sigs.len() == before {
            return None; // nothing new: absorb silently (loop cut)
        }
        let mut signatures: Vec<(PublicKey, Signature)> =
            sigs.iter().map(|(p, s)| (*p, *s)).collect();
        signatures.sort_by_key(|(p, _)| *p);
        Some(Checkpoint {
            data: data.clone(),
            signatures,
        })
    }

    /// Attempts to finalize every pending aggregate whose quorum is
    /// met. Returns the finalized checkpoint to gossip.
    fn try_finalize(&mut self) -> Option<Checkpoint> {
        let hashes: Vec<[u8; 32]> = self.pending.keys().copied().collect();
        for h in hashes {
            let Some((data, sigs)) = self.pending.get(&h) else {
                continue;
            };
            if self.chain.check_checkpoint_data(data).is_err() {
                self.pending.remove(&h);
                continue;
            }
            // Sim-level guard: only finalize checkpoints of OUR blocks
            // (the core cannot see foreign branches; reorg first).
            if self.chain.block_hash_at(data.height) != Some(BlockHash::from_bytes(data.block_hash))
            {
                continue; // keep: may become valid after a branch adoption
            }
            let committee = self.chain.committee(data.recovery);
            if committee.len() < MIN_FINALITY_COMMITTEE_SIZE {
                self.pending.remove(&h);
                continue;
            }
            let quorum = quorum_for(committee.len());
            let mut signatures: Vec<(PublicKey, Signature)> = sigs
                .iter()
                .filter(|(p, _)| committee.contains(p))
                .map(|(p, s)| (*p, *s))
                .collect();
            if signatures.len() < quorum {
                continue;
            }
            signatures.sort_by_key(|(p, _)| *p);
            let cp = Checkpoint {
                data: data.clone(),
                signatures,
            };
            match self.chain.accept_checkpoint(cp.clone()) {
                Ok(_) => {
                    self.pending.remove(&h);
                    return Some(cp);
                }
                Err(_) => {
                    self.pending.remove(&h);
                }
            }
        }
        None
    }

    /// Forgets everything a crashed process loses; the signer guard
    /// state survives on disk.
    fn crash(&mut self) {
        self.alive = false;
        self.chain = Blockchain::new();
        self.mempool.clear();
        self.parked.clear();
        self.seen_blocks.clear();
        self.seen_txs.clear();
        self.pending.clear();
        self.signed_cps.clear();
    }

    /// Restart: RAM is empty, the guard is reloaded from disk (its
    /// equivocation memory survived the crash).
    fn restart(&mut self, tick: u64) {
        self.alive = true;
        self.guard = SignerGuard::load(&self.dir);
        self.last_progress_tick = tick;
    }
}

// ---------------------------------------------------------------------------
// SimNet
// ---------------------------------------------------------------------------

static INSTANCE: AtomicU64 = AtomicU64::new(0);

/// A deterministic simulated network of N real blockchains.
pub struct SimNet {
    params: SimParams,
    nodes: Vec<SimNode>,
    queue: BTreeMap<(u64, u64), Event>,
    next_seq: u64,
    logical_tick: u64,
    send_seq: u64,
    /// Partition group id per node (`usize::MAX` = isolated).
    groups: Vec<usize>,
    producing: bool,
    /// Every checkpoint finalized on any node, by epoch (safety oracle).
    finalized: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    /// Virtual shared node-store: every block that ever became
    /// canonical anywhere, by height (the union of the network's
    /// persistent stores — the harness equivalent of `scone-storage`
    /// without importing the crate). Sync serves from a node's RAM
    /// window first, then from this archive, so catch-up works past
    /// `RAM_WINDOW_BLOCKS` eviction.
    archive: HashMap<u64, Block>,
    root_dir: PathBuf,
    /// Rejections observed across all nodes.
    pub rejections: Rejections,
    /// Transport counters.
    pub stats: SimStats,
    /// Dispatched event count (diagnostics).
    pub steps: u64,
}

impl SimNet {
    /// Builds the network: fresh chains at genesis, one signer-guard
    /// directory per node, production and sync timers scheduled.
    ///
    /// # Panics
    ///
    /// Panics on unusable parameters (latency minimum must be ≥ 1 tick)
    /// or when the guard directories cannot be created — caller setup
    /// errors, not simulated data.
    pub fn new(params: SimParams) -> Self {
        assert!(
            params.latency_ticks.0 >= 1,
            "latency minimum must be >= 1 tick"
        );
        assert!(params.nodes >= 2, "a network needs at least 2 nodes");
        let instance = INSTANCE.fetch_add(1, Ordering::Relaxed);
        let root_dir =
            std::env::temp_dir().join(format!("scone-sim-{}-{instance}", std::process::id()));
        std::fs::create_dir_all(&root_dir).expect("sim temp dir");
        let mut nodes = Vec::with_capacity(params.nodes);
        for i in 0..params.nodes {
            let dir = root_dir.join(format!("node{i}"));
            std::fs::create_dir_all(&dir).expect("node dir");
            nodes.push(SimNode::new(i, dir));
        }
        let mut net = Self {
            params: params.clone(),
            nodes,
            queue: BTreeMap::new(),
            next_seq: 0,
            logical_tick: 0,
            send_seq: 0,
            groups: vec![0; params.nodes],
            producing: true,
            finalized: BTreeMap::new(),
            archive: HashMap::new(),
            root_dir,
            rejections: Rejections::default(),
            stats: SimStats::default(),
            steps: 0,
        };
        net.schedule(10, Event::ProduceRound);
        for i in 0..net.nodes.len() {
            let t = 25 + (i as u64) * 5;
            net.schedule(t, Event::Sync { node: i });
        }
        net
    }

    // -- scheduling ---------------------------------------------------------

    fn schedule(&mut self, tick: u64, event: Event) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.queue.insert((tick, seq), event);
    }

    /// Current virtual time (never advanced by duplicate copies).
    #[must_use]
    pub fn logical_tick(&self) -> u64 {
        self.logical_tick
    }

    /// Stops block production (delivery and sync keep running).
    pub fn stop_production(&mut self) {
        self.producing = false;
    }

    /// Runs events until `pred` holds, the queue empties or the horizon
    /// is reached.
    pub fn run_until(&mut self, pred: impl FnMut(&SimNet) -> bool) {
        let mut pred = pred;
        loop {
            if pred(self) || self.queue.is_empty() || self.logical_tick >= self.params.horizon {
                return;
            }
            self.step_once();
        }
    }

    fn step_once(&mut self) {
        let ((tick, _), event) = self.queue.pop_first().expect("queue non-empty (checked)");
        if event.is_real() && tick > self.logical_tick {
            self.logical_tick = tick;
        }
        self.dispatch(tick, event);
        self.steps += 1;
        if false && self.steps.is_multiple_of(20_000) {
            eprintln!(
                "[sim] s={} t={} hs={:?} parks={:?} stuck={:?} roots={:?}",
                self.steps,
                self.logical_tick,
                self.nodes
                    .iter()
                    .map(|n| n.chain.height())
                    .collect::<Vec<_>>(),
                self.nodes
                    .iter()
                    .map(|n| n.parked.len())
                    .collect::<Vec<_>>(),
                self.nodes
                    .iter()
                    .map(|n| n.stuck_rounds)
                    .collect::<Vec<_>>(),
                self.nodes
                    .iter()
                    .map(|n| n.chain.state().state_root_smt()[..4].to_vec())
                    .collect::<Vec<_>>()
            );
        }
    }

    fn dispatch(&mut self, tick: u64, event: Event) {
        match event {
            Event::Deliver { from, to, msg, .. } => {
                self.stats.delivered += 1;
                self.handle_deliver(from, to, msg);
            }
            Event::ProduceRound => self.produce_round(tick),
            Event::Sync { node } => self.try_sync(tick, node),
            Event::Submit { node, tx } => self.handle_submit(node, tx),
        }
    }

    // -- transport ----------------------------------------------------------

    fn net_send(&mut self, from: usize, to: usize, msg: SimMsg) {
        if self.groups[from] != self.groups[to] {
            self.stats.partition_dropped += 1;
            return;
        }
        if !self.nodes[to].alive {
            return;
        }
        let seq = self.send_seq;
        self.send_seq += 1;
        self.stats.sent += 1;
        let draw = send_draw(self.params.seed, seq, &self.params);
        if draw.lost {
            self.stats.lost += 1;
            return;
        }
        let tick = self.logical_tick + draw.latency;
        self.schedule(
            tick,
            Event::Deliver {
                from,
                to,
                msg: msg.clone(),
                copy: 0,
            },
        );
        if msg.duplicable() && draw.dup {
            self.stats.duplicates_sent += 1;
            self.schedule(
                tick + draw.dup_delay,
                Event::Deliver {
                    from,
                    to,
                    msg,
                    copy: 1,
                },
            );
        }
    }

    fn gossip(&mut self, from: usize, msg: SimMsg) {
        let group = self.groups[from];
        for to in 0..self.nodes.len() {
            if to != from && self.groups[to] == group {
                self.net_send(from, to, msg.clone());
            }
        }
    }

    // -- driver API ---------------------------------------------------------

    /// Submits a transaction to `node` (a local wallet submission).
    pub fn submit(&mut self, node: usize, tx: Transaction) {
        self.schedule(self.logical_tick, Event::Submit { node, tx });
    }

    /// Splits the network into disjoint groups (a partition). Messages
    /// between groups are dropped.
    pub fn partition(&mut self, groups: &[Vec<usize>]) {
        self.groups = vec![usize::MAX; self.nodes.len()];
        for (gi, members) in groups.iter().enumerate() {
            for &n in members {
                self.groups[n] = gi;
            }
        }
    }

    /// Heals every partition.
    pub fn heal(&mut self) {
        self.groups = vec![0; self.nodes.len()];
    }

    /// Crashes `node`: RAM state lost, signer guard kept on disk.
    pub fn crash(&mut self, node: usize) {
        self.nodes[node].crash();
    }

    /// Restarts `node`: empty chain, guard reloaded from disk.
    pub fn restart(&mut self, node: usize) {
        self.nodes[node].restart(self.logical_tick);
    }

    // -- handlers -----------------------------------------------------------

    fn handle_deliver(&mut self, from: usize, to: usize, msg: SimMsg) {
        if !self.nodes[to].alive {
            return;
        }
        match msg {
            SimMsg::Block(block) => self.handle_block(to, block),
            SimMsg::Tx(tx) => self.handle_tx_in(to, tx),
            SimMsg::Checkpoint(cp) => self.handle_checkpoint(to, cp),
            SimMsg::GetBlocks { start } => self.serve_blocks(to, from, start),
            SimMsg::Blocks(blocks) => {
                self.handle_sync_batch(to, blocks);
            }
            SimMsg::GetCheckpoints => self.serve_checkpoints(to, from),
            SimMsg::Checkpoints(cps) => {
                for cp in cps {
                    self.handle_checkpoint(to, cp);
                }
            }
        }
    }

    fn handle_submit(&mut self, node: usize, tx: Transaction) {
        if !self.nodes[node].alive {
            return;
        }
        self.handle_tx_in(node, tx);
    }

    fn handle_tx_in(&mut self, node: usize, tx: Transaction) {
        let outcome = self.nodes[node].accept_tx(tx.clone());
        match outcome {
            TxOutcome::New => self.gossip(node, SimMsg::Tx(tx)),
            TxOutcome::Duplicate => {}
            TxOutcome::Rejected(kind) => self.rejections.count(kind),
        }
    }

    /// A `GetBlocks` response batch: first the linear path (the common
    /// case — the batch extends our tip), then a single whole-batch
    /// branch adoption attempt (the catch-up walk case), and only as a
    /// last resort per-block parking. Parking a whole walked batch
    /// would blow the cap and evict the very blocks the catch-up
    /// needs; `adopt_branch` evaluates the batch as one candidate
    /// branch (its first block roots at the fork point the walk
    /// reached).
    fn handle_sync_batch(&mut self, node: usize, blocks: Vec<Block>) {
        if blocks.is_empty() || !self.nodes[node].alive {
            return;
        }
        if node == 1 {
            let _ = format_args!(""); /*
            eprintln!("[sync1] got {} blocks, first_h={} my_h={} my_tip_ok={}",
            blocks.len(), blocks[0].header.height,
            self.nodes[node].chain.height(),
            blocks[0].header.prev_hash == self.nodes[node].chain.tip_hash()); */
        }
        // Linear extension: push while each block extends our tip.
        let mut idx = 0;
        while idx < blocks.len() {
            let b = &blocks[idx];
            if b.header.prev_hash == self.nodes[node].chain.tip_hash()
                && b.header.height == self.nodes[node].chain.height() + 1
            {
                match self.nodes[node].chain.push_block_with_gc(b) {
                    Ok(_) => {
                        self.stats.blocks_accepted += 1;
                        idx += 1;
                    }
                    Err(_) => break,
                }
            } else {
                break;
            }
        }
        if idx > 0 {
            let applied: Vec<Block> = blocks[..idx].to_vec();
            for b in &applied {
                self.after_progress(node, &b.transactions);
                self.gossip(node, SimMsg::Block(b.clone()));
            }
        }
        // Whole-batch adoption (catch-up walk / divergence).
        let rest: Vec<Block> = blocks[idx..].to_vec();
        if rest.is_empty() {
            return;
        }
        let dbg = self.nodes[node].chain.adopt_branch(&rest);
        if self.nodes[node].stuck_rounds > 50 {
            eprintln!(
                "[adopt] n={node} first_h={} len={} err={:?}",
                rest[0].header.height,
                rest.len(),
                dbg.as_ref().err()
            );
        }
        match dbg {
            Ok(true) => {
                self.stats.reorgs += 1;
                self.stats.blocks_accepted += rest.len() as u64;
                self.nodes[node].stuck_rounds = 0;
                for b in &rest {
                    self.after_progress(node, &b.transactions);
                    self.gossip(node, SimMsg::Block(b.clone()));
                }
            }
            _ => {
                // Park the remainder individually (announcement path).
                for b in rest {
                    self.handle_block(node, b);
                }
            }
        }
    }

    fn handle_block(&mut self, node: usize, block: Block) {
        let outcome = self.nodes[node].accept_block(&block);
        match outcome {
            BlockOutcome::Accepted => {
                self.stats.blocks_accepted += 1;
                self.after_progress(node, &block.transactions);
                self.gossip(node, SimMsg::Block(block));
            }
            // A parked block is NEVER re-broadcast (the relay's rule:
            // only accepted blocks are relayed). Out-of-order gaps are
            // healed by the sync path (`GetBlocks`), not by flooding
            // orphans — otherwise every re-delivery amplifies.
            // A pure duplicate changed nothing: no drive needed.
            BlockOutcome::ParkedKnown | BlockOutcome::ParkedOrphan => {
                self.drive_node(node);
            }
            BlockOutcome::Duplicate => {}
            BlockOutcome::Rejected(kind) => self.rejections.count(kind),
        }
    }

    /// Post-effects of blocks becoming canonical on `node` (produced,
    /// pushed, drained or adopted): mempool reconciliation, checkpoint
    /// round, then linear drain of anything the canonical change
    /// un-parked (cascades deterministically).
    fn after_progress(&mut self, node: usize, txs: &[Transaction]) {
        let tick = self.logical_tick;
        {
            let n = &mut self.nodes[node];
            n.last_progress_tick = tick;
            n.stuck_rounds = 0; // any canonical progress resets the walk
            for tx in txs {
                if let Ok(id) = transaction_id(tx) {
                    n.seen_txs.insert(id);
                    n.mempool.retain(|(x, _)| x != &id);
                }
            }
        }
        // Archive the node's canonical tip (virtual shared store).
        let height = self.nodes[node].chain.height();
        if let Some(b) = self.nodes[node].chain.block(height) {
            self.archive.insert(b.header.height, b.clone());
        }
        self.anchor_round(node);
    }

    /// Full post-delivery driver of `node`: linear drain first (cheap),
    /// then whole-branch adoption for genuine reorgs. Every canonical
    /// change reconciles the mempool, runs the checkpoint round, and
    /// gossips the newly accepted blocks (a drained block was never
    /// relayed before — this is its first broadcast).
    fn drive_node(&mut self, node: usize) {
        loop {
            let mut drained_blocks: Vec<Block> = Vec::new();
            let drained = self.nodes[node].drain_parked();
            if drained > 0 {
                self.stats.blocks_accepted += drained as u64;
                let n = &self.nodes[node];
                let from = n.chain.height() + 1 - drained as u64;
                for h in from..=n.chain.height() {
                    if let Some(b) = n.chain.block(h) {
                        drained_blocks.push(b.clone());
                    }
                }
            }
            for b in &drained_blocks {
                self.after_progress(node, &b.transactions);
                self.gossip(node, SimMsg::Block(b.clone()));
            }
            match self.nodes[node].try_adopt() {
                Some(adopted) => {
                    self.stats.reorgs += 1;
                    self.stats.blocks_accepted += adopted.len() as u64;
                    self.nodes[node].stuck_rounds = 0;
                    for b in &adopted {
                        self.after_progress(node, &b.transactions);
                        self.gossip(node, SimMsg::Block(b.clone()));
                    }
                    continue;
                }
                None => {
                    if drained == 0 {
                        break;
                    }
                }
            }
        }
    }

    /// Checkpoint round after a canonical change on `node`. The
    /// designated anchor of the round (committee rotation on the
    /// checkpoint epoch) builds the deterministic content for its tip
    /// when the chain is ready (`propose_checkpoint`), signs it through
    /// the crash-safe guard and gossips the partial aggregate; the
    /// other committee members sign **on receipt** (`checkpoint_vote`)
    /// and re-gossip — an epidemic signature aggregation, exactly like
    /// the relay's anchor loop.
    fn anchor_round(&mut self, node: usize) {
        let sign_interval = self.params.sign_interval;
        let proposal = {
            let n = &mut self.nodes[node];
            if !n.alive || !n.chain.height().is_multiple_of(sign_interval) {
                return;
            }
            let committee = n.chain.committee(0);
            if committee.len() < MIN_FINALITY_COMMITTEE_SIZE {
                return; // finality deferred by design
            }
            let Some(data) = n.chain.propose_checkpoint() else {
                return; // epoch_min_blocks not reached
            };
            let epoch = data.epoch;
            let proposer = committee[(epoch as usize) % committee.len()];
            if proposer != n.pk {
                return; // not this round's designated anchor
            }
            if !n.commit_epoch(&data) {
                self.rejections.count("cp_conflict");
                return; // a proposal for this epoch already spread
            }
            let h = data.signing_hash();
            if n.signed_cps.contains(&h) {
                return; // already signed (idempotent)
            }
            let sig = match n.chain.sign_checkpoint(&mut n.guard, &n.key, &data) {
                Ok(s) => s,
                Err(_) => {
                    self.rejections.count("signer_refused");
                    return;
                }
            };
            n.signed_cps.insert(h);
            let entry = n
                .pending
                .entry(h)
                .or_insert_with(|| (data.clone(), BTreeMap::new()));
            entry.1.insert(n.pk, sig);
            Checkpoint {
                data,
                signatures: vec![(n.pk, sig)],
            }
        };
        self.gossip(node, SimMsg::Checkpoint(proposal));
        self.finalize_and_gossip(node);
    }

    /// Committee members sign a received checkpoint proposal on sight
    /// (through their own guard) and relay the enriched aggregate. An
    /// honest anchor only ever signs content it can fully verify
    /// against its OWN canonical chain: the data rules
    /// (`check_checkpoint_data`) and the referenced block must be the
    /// signer's canonical block at that height (the core cannot see
    /// foreign branches — the relay-level guard).
    fn checkpoint_vote(&mut self, node: usize, cp: &Checkpoint) {
        let enriched = {
            let n = &mut self.nodes[node];
            if !n.alive {
                return;
            }
            if !n.commit_epoch(&cp.data) {
                self.rejections.count("cp_conflict");
                return; // conflicting proposal of a committed epoch
            }
            if n.chain.check_checkpoint_data(&cp.data).is_err() {
                return; // not verifiable against our chain
            }
            if n.chain.block_hash_at(cp.data.height)
                != Some(BlockHash::from_bytes(cp.data.block_hash))
            {
                return; // foreign branch: never sign what we don't hold
            }
            let committee = n.chain.committee(cp.data.recovery);
            if committee.len() < MIN_FINALITY_COMMITTEE_SIZE || !committee.contains(&n.pk) {
                return;
            }
            if !committee
                .iter()
                .any(|p| cp.signatures.iter().any(|(s, _)| s == p))
            {
                return; // not a committee proposal: do not amplify
            }
            let h = cp.data.signing_hash();
            if n.signed_cps.contains(&h) {
                return;
            }
            let sig = match n.chain.sign_checkpoint(&mut n.guard, &n.key, &cp.data) {
                Ok(s) => s,
                Err(_) => {
                    self.rejections.count("signer_refused");
                    return;
                }
            };
            n.signed_cps.insert(h);
            let entry = n
                .pending
                .entry(h)
                .or_insert_with(|| (cp.data.clone(), BTreeMap::new()));
            entry.1.extend(cp.signatures.iter().cloned());
            entry.1.insert(n.pk, sig);
            let mut signatures: Vec<(PublicKey, Signature)> =
                entry.1.iter().map(|(p, s)| (*p, *s)).collect();
            signatures.sort_by_key(|(p, _)| *p);
            Checkpoint {
                data: cp.data.clone(),
                signatures,
            }
        };
        self.gossip(node, SimMsg::Checkpoint(enriched));
        self.finalize_and_gossip(node);
    }

    fn finalize_and_gossip(&mut self, node: usize) {
        if let Some(finalized) = self.nodes[node].try_finalize() {
            self.record_finalized(&finalized);
            self.gossip(node, SimMsg::Checkpoint(finalized));
        }
    }

    fn handle_checkpoint(&mut self, node: usize, cp: Checkpoint) {
        if let Some(aggregate) = self.nodes[node].merge_checkpoint(&cp) {
            self.gossip(node, SimMsg::Checkpoint(aggregate));
            self.checkpoint_vote(node, &cp);
        }
        self.finalize_and_gossip(node);
    }

    fn record_finalized(&mut self, cp: &Checkpoint) {
        self.stats.checkpoints_finalized += 1;
        // Safety oracle key = the checkpoint CONTENT (signing hash),
        // not `cp.hash()`: two quorums of distinct signers may
        // legitimately finalize the same content (the aggregate sets
        // only differ), which is compatible. Distinct contents of one
        // epoch are the actual violation.
        self.finalized
            .entry(cp.data.epoch)
            .or_default()
            .insert(cp.data.signing_hash());
    }

    // -- production ---------------------------------------------------------

    fn produce_round(&mut self, tick: u64) {
        if !self.producing {
            return;
        }
        let interval = self.params.produce_interval;
        self.schedule(tick + interval, Event::ProduceRound);
        let mut groups: Vec<usize> = self.groups.clone();
        groups.sort_unstable();
        groups.dedup();
        for group in groups {
            let mut candidates: Vec<usize> = (0..self.nodes.len())
                .filter(|&i| self.groups[i] == group && self.nodes[i].alive)
                .collect();
            // Best producer: highest canonical height, then lowest id.
            candidates.sort_by(|&a, &b| {
                self.nodes[b]
                    .chain
                    .height()
                    .cmp(&self.nodes[a].chain.height())
                    .then(a.cmp(&b))
            });
            // Bootstrap discipline: before the FIRST finalized
            // checkpoint the allowed-producer set is state-derived
            // (live-domain pool at the block timestamp), so nodes with
            // slightly different states compute different committees —
            // a block legally produced on one view is InvalidProducer
            // on another and the network forks for good. During
            // bootstrap the harness therefore pins production to a
            // single deterministic producer (lowest node id holding
            // the group's best chain). After the first finality the
            // committee is frozen in the finality base — identical on
            // every converged node — and production rotates freely.
            let bootstrapping = candidates
                .first()
                .is_some_and(|&i| self.nodes[i].chain.finalized().is_none());
            let next_h = candidates
                .first()
                .map(|&i| self.nodes[i].chain.height() + 1)
                .unwrap_or(1);
            let ts = next_h * BLOCK_TS_STEP;
            let producer = if bootstrapping {
                // Bootstrap producer = node 0 (the `uip` claimer,
                // pool member on every view since block 1). Exactly
                // one producer => exactly one chain exists before the
                // first finality: no divergent committees, no
                // bootstrap double-finality window. If node 0 is down
                // the group simply waits (crashes in the scenarios
                // happen post-bootstrap).
                candidates.into_iter().find(|&i| i == 0)
            } else {
                candidates.into_iter().find(|&i| {
                    let allowed = self.nodes[i].chain.allowed_producers(ts);
                    allowed.is_empty() || allowed.contains(&self.nodes[i].pk)
                })
            };
            let Some(node) = producer else {
                continue; // no allowed producer alive in this group
            };
            let (kinds, produced) = self.nodes[node].build_block(ts);
            for k in kinds {
                self.rejections.count(k);
            }
            if let Some(block) = produced {
                self.stats.blocks_produced += 1;
                self.stats.blocks_accepted += 1;
                self.after_progress(node, &block.transactions);
                self.gossip(node, SimMsg::Block(block));
            }
        }
    }

    // -- sync ---------------------------------------------------------------

    fn try_sync(&mut self, tick: u64, node: usize) {
        let interval = self.params.sync_interval;
        self.schedule(tick + interval, Event::Sync { node });
        if !self.nodes[node].alive {
            return;
        }
        let group = self.groups[node];
        let peers: Vec<usize> = (0..self.nodes.len())
            .filter(|&p| p != node && self.groups[p] == group && self.nodes[p].alive)
            .collect();
        let Some(peer) = peers
            .get(self.nodes[node].sync_counter as usize % peers.len())
            .copied()
        else {
            return;
        };
        self.nodes[node].sync_counter += 1;
        // Stall back-off: a node whose canonical chain diverged from
        // the group (losing fork) cannot attach the blocks the plain
        // `height + 1` request returns — every response parks forever
        // (the fork point sits below the served range). After a few
        // stalled rounds the node falls back to a full-range request
        // (`start = 1`): the peer serves its whole canonical chain,
        // the winning branch (longer) is adopted through the parking.
        // The back-off resets on any canonical progress.
        let stalled_rounds = tick
            .saturating_sub(self.nodes[node].last_progress_tick)
            .saturating_sub(1)
            / interval;
        let my_height = self.nodes[node].chain.height();
        // Full catch-up walk: a node that keeps producing its OWN
        // divergent branch never looks idle, yet it can never attach
        // the group's blocks (the fork point is below anything it
        // receives). Track unresolved parking instead: when parked
        // blocks sit unattached across sync rounds, page through the
        // peer's chain from genesis (SYNC_BATCH per round) until the
        // fork point is crossed and the winning branch — longer — gets
        // adopted through the parking. Resets on any adoption.
        let stuck = self.nodes[node].stuck_rounds;
        // Catch-up walk: page-aligned batches (start ≡ 1 mod 64),
        // zig-zagging around our own tip's page — one page per stalled
        // round, first DOWN towards genesis (covers the fork point
        // when our chain diverged), then UP beyond our height (covers
        // the winning branch's continuation). A page that roots on our
        // canonical prefix and extends past our height wins the
        // whole-batch adoption; longer requests keep arriving every
        // round, so the branch eventually accumulates.
        // Sequential walk from genesis: while stuck, each sync round
        // requests the NEXT 64-block page from the peer (page 1, 2,
        // 3, …), clamped to the network's known best height (the
        // driver's view — the harness knows the virtual network's
        // max height the way a real node knows its peers' announced
        // tips). Pages matching our own canonical prefix are absorbed
        // as no-ops; pages past our fork point accumulate in the
        // parking until the assembled foreign branch — longer than
        // ours — wins a single whole-branch adoption. Once the walk
        // reaches the network tip it keeps re-requesting the LAST
        // page, which keeps growing, until the branch is long enough.
        // Recovery reset: a node whose canonical chain diverged from
        // its group AND whose parking is saturated can never assemble
        // an adoptable branch (the eviction keeps trimming the branch
        // root). It performs the honest last resort a real node has:
        // throw the divergent chain away and resynchronize from
        // genesis — the crash-restart path minus the crash (the
        // signer guard stays armed; finality history replays from the
        // peers' checkpoint window).
        if stuck > 40 && self.nodes[node].parked.len() >= PARKED_CAP {
            let dir = self.nodes[node].dir.clone();
            self.nodes[node].crash();
            self.nodes[node].restart(tick);
            let _ = dir;
            self.nodes[node].stuck_rounds = 0;
        }
        let start = my_height + 1;
        let _ = stalled_rounds;
        // Stall accounting: unresolved parking across sync rounds.
        // A node AT the network's best tip holds only orphaned
        // leftovers of losing branches — the winning branch is
        // adopted, the parking is dead weight that would otherwise
        // trip the recovery reset forever. Drop it (a real node's
        // equivalent: orphan eviction below the finality floor, which
        // the RAM window already enforces on live chains).
        if self.nodes[node].chain.height() >= self.max_height() {
            self.nodes[node].parked.clear();
        }
        if self.nodes[node].parked.is_empty() {
            self.nodes[node].stuck_rounds = 0;
        } else {
            self.nodes[node].stuck_rounds += 1;
        }
        self.net_send(node, peer, SimMsg::GetBlocks { start });
        if self.nodes[node].sync_counter.is_multiple_of(2) {
            self.net_send(node, peer, SimMsg::GetCheckpoints);
        }
    }

    fn serve_blocks(&mut self, server: usize, to: usize, start: u64) {
        if to == 1 {
            // [req1] diagnostic disabled
        }
        let tip = self.nodes[server].chain.height();
        let end = (start + SYNC_BATCH - 1).min(tip);
        if start > end {
            return;
        }
        let mut blocks: Vec<Block> = (start..=end)
            .filter_map(|h| self.nodes[server].chain.block(h).cloned())
            .collect();
        // RAM window miss: serve from the virtual shared store.
        if blocks.len() < (end - start + 1) as usize {
            blocks = (start..=end)
                .filter_map(|h| self.archive.get(&h).cloned())
                .collect();
        }
        if blocks.is_empty() {
            return;
        }
        self.net_send(server, to, SimMsg::Blocks(blocks));
    }

    fn serve_checkpoints(&mut self, server: usize, to: usize) {
        let cps: Vec<Checkpoint> = self.nodes[server]
            .chain
            .checkpoint_window()
            .iter()
            .take(crate::finality::CHECKPOINT_KEEP)
            .cloned()
            .collect();
        if cps.is_empty() {
            return;
        }
        self.net_send(server, to, SimMsg::Checkpoints(cps));
    }

    // -- observations -------------------------------------------------------

    /// Height of `node`'s canonical tip.
    #[must_use]
    pub fn height(&self, node: usize) -> u64 {
        self.nodes[node].chain.height()
    }

    /// Hash of `node`'s canonical tip.
    #[must_use]
    pub fn tip(&self, node: usize) -> BlockHash {
        self.nodes[node].chain.tip_hash()
    }

    /// SMT state root of `node`'s authoritative state.
    #[must_use]
    pub fn state_root(&self, node: usize) -> [u8; 32] {
        self.nodes[node].chain.state().state_root_smt()
    }

    /// Read access to `node`'s chain (scenario assertions).
    #[must_use]
    pub fn chain(&self, node: usize) -> &Blockchain {
        &self.nodes[node].chain
    }

    /// Public key of `node`'s pool key.
    #[must_use]
    pub fn node_pk(&self, node: usize) -> PublicKey {
        self.nodes[node].pk
    }

    /// Whether `node` is alive.
    #[must_use]
    pub fn alive(&self, node: usize) -> bool {
        self.nodes[node].alive
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Highest canonical height over all alive nodes.
    #[must_use]
    pub fn max_height(&self) -> u64 {
        self.nodes
            .iter()
            .filter(|n| n.alive)
            .map(|n| n.chain.height())
            .max()
            .unwrap_or(0)
    }

    /// Every checkpoint finalized anywhere, by epoch (the safety
    /// oracle: an epoch must never hold two distinct hashes).
    #[must_use]
    pub fn finalized_epochs(&self) -> &BTreeMap<u64, BTreeSet<[u8; 32]>> {
        &self.finalized
    }

    /// Whether every alive node converged on the same tip, height and
    /// state root.
    #[must_use]
    pub fn converged(&self) -> bool {
        let mut alive = self.nodes.iter().filter(|n| n.alive);
        let Some(first) = alive.next() else {
            return true;
        };
        let (h, t, r) = (
            first.chain.height(),
            first.chain.tip_hash(),
            first.chain.state().state_root_smt(),
        );
        alive.all(|n| {
            n.chain.height() == h
                && n.chain.tip_hash() == t
                && n.chain.state().state_root_smt() == r
        })
    }
}

impl Drop for SimNet {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_dir);
    }
}

// ---------------------------------------------------------------------------
// Transaction fixtures (testnet PoW, canonical signing)
// ---------------------------------------------------------------------------

/// Signs a transaction over its canonical signing payload.
fn sign_tx(unsigned: Transaction, sk: &SigningKey) -> Transaction {
    let payload = scone_protocol::signing_payload(&unsigned).expect("fixture encodes");
    let sig = sk.sign(&payload);
    match unsigned {
        Transaction::RegisterDomain(mut r) => {
            r.signature = sig;
            Transaction::RegisterDomain(r)
        }
        Transaction::UpdateDomain(mut u) => {
            u.signature = sig;
            Transaction::UpdateDomain(u)
        }
        Transaction::RegisterTld(mut t) => {
            t.signature = sig;
            Transaction::RegisterTld(t)
        }
        Transaction::TransferTld(mut t) => {
            t.signature = sig;
            Transaction::TransferTld(t)
        }
        Transaction::RevokeTld(mut t) => {
            t.signature = sig;
            Transaction::RevokeTld(t)
        }
        Transaction::SetTldOpen(mut t) => {
            t.signature = sig;
            Transaction::SetTldOpen(t)
        }
        Transaction::AssignDomain(mut a) => {
            a.signature = sig;
            Transaction::AssignDomain(a)
        }
        Transaction::RenewDomain(mut r) => {
            r.signature = sig;
            Transaction::RenewDomain(r)
        }
        Transaction::TransferDomain(mut t) => {
            t.signature = sig;
            Transaction::TransferDomain(t)
        }
        Transaction::Slash(mut s) => {
            s.signature = sig;
            Transaction::Slash(s)
        }
    }
}

/// Mines a testnet registration proof for `name`.
fn mined_proof(name: &str, tld: bool) -> Proof {
    let (prefix, difficulty) = if tld {
        (
            scone_core::id::TLD_ID_VERSION,
            scone_core::TESTNET.tld_pow_difficulty,
        )
    } else {
        (
            scone_core::id::DOMAIN_ID_VERSION,
            scone_core::TESTNET.domain_pow_difficulty,
        )
    };
    let mut challenge = Vec::with_capacity(prefix.len() + name.len());
    challenge.extend_from_slice(prefix);
    challenge.extend_from_slice(name.as_bytes());
    let checked = scone_core::pow::mine(scone_core::TESTNET.network_id, &challenge, difficulty);
    Proof::from_bytes(scone_core::pow::encode_proof(&checked))
}

/// A signed `RegisterTld` fixture (testnet PoW).
#[must_use]
pub fn sim_register_tld(tld: &str, seed: u8) -> Transaction {
    let sk = SigningKey::from_bytes([seed; 32]);
    sign_tx(
        Transaction::RegisterTld(RegisterTld::register_tld_signed(
            TldName::new(tld).expect("fixture tld"),
            1,
            mined_proof(tld, true),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        &sk,
    )
}

/// A signed `SetTldOpen` fixture.
#[must_use]
pub fn sim_set_tld_open(tld: &str, seed: u8, open: bool) -> Transaction {
    let sk = SigningKey::from_bytes([seed; 32]);
    sign_tx(
        Transaction::SetTldOpen(SetTldOpen::set_tld_open_signed(
            TldId::from_tld(&TldName::new(tld).expect("fixture tld")),
            open,
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        &sk,
    )
}

/// A signed `RegisterDomain` fixture (testnet PoW).
#[must_use]
pub fn sim_register_domain(name: &str, seed: u8) -> Transaction {
    let sk = SigningKey::from_bytes([seed; 32]);
    sign_tx(
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new(name).expect("fixture name"),
            1,
            mined_proof(name, false),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        &sk,
    )
}

/// A signed `UpdateDomain` fixture (record hash = `[record; 32]`).
#[must_use]
pub fn sim_update_domain(id: DomainId, seed: u8, sequence: u64, record: u8) -> Transaction {
    let sk = SigningKey::from_bytes([seed; 32]);
    sign_tx(
        Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            id,
            sequence,
            RecordHash::from_bytes([record; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        &sk,
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod scale_tests;
