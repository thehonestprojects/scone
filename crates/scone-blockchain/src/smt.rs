//! Compact sparse Merkle tree (SMT) — incremental state commitment.
//!
//! Fixed-depth trie where only **branch points** are stored: a key update
//! costs O(depth) hashes instead of a full O(N log N) recomputation.
//!
//! # Design (vs alternatives)
//!
//! - **Compact radix trie over 40 key bits** (top bits of a `DomainId` /
//!   public key, uniform under blake3/ed25519): only branch points are
//!   stored (~N-1 nodes for N leaves), never single-child chains — their
//!   hash is recomputed by folding the leaf (O(chain length), amortized
//!   O(40) per update: the chains along a root→leaf path partition its 40
//!   levels).
//! - Recomputed sorted Merkle: O(N log N) per checkpoint — rejected.
//! - Persistent / hashed B-tree Merkle: complex deterministic rebalancing
//!   for the same commitment — rejected.
//! - 40-bit prefix collisions (~45 expected at 10M keys): handled by
//!   bucket leaves (Merkle over the sorted entries sharing the prefix) —
//!   deterministic, marginal cost.
//!
//! # Encoding (bit-exact port of the `.bak` implementation — roots unchanged)
//!
//! - node: `blake3("SCONE-SMT-NODE" || left || right)` (tag split as a
//!   `hash256` part);
//! - empty leaf: `blake3("SCONE-SMT-LEAF-EMPTY")`;
//! - bucket leaf: Merkle tree over the sorted entries (1 entry = itself);
//!   NOTE: bucket-internal nodes are `blake3(left || right)` **without** a
//!   tag, exactly as in the origin implementation (`merkle_root_hashes`) —
//!   keeping them untagged is required for bit-identical roots;
//! - empty subtree at depth d: derived default chain
//!   (`default[i] = node(default[i-1], default[i-1])`).
//!
//! # Structure
//!
//! - `nodes: HashMap<packed_path, BranchNode>`: one node per branch point.
//!   `packed_path = (depth << 40) | prefix` — canonical node id, a function
//!   of the key SET only.
//! - Each child (`left`/`right`, packed u64) is: `EMPTY` (empty subtree),
//!   `CHAIN(k)` (implicit chain down to leaf k — no node below) or
//!   `NODE(d', p')` (reference to the nearest branch point UNDER that
//!   slot; the intermediate chain is implicit).
//! - `root_child`: EMPTY / CHAIN / NODE — root navigation.
//! - `root_hash`: cache maintained by every `recompute` (O(1) `root()`).
//!
//! # Guarantees
//!
//! - identical root for any (key → leaf) set regardless of
//!   insertion/removal order (tested, + differential fuzz against the
//!   original flat-arena implementation);
//! - the physical shape (which slots, which ids) depends ONLY on the key
//!   set;
//! - an entry leaf MUST include something distinguishing the entries of a
//!   same bucket (id/key): two identical entries in a bucket would commit
//!   the same value only once (never the case here: state leaves include
//!   the DomainId, index leaves the public key).
//!
//! This layer hashes application content, hence it lives in
//! `scone-blockchain` (not `scone-core`). Pure in-memory structure: no
//! serialization here — persistence (redb) uses the public accessors
//! (`iter_branch_nodes`, `iter_leaf_keys`, `root_state`, `restore_*`,
//! `take_dirty`).

use std::collections::HashMap;
use std::sync::OnceLock;

/// Domain-separation tag for internal node hashes.
pub const SMT_NODE_TAG: &[u8] = b"SCONE-SMT-NODE";
/// Domain-separation tag hashed to build the empty leaf.
pub const SMT_EMPTY_LEAF_TAG: &[u8] = b"SCONE-SMT-LEAF-EMPTY";

const MAX_DEPTH: u8 = 40;
const D: u64 = MAX_DEPTH as u64;

// ——— Compact encoding of children and paths ———

/// Empty child slot (default subtree).
const EMPTY: u64 = 0;
/// Tag bit "implicit chain down to leaf k" (k in the low 40 bits).
const CHAIN_BIT: u64 = 1 << 63;
/// Tag bit "branch point at packed (depth, prefix)".
const NODE_BIT: u64 = 1 << 62;
const TAG_MASK: u64 = CHAIN_BIT | NODE_BIT;

#[inline]
fn chain(key: u64) -> u64 {
    debug_assert!(key < 1 << 40);
    CHAIN_BIT | key
}
#[inline]
fn is_chain(c: u64) -> bool {
    c & CHAIN_BIT != 0
}
#[inline]
fn chain_key(c: u64) -> u64 {
    c & !TAG_MASK
}
#[inline]
fn node_ref(packed: u64) -> u64 {
    NODE_BIT | packed
}
#[inline]
fn is_node(c: u64) -> bool {
    c & NODE_BIT != 0
}
#[inline]
fn node_packed(c: u64) -> u64 {
    c & !TAG_MASK
}

/// Packs (depth, prefix) into a node key: bits 40.. = depth, bits 0..40 =
/// prefix (high bits of the key).
#[inline]
fn pack(depth: u64, path: u64) -> u64 {
    debug_assert!(depth <= D && path < 1 << depth.max(1));
    (depth << 40) | path
}
#[inline]
fn unpack(p: u64) -> (u64, u64) {
    (p >> 40, p & ((1 << 40) - 1))
}

/// First bit (0-based depth from the root) where two 40-bit keys/prefixes
/// diverge. `x != 0` required.
#[inline]
fn divergence_depth(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    debug_assert!(x != 0 && x < 1 << 40);
    D - 1 - (63 - x.leading_zeros() as u64)
}

/// Branch node: subtree hash + the two child slots. 48 copyable bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchNode {
    pub hash: [u8; 32],
    pub left: u64,
    pub right: u64,
}

/// Persisted leaf of a key: the unique hash, or the sorted collision
/// bucket when several entries share the 40-bit prefix.
pub type LeafEntry = ([u8; 32], Option<Vec<[u8; 32]>>);

/// Location of a child slot: the root, or child `bit` of node `parent`.
#[derive(Clone, Copy, Debug)]
enum SlotRef {
    Root,
    Child { parent: u64, bit: u64 },
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    scone_crypto::hash256(&[SMT_NODE_TAG, left, right])
}

fn empty_leaf() -> [u8; 32] {
    scone_crypto::hash256(&[SMT_EMPTY_LEAF_TAG])
}

/// Merkle root over already-hashed bucket leaves — bit-exact port of the
/// origin `merkle_root_hashes`: 0 leaves → `[0; 32]` (reserved value,
/// never a leaf), 1 leaf → the leaf itself, odd level → last hash
/// duplicated, node = untagged `blake3(left || right)`.
fn bucket_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => return [0; 32],
        1 => return leaves[0],
        _ => {}
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if !level.len().is_multiple_of(2) {
            level.push(*level.last().expect("non-empty"));
        }
        level = level
            .chunks(2)
            .map(|p| scone_crypto::hash256(&[&p[0], &p[1]]))
            .collect();
    }
    level[0]
}

/// Default chain: `defaults[i]` = hash of the empty subtree covering i
/// levels above the leaves (defaults[0] = empty leaf). Immutable: computed
/// once for all.
fn defaults() -> &'static [[u8; 32]; 41] {
    static DEFS: OnceLock<[[u8; 32]; 41]> = OnceLock::new();
    DEFS.get_or_init(|| {
        let mut d = [empty_leaf(); 41];
        for i in 1..=MAX_DEPTH as usize {
            d[i] = node_hash(&d[i - 1], &d[i - 1]);
        }
        d
    })
}

/// Sparse Merkle tree of depth [`MAX_DEPTH`], key = u64 (high bits of the
/// state key; bits beyond 40 are ignored).
///
/// # Physical shape vs commitment
///
/// The physical layout depends on the key SET only (canonical branch
/// points) — never on the operation order: `root()` and every hash depend
/// ONLY on the (key → leaf) mapping.
#[derive(Clone, Default)]
pub struct Smt {
    /// Single leaf per key (overwhelming case: ~45 collisions expected at
    /// 10M uniform keys).
    leaves: HashMap<u64, [u8; 32]>,
    /// 40-bit prefix collision buckets (sorted, deduplicated) — rare.
    buckets: HashMap<u64, Vec<[u8; 32]>>,
    /// Branch points only (implicit chains): ~N-1 entries.
    nodes: HashMap<u64, BranchNode>,
    /// Root slot: EMPTY | CHAIN(k) | NODE(packed).
    root_child: u64,
    /// Root cache (None: empty tree → max-depth default).
    root_hash: Option<[u8; 32]>,
    /// Invalidation tracking for incremental persistence (redb): node
    /// paths touched since the last `take_dirty`.
    dirty_nodes: Vec<u64>,
    /// Leaf keys touched since the last `take_dirty`.
    dirty_leaves: Vec<u64>,
}

impl Smt {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Leaf hash of a key (sorted bucket on collision; single leaf =
    /// itself; absent = empty leaf).
    fn bucket_root(&self, key: u64) -> [u8; 32] {
        if let Some(v) = self.buckets.get(&key) {
            return bucket_merkle_root(v);
        }
        match self.leaves.get(&key) {
            None => empty_leaf(),
            Some(h) => *h,
        }
    }

    /// Value of the single-leaf subtree of key k rooted at `from_depth`:
    /// the implicit chain, folded from the leaf (no stored node).
    fn fold(&self, k: u64, from_depth: u64) -> [u8; 32] {
        let mut v = self.bucket_root(k);
        for d in (from_depth..D).rev() {
            let def = defaults()[(D - 1 - d) as usize];
            let bit = (k >> (D - 1 - d)) & 1;
            v = if bit == 0 {
                node_hash(&v, &def)
            } else {
                node_hash(&def, &v)
            };
        }
        v
    }

    /// Value of the full subtree at the ROOT slot (the root slot is not
    /// the child of a depth-0 node: a chain there folds from depth 0, and
    /// a NODE folds from 0 as well).
    fn root_value(&self) -> [u8; 32] {
        let repr = self.root_child;
        if repr == EMPTY {
            defaults()[MAX_DEPTH as usize]
        } else if is_chain(repr) {
            self.fold(chain_key(repr), 0)
        } else {
            let packed = node_packed(repr);
            let (d, p) = unpack(packed);
            let mut v = self.nodes[&packed].hash;
            for dd in (0..d).rev() {
                let bit = (p >> (d - 1 - dd)) & 1;
                let def = defaults()[(D - 1 - dd) as usize];
                v = if bit == 0 {
                    node_hash(&v, &def)
                } else {
                    node_hash(&def, &v)
                };
            }
            v
        }
    }

    /// Value of the subtree of child slot `repr` (child of a node at depth
    /// `parent_depth`). A NODE slot may reference a node deeper than
    /// `parent_depth+1`: the intermediate implicit chain is folded (a
    /// subtree hash depends on the attach depth).
    fn child_value(&self, repr: u64, parent_depth: u64) -> [u8; 32] {
        if repr == EMPTY {
            defaults()[(D - 1 - parent_depth) as usize]
        } else if is_chain(repr) {
            self.fold(chain_key(repr), parent_depth + 1)
        } else {
            let packed = node_packed(repr);
            let (d, p) = unpack(packed);
            let mut v = self.nodes[&packed].hash;
            for dd in (parent_depth + 1..d).rev() {
                let bit = (p >> (d - 1 - dd)) & 1;
                let def = defaults()[(D - 1 - dd) as usize];
                v = if bit == 0 {
                    node_hash(&v, &def)
                } else {
                    node_hash(&def, &v)
                };
            }
            v
        }
    }

    /// Descends along the path of `key` to the terminal slot: the slot
    /// whose content is EMPTY, CHAIN(k), or a NODE reference that does not
    /// cover `key` (divergence above the referenced node).
    fn locate(&self, key: u64) -> (SlotRef, u64) {
        let (stack, slot, repr) = self.locate_full(key);
        let _ = stack;
        (slot, repr)
    }

    /// Full variant: ALSO returns the stack of ancestors along the path
    /// (packed node, bit followed), top (root) to bottom (terminal).
    /// `stack.last()` is the parent of the terminal slot.
    fn locate_full(&self, key: u64) -> (Vec<(u64, u64)>, SlotRef, u64) {
        let mut stack = Vec::new();
        let mut slot = SlotRef::Root;
        let mut repr = self.root_child;
        while is_node(repr) {
            let packed = node_packed(repr);
            let (d, p) = unpack(packed);
            if (key >> (D - d)) == p {
                let bit = (key >> (D - 1 - d)) & 1;
                stack.push((packed, bit));
                slot = SlotRef::Child {
                    parent: packed,
                    bit,
                };
                repr = if bit == 0 {
                    self.nodes[&packed].left
                } else {
                    self.nodes[&packed].right
                };
            } else {
                break;
            }
        }
        (stack, slot, repr)
    }

    fn write_slot(&mut self, slot: SlotRef, val: u64) {
        match slot {
            SlotRef::Root => self.root_child = val,
            SlotRef::Child { parent, bit } => {
                let n = self.nodes.get_mut(&parent).expect("parent alive");
                if bit == 0 {
                    n.left = val;
                } else {
                    n.right = val;
                }
            }
        }
    }

    /// Rewrites the hashes along the path of `key` (leaf → root): every
    /// branch point encountered is updated, implicit chains are folded on
    /// the fly. Total cost O(40) hashes (the chains along a path partition
    /// its levels).
    fn recompute(&mut self, key: u64) {
        self.recompute_from(key, self.bucket_root(key), D);
    }

    /// Variant: starts with value `v0` of the subtree at depth `v0_depth`
    /// (used after collapse: v0 = promoted subtree).
    fn recompute_from(&mut self, key: u64, v0: [u8; 32], v0_depth: u64) {
        let mut v = v0;
        for d in (0..v0_depth).rev() {
            let bit = (key >> (D - 1 - d)) & 1;
            let packed = pack(d, key >> (D - d));
            let sib = self
                .nodes
                .get(&packed)
                .map(|n| if bit == 0 { n.right } else { n.left });
            match sib {
                Some(sib) => {
                    let sib_val = self.child_value(sib, d);
                    v = if bit == 0 {
                        node_hash(&v, &sib_val)
                    } else {
                        node_hash(&sib_val, &v)
                    };
                    let n = self.nodes.get_mut(&packed).expect("present");
                    n.hash = v;
                    self.dirty_nodes.push(packed);
                }
                None => {
                    let def = defaults()[(D - 1 - d) as usize];
                    v = if bit == 0 {
                        node_hash(&v, &def)
                    } else {
                        node_hash(&def, &v)
                    };
                }
            }
        }
        self.root_hash = Some(v);
    }

    /// Adds an entry leaf at `key` (idempotent); a second distinct leaf
    /// switches the key to a sorted collision bucket.
    pub fn insert(&mut self, key: u64, leaf: [u8; 32]) {
        let touched = if let Some(v) = self.buckets.get_mut(&key) {
            match v.binary_search(&leaf) {
                Ok(_) => false,
                Err(pos) => {
                    v.insert(pos, leaf);
                    true
                }
            }
        } else {
            match self.leaves.get(&key) {
                Some(h) if *h == leaf => false,
                Some(h) => {
                    let mut v = vec![*h, leaf];
                    v.sort_unstable();
                    self.buckets.insert(key, v);
                    self.leaves.remove(&key);
                    true
                }
                None => {
                    self.leaves.insert(key, leaf);
                    true
                }
            }
        };
        if !touched {
            return;
        }
        self.dirty_leaves.push(key);
        let (slot, repr) = self.locate(key);
        if repr == EMPTY {
            // First leaf of the subtree: direct implicit chain.
            self.write_slot(slot, chain(key));
        } else if is_chain(repr) {
            let k = chain_key(repr);
            if k != key {
                // k/key divergence: new branch point at the depth of the
                // first differing bit (implicit chains on both sides).
                let div = divergence_depth(k, key);
                let bit_k = (k >> (D - 1 - div)) & 1;
                let np = pack(div, key >> (D - div));
                let (l, r) = if bit_k == 0 {
                    (chain(k), chain(key))
                } else {
                    (chain(key), chain(k))
                };
                self.nodes.insert(
                    np,
                    BranchNode {
                        hash: empty_leaf(),
                        left: l,
                        right: r,
                    },
                );
                self.dirty_nodes.push(np);
                self.write_slot(slot, node_ref(np));
            }
            // k == key: bucket or replacement — structure unchanged.
        } else {
            // NODE reference not covering key: branch between key and the
            // prefix of the referenced subtree. Divergence computed on the
            // d-bit prefixes (never on the full 40-bit integer): first
            // differing bit → depth div strictly < d.
            let (d, p) = unpack(node_packed(repr));
            let q = key >> (D - d);
            let x = q ^ p;
            debug_assert!(x != 0, "node does not cover key (guaranteed by locate)");
            let b = 63 - x.leading_zeros() as u64;
            let div = d - 1 - b;
            debug_assert!(div < d);
            let bit_key = (key >> (D - 1 - div)) & 1;
            let np = pack(div, key >> (D - div));
            let (l, r) = if bit_key == 0 {
                (chain(key), repr)
            } else {
                (repr, chain(key))
            };
            self.nodes.insert(
                np,
                BranchNode {
                    hash: empty_leaf(),
                    left: l,
                    right: r,
                },
            );
            self.dirty_nodes.push(np);
            self.write_slot(slot, node_ref(np));
        }
        self.recompute(key);
    }

    /// Removes an entry leaf from `key` (idempotent; emptied key → default
    /// subtree; bucket fallen back to 1 → single leaf).
    pub fn remove(&mut self, key: u64, leaf: &[u8; 32]) {
        let mut key_emptied = false;
        let touched = if let Some(v) = self.buckets.get_mut(&key) {
            match v.binary_search(leaf) {
                Ok(pos) => {
                    v.remove(pos);
                    if v.len() == 1 {
                        let rest = v.pop().expect("len 1");
                        self.buckets.remove(&key);
                        self.leaves.insert(key, rest);
                    }
                    true
                }
                Err(_) => false,
            }
        } else if self.leaves.get(&key) == Some(leaf) {
            self.leaves.remove(&key);
            key_emptied = true;
            true
        } else {
            false
        };
        if !touched {
            return;
        }
        self.dirty_leaves.push(key);
        if key_emptied {
            // The key lost its last leaf: remove its chain, then collapse
            // the degenerate branch points by WALKING UP the ancestor
            // stack of the path (collected by locate_full — never
            // re-descend: the path would mutate under our feet).
            let (stack, slot, repr) = self.locate_full(key);
            debug_assert!(
                is_chain(repr) && chain_key(repr) == key,
                "the removed leaf is the terminus of its path"
            );
            let _ = slot;
            // Promoted = value that will replace the reference of the
            // highest collapsed node. Starts at EMPTY (key's chain
            // disappears).
            let mut promoted = EMPTY;
            // Walk from the deepest node up to the root. stack[i] =
            // (packed node, key's bit at that node); stack[i]'s slot is
            // child `bit` of stack[i]. Removing key's chain makes
            // stack.last() degenerate; a degenerate node (one EMPTY
            // child) is removed and replaced by its other child.
            for &(parent, bit) in stack.iter().rev() {
                if promoted != EMPTY {
                    // The parent node survives: its child on key's side
                    // becomes the promoted subtree (CHAIN or NODE that
                    // absorbed the deeper removal) — rewrite the hashes
                    // upward and stop structural collapse.
                    break;
                }
                let other = {
                    let n = self.nodes.get(&parent).expect("parent alive");
                    if bit == 0 { n.right } else { n.left }
                };
                if other != EMPTY {
                    // Degenerate but carrying: the node collapses to
                    // `other`.
                    self.nodes.remove(&parent);
                    promoted = other;
                } else {
                    // Doubly degenerate: the node disappears, EMPTY moves
                    // up.
                    self.nodes.remove(&parent);
                }
            }
            // Rewrite the reference of the first surviving ancestor (or
            // the root) with the promoted value.
            if promoted != EMPTY {
                // First stack entry (from the bottom) not removed:
                let surviving = stack
                    .iter()
                    .rev()
                    .find(|&&(p, _)| self.nodes.contains_key(&p));
                match surviving {
                    Some(&(p, b)) => {
                        self.write_slot(SlotRef::Child { parent: p, bit: b }, promoted);
                        // Recompute the hashes above the attach point:
                        // v0 = value of the promoted subtree folded at
                        // the child depth of p (child_value handles
                        // CHAIN/NODE), then lifted to the root along the
                        // path.
                        let d_p = unpack(p).0;
                        let v0 = self.child_value(promoted, d_p);
                        self.recompute_from(key, v0, d_p + 1);
                    }
                    None => {
                        // All ancestors removed: the root IS the promoted.
                        self.root_child = promoted;
                        self.root_hash = Some(self.root_value());
                    }
                }
            } else {
                // Nothing promoted: the tree is empty (empty root), or
                // the stack was empty from the start (root was
                // CHAIN(key)).
                if stack.is_empty() {
                    self.root_child = EMPTY;
                    self.root_hash = None;
                } else {
                    // All path nodes removed without promotion:
                    // impossible (the last ancestor always has another
                    // non-empty child, else it would have collapsed
                    // before).
                    unreachable!("collapse without promotion with a non-empty stack");
                }
            }
            return;
        }
        self.recompute(key);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len() + self.buckets.values().map(Vec::len).sum::<usize>()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty() && self.buckets.is_empty()
    }

    /// Tree root: O(1) — cache maintained by `recompute`. Deterministic
    /// for the same content, regardless of order.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        match self.root_hash {
            Some(h) => h,
            None => defaults()[MAX_DEPTH as usize],
        }
    }

    // ——— Persistence (incremental redb snapshot) ———

    /// Drains the invalidation markers (node paths, leaf keys) accumulated
    /// since the last call.
    pub fn take_dirty(&mut self) -> (Vec<u64>, Vec<u64>) {
        (
            std::mem::take(&mut self.dirty_nodes),
            std::mem::take(&mut self.dirty_leaves),
        )
    }

    /// Number of stored branch points (metric/diagnostic).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Persistence read: branch node by packed path.
    #[must_use]
    pub fn branch_node(&self, packed: u64) -> Option<BranchNode> {
        self.nodes.get(&packed).copied()
    }

    /// Iterates all packed paths of the branch points.
    pub fn iter_branch_nodes(&self) -> impl Iterator<Item = (u64, BranchNode)> + '_ {
        self.nodes.iter().map(|(k, v)| (*k, *v))
    }

    /// Persisted leaf of a key: (unique hash) or (sorted bucket).
    #[must_use]
    pub fn leaf_entry(&self, key: u64) -> Option<LeafEntry> {
        if let Some(v) = self.buckets.get(&key) {
            return Some((v[0], Some(v.clone())));
        }
        self.leaves.get(&key).map(|h| (*h, None))
    }

    /// Iterates the leaf keys (single and bucketed).
    pub fn iter_leaf_keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.leaves
            .keys()
            .copied()
            .chain(self.buckets.keys().copied())
    }

    /// Root state for persistence: (root_child, root_hash).
    #[must_use]
    pub fn root_state(&self) -> (u64, Option<[u8; 32]>) {
        (self.root_child, self.root_hash)
    }

    /// Restoration: reinserts a branch node as-is (import).
    pub fn restore_branch_node(&mut self, packed: u64, n: BranchNode) {
        self.nodes.insert(packed, n);
    }

    /// Restoration: reinserts a leaf/bucket as-is (import).
    pub fn restore_leaf(&mut self, key: u64, h: [u8; 32], bucket: Option<Vec<[u8; 32]>>) {
        match bucket {
            None => {
                self.leaves.insert(key, h);
            }
            Some(v) => {
                self.buckets.insert(key, v);
            }
        }
    }

    /// Restoration: root state (root_child, root_hash).
    pub fn restore_root(&mut self, root_child: u64, root_hash: Option<[u8; 32]>) {
        self.root_child = root_child;
        self.root_hash = root_hash;
    }
}

/// SMT key of a 32-byte identifier: the top 40 bits (big-endian first 5
/// bytes; bits beyond the 40th are ignored).
#[must_use]
pub fn smt_key(id: &[u8; 32]) -> u64 {
    u64::from_be_bytes(id[0..8].try_into().expect("8 bytes")) >> (64 - MAX_DEPTH)
}

/// Content equality: the physical shape is a pure function of the
/// (key → leaf) set (see `# Guarantees`), so comparing the leaf/bucket
/// maps, the branch nodes and the root state is exact. The
/// dirty-tracking vectors (persistence markers, drained by
/// `take_dirty`) are deliberately excluded — they are write-side
/// bookkeeping, not committed state.
impl PartialEq for Smt {
    fn eq(&self, other: &Self) -> bool {
        self.root_child == other.root_child
            && self.root_hash == other.root_hash
            && self.leaves == other.leaves
            && self.buckets == other.buckets
            && self.nodes == other.nodes
    }
}

impl Eq for Smt {}

/// Compact diagnostic view (root/size only — never dumps the maps).
impl std::fmt::Debug for Smt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smt")
            .field("root", &self.root())
            .field("len", &self.len())
            .field("nodes", &self.node_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u64) -> [u8; 32] {
        scone_crypto::hash256(&[&i.to_le_bytes()])
    }

    /// Determinism: the same leaf set yields the same root regardless of
    /// insertion order (and after removals/reinsertions).
    #[test]
    fn root_is_order_independent() {
        let mut a = Smt::new();
        for k in 0..100u64 {
            a.insert(k * 7919 % 128, h(k));
        }
        let mut b = Smt::new();
        for k in (0..100u64).rev() {
            b.insert(k * 7919 % 128, h(k));
        }
        assert_eq!(a.root(), b.root());
        // removal + reinsertion → same root
        b.remove(0, &h(0));
        assert_ne!(a.root(), b.root());
        b.insert(0, h(0));
        assert_eq!(a.root(), b.root());
    }

    /// Empty tree: root = max-depth default, len 0.
    #[test]
    fn empty_root_is_pinned() {
        let s = Smt::new();
        assert!(s.is_empty());
        assert_eq!(s.root(), defaults()[MAX_DEPTH as usize]);
        assert_eq!(s.len(), 0);
    }

    /// Distinct content → distinct roots (one leaf is enough).
    #[test]
    fn distinct_content_distinct_roots() {
        let mut a = Smt::new();
        let mut b = Smt::new();
        a.insert(42, h(1));
        b.insert(43, h(1)); // other key
        assert_ne!(a.root(), b.root());
        b.remove(43, &h(1));
        b.insert(42, h(2)); // same key, other leaf
        assert_ne!(a.root(), b.root());
    }

    /// Collision buckets: two entries under the same key commit both (the
    /// root changes for each) and sorting makes them deterministic.
    #[test]
    fn collision_buckets_commit_all_entries() {
        let mut s = Smt::new();
        s.insert(7, h(1));
        let r1 = s.root();
        s.insert(7, h(2));
        assert_eq!(s.len(), 2);
        assert_ne!(s.root(), r1);
        // reversed order → same root
        let mut t = Smt::new();
        t.insert(7, h(2));
        t.insert(7, h(1));
        assert_eq!(s.root(), t.root());
    }

    /// In-place update: replacing a leaf = remove + insert, O(40).
    #[test]
    fn update_replaces_leaf() {
        let mut s = Smt::new();
        s.insert(9, h(1));
        let r_before = s.root();
        s.remove(9, &h(1));
        s.insert(9, h(2));
        assert_ne!(s.root(), r_before);
        assert_eq!(s.len(), 1);
        // back to the initial state → same root
        s.remove(9, &h(2));
        s.insert(9, h(1));
        assert_eq!(s.root(), r_before);
    }

    /// smt_key: top 40 bits, stable.
    #[test]
    fn smt_key_uses_top_40_bits() {
        let mut id = [0u8; 32];
        id[0] = 0xFF;
        id[4] = 0x01;
        let expected = u64::from_be_bytes([0xFF, 0, 0, 0, 0x01, 0, 0, 0]) >> 24;
        assert_eq!(smt_key(&id), expected);
        // bits beyond the 40th change nothing
        let a = smt_key(&id);
        id[5] = 0xFF;
        id[6] = 0xFF;
        assert_eq!(smt_key(&id), a);
    }

    /// Implicit chains: nearby keys (long shared prefix) create only one
    /// branch point — and the root is exactly that of a naive computation
    /// folding the defaults.
    #[test]
    fn compact_chains_match_naive_root() {
        // Three keys sharing 38 bits of prefix: 2 branch points.
        let keys = [1u64 << 2, 1u64 << 2 | 1, 1u64 << 1];
        let mut s = Smt::new();
        for (i, k) in keys.iter().enumerate() {
            s.insert(*k, h(i as u64));
        }
        assert_eq!(s.len(), 3);
        // Naive root: fold the full tree from the leaves. Partition on the
        // bit at `depth` (0 = left, 1 = right).
        fn naive(
            depth: u64,
            prefix: u64,
            keys: &[u64],
            leaf: &dyn Fn(u64) -> [u8; 32],
        ) -> [u8; 32] {
            if depth == D {
                return if keys.contains(&prefix) {
                    leaf(prefix)
                } else {
                    empty_leaf()
                };
            }
            let (l, r): (Vec<u64>, Vec<u64>) =
                keys.iter().partition(|k| (*k >> (D - depth - 1)) & 1 == 0);
            let lh = if l.is_empty() {
                defaults()[(D - depth - 1) as usize]
            } else {
                naive(depth + 1, prefix << 1, &l, leaf)
            };
            let rh = if r.is_empty() {
                defaults()[(D - depth - 1) as usize]
            } else {
                naive(depth + 1, prefix << 1 | 1, &r, leaf)
            };
            node_hash(&lh, &rh)
        }
        let leaf = |k: u64| -> [u8; 32] {
            keys.iter()
                .position(|x| *x == k)
                .map(|i| h(i as u64))
                .unwrap_or_else(empty_leaf)
        };
        assert_eq!(s.root(), naive(0, 0, &keys, &leaf));
    }

    /// Compact trie: N leaves → N-1 branch points (only divergence
    /// points, never the chain nodes).
    #[test]
    fn node_count_equals_branch_points() {
        let mut s = Smt::new();
        s.insert(1 << 5, h(1));
        assert_eq!(s.node_count(), 0); // single leaf: chain only
        s.insert((1 << 5) | 1, h(2));
        assert_eq!(s.node_count(), 1);
        s.insert(1 << 6, h(3));
        assert_eq!(s.node_count(), 2);
        for i in 0..64u64 {
            s.insert(1 << 20 | i, h(20 + i));
        }
        // 64 consecutive keys in a subtree → 63 branch points inside, one
        // above (already counted), one attaching that subtree.
        assert_eq!(s.node_count(), 2 + 63 + 1);
    }

    /// Collapse: removing one of the two leaves of a branch removes the
    /// branch point (node_count decreases).
    #[test]
    fn remove_collapses_branch_points() {
        let mut s = Smt::new();
        s.insert(1 << 5, h(1));
        s.insert((1 << 5) | 1, h(2));
        assert_eq!(s.node_count(), 1);
        s.remove((1 << 5) | 1, &h(2));
        assert_eq!(s.node_count(), 0);
        // the remaining leaf alone → root = folded chain
        let mut t = Smt::new();
        t.insert(1 << 5, h(1));
        assert_eq!(s.root(), t.root());
        // and full removal is back to the empty tree
        s.remove(1 << 5, &h(1));
        assert_eq!(s.root(), defaults()[MAX_DEPTH as usize]);
        assert_eq!(s.node_count(), 0);
    }

    /// High divergence: an insertion whose key diverges from a referenced
    /// subtree BEFORE the depth of its node (intermediate chain).
    #[test]
    fn insertion_above_referenced_node() {
        let near = 1u64 << 39;
        let far = (1u64 << 39) | 12345;
        let mut s = Smt::new();
        s.insert(near, h(1));
        s.insert(far, h(2));
        let mut t = Smt::new();
        t.insert(near, h(1));
        t.insert(far, h(2));
        assert_eq!(s.root(), t.root());
        // canonical structure: 1 single branch point for 2 leaves
        assert_eq!(s.node_count(), 1);
    }

    /// Persistence: export → freshly imported tree → same root, same
    /// subsequent operations (restore_branch_node/leaf/root).
    #[test]
    fn snapshot_restore_roundtrip() {
        let mut s = Smt::new();
        for k in 0..500u64 {
            s.insert(k.wrapping_mul(0x9E3779B97F4A7C15) >> 24, h(k));
        }
        s.insert(7, h(1000)); // collision bucket
        let mut t = Smt::new();
        for (packed, n) in s.iter_branch_nodes() {
            t.restore_branch_node(packed, n);
        }
        for k in s.iter_leaf_keys() {
            let (h1, b) = s.leaf_entry(k).expect("leaf");
            t.restore_leaf(k, h1, b);
        }
        let (rc, rh) = s.root_state();
        t.restore_root(rc, rh);
        assert_eq!(s.root(), t.root());
        assert_eq!(s.len(), t.len());
        assert_eq!(s.node_count(), t.node_count());
        // both trees then evolve identically
        s.insert(999_999, h(42));
        t.insert(999_999, h(42));
        assert_eq!(s.root(), t.root());
    }

    /// Dirty tracking: touched node paths and leaf keys accumulate until
    /// `take_dirty` drains them; a no-op insert touches nothing.
    #[test]
    fn take_dirty_drains_and_resets() {
        let mut s = Smt::new();
        s.insert(1, h(1));
        s.insert(2, h(2));
        let (nodes, leaves) = s.take_dirty();
        assert_eq!(leaves.len(), 2);
        assert!(!nodes.is_empty()); // branch point between keys 1 and 2
        let (nodes2, leaves2) = s.take_dirty();
        assert!(nodes2.is_empty() && leaves2.is_empty());
        // idempotent insert → nothing dirty
        s.insert(1, h(1));
        let (n3, l3) = s.take_dirty();
        assert!(n3.is_empty() && l3.is_empty());
        // removal dirties the leaf key
        s.remove(1, &h(1));
        let (n4, l4) = s.take_dirty();
        assert_eq!(l4, vec![1]);
        assert!(!n4.is_empty() || s.node_count() == 0); // collapse may empty it
    }

    /// Differential fuzz: compact `Smt` vs a verbatim port of the original
    /// flat-arena implementation, seeded random operations — the roots
    /// must stay IDENTICAL after every operation.
    #[test]
    fn differential_fuzz() {
        mod legacy {
            use super::super::*;
            use std::collections::HashMap;
            const MAX_DEPTH: u8 = 40;
            fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
                scone_crypto::hash256(&[SMT_NODE_TAG, left, right])
            }
            fn empty_leaf() -> [u8; 32] {
                scone_crypto::hash256(&[SMT_EMPTY_LEAF_TAG])
            }
            fn defaults() -> Vec<[u8; 32]> {
                let mut d = Vec::with_capacity(MAX_DEPTH as usize + 1);
                d.push(empty_leaf());
                for i in 1..=MAX_DEPTH as usize {
                    d.push(node_hash(&d[i - 1], &d[i - 1]));
                }
                d
            }
            #[derive(Default, Clone)]
            pub struct LegacySmt {
                pub leaves: HashMap<u64, [u8; 32]>,
                pub buckets: HashMap<u64, Vec<[u8; 32]>>,
                pub nodes: HashMap<(u8, u64), [u8; 32]>,
            }
            impl LegacySmt {
                fn bucket_root(&self, key: u64) -> [u8; 32] {
                    if let Some(v) = self.buckets.get(&key) {
                        return bucket_merkle_root(v);
                    }
                    match self.leaves.get(&key) {
                        None => empty_leaf(),
                        Some(h) => *h,
                    }
                }
                pub fn insert(&mut self, key: u64, leaf: [u8; 32]) {
                    let touched = if let Some(v) = self.buckets.get_mut(&key) {
                        match v.binary_search(&leaf) {
                            Ok(_) => false,
                            Err(pos) => {
                                v.insert(pos, leaf);
                                true
                            }
                        }
                    } else {
                        match self.leaves.get(&key) {
                            Some(h) if *h == leaf => false,
                            Some(h) => {
                                let mut v = vec![*h, leaf];
                                v.sort_unstable();
                                self.buckets.insert(key, v);
                                self.leaves.remove(&key);
                                true
                            }
                            None => {
                                self.leaves.insert(key, leaf);
                                true
                            }
                        }
                    };
                    if touched {
                        let defs = defaults();
                        self.recompute_path_key(key, &defs);
                    }
                }
                fn recompute_path_key(&mut self, key: u64, defs: &[[u8; 32]]) {
                    let mut cur = self.bucket_root(key);
                    for d in (0..=MAX_DEPTH).rev() {
                        let path = key >> (MAX_DEPTH - d);
                        if cur == defs[(MAX_DEPTH - d) as usize] {
                            self.nodes.remove(&(d, path));
                        } else {
                            self.nodes.insert((d, path), cur);
                        }
                        if d == 0 {
                            break;
                        }
                        let sib = self
                            .nodes
                            .get(&(d, path ^ 1))
                            .copied()
                            .unwrap_or(defs[(MAX_DEPTH - d) as usize]);
                        let (left, right) = if path & 1 == 0 {
                            (cur, sib)
                        } else {
                            (sib, cur)
                        };
                        cur = node_hash(&left, &right);
                    }
                }
                pub fn remove(&mut self, key: u64, leaf: &[u8; 32]) {
                    let defs = defaults();
                    let mut touched = false;
                    if let Some(v) = self.buckets.get_mut(&key) {
                        if let Ok(pos) = v.binary_search(leaf) {
                            v.remove(pos);
                            touched = true;
                            if v.len() <= 1 {
                                let rest = v.pop();
                                self.buckets.remove(&key);
                                if let Some(h) = rest {
                                    self.leaves.insert(key, h);
                                }
                            }
                        }
                    } else if self.leaves.get(&key) == Some(leaf) {
                        self.leaves.remove(&key);
                        touched = true;
                    }
                    if touched {
                        self.recompute_path_key(key, &defs);
                    }
                }
                pub fn len(&self) -> usize {
                    self.leaves.len() + self.buckets.values().map(Vec::len).sum::<usize>()
                }
                pub fn root(&self) -> [u8; 32] {
                    self.nodes
                        .get(&(0, 0))
                        .copied()
                        .unwrap_or_else(|| defaults()[MAX_DEPTH as usize])
                }
            }
        }

        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
        }

        for &seed in &[1u64, 2, 3, 7, 42, 1337, 20260910] {
            let mut rng = Rng(seed);
            let universe: u64 = 1 << 32;
            let mut new = Smt::new();
            let mut old = legacy::LegacySmt::default();
            let mut live: Vec<(u64, u64)> = vec![];
            for step in 0..20000 {
                let key = rng.next() % universe;
                let (ins, k, l) = if rng.next().is_multiple_of(3) || live.is_empty() {
                    let leaf = rng.next() % 8;
                    live.push((key, leaf));
                    (true, key, leaf)
                } else {
                    let i = (rng.next() as usize) % live.len();
                    let (k, l) = live[i];
                    live.remove(i);
                    (false, k, l)
                };
                if ins {
                    new.insert(k, h(l));
                    old.insert(k, h(l));
                } else {
                    new.remove(k, &h(l));
                    old.remove(k, &h(l));
                }
                assert_eq!(
                    new.root(),
                    old.root(),
                    "divergence seed={seed} step={step} op={} key={k} leaf={l}",
                    if ins { "INS" } else { "REM" }
                );
                assert_eq!(new.len(), old.len());
            }
        }
    }
}
