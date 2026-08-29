use std::fmt;

// The v0.1 pure-core envelope is contract-visible and intentionally fixed.
// Byte limits align with source-manifest-v2; graph limits align with the
// built-in config-v2 profile. The edge budget permits the documented
// four-edge average fanout without silently widening the node budget.
const BYTES_PER_MEBIBYTE: u64 = 1_048_576;
const DEFAULT_INPUT_MEBIBYTES: u64 = 16;
const DEFAULT_SNAPSHOT_MEBIBYTES: u64 = 4_096;
const DEFAULT_GRAPH_NODES: u64 = 1_000_000;
const DEFAULT_GRAPH_EDGE_FANOUT: u64 = 4;
const DEFAULT_NESTING_DEPTH: u32 = 128;

/// A deterministic resource envelope. A caller may make it smaller, but an
/// untrusted document cannot widen it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    pub max_input_bytes: u64,
    pub max_file_bytes: u64,
    pub max_snapshot_bytes: u64,
    pub max_entries: u64,
    pub max_nodes: u64,
    pub max_edges: u64,
    pub max_nesting: u32,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_INPUT_MEBIBYTES * BYTES_PER_MEBIBYTE,
            max_file_bytes: DEFAULT_INPUT_MEBIBYTES * BYTES_PER_MEBIBYTE,
            max_snapshot_bytes: DEFAULT_SNAPSHOT_MEBIBYTES * BYTES_PER_MEBIBYTE,
            max_entries: DEFAULT_GRAPH_NODES,
            max_nodes: DEFAULT_GRAPH_NODES,
            max_edges: DEFAULT_GRAPH_NODES * DEFAULT_GRAPH_EDGE_FANOUT,
            max_nesting: DEFAULT_NESTING_DEPTH,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetKind {
    InputBytes,
    FileBytes,
    SnapshotBytes,
    Entries,
    Nodes,
    Edges,
    Nesting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetError {
    pub kind: BudgetKind,
    pub limit: u64,
    pub attempted: u64,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Incomplete.Resource_limit: {:?} budget {} exceeded by {}",
            self.kind, self.limit, self.attempted
        )
    }
}

impl std::error::Error for BudgetError {}

#[derive(Clone, Debug)]
pub struct BudgetTracker {
    budget: Budget,
    snapshot_bytes: u64,
    entries: u64,
    nodes: u64,
    edges: u64,
}

impl BudgetTracker {
    #[must_use]
    pub fn new(budget: Budget) -> Self {
        Self {
            budget,
            snapshot_bytes: 0,
            entries: 0,
            nodes: 0,
            edges: 0,
        }
    }

    fn add(
        current: &mut u64,
        amount: u64,
        limit: u64,
        kind: BudgetKind,
    ) -> Result<(), BudgetError> {
        let attempted = current.saturating_add(amount);
        if attempted > limit {
            return Err(BudgetError {
                kind,
                limit,
                attempted,
            });
        }
        *current = attempted;
        Ok(())
    }

    /// Validate the size of one untrusted input.
    ///
    /// # Errors
    /// Returns a typed resource-limit error when `bytes` exceeds the envelope.
    pub fn input(&self, bytes: usize) -> Result<(), BudgetError> {
        let attempted = u64::try_from(bytes).unwrap_or(u64::MAX);
        if attempted > self.budget.max_input_bytes {
            Err(BudgetError {
                kind: BudgetKind::InputBytes,
                limit: self.budget.max_input_bytes,
                attempted,
            })
        } else {
            Ok(())
        }
    }

    /// Account for one regular file and the cumulative snapshot size.
    ///
    /// # Errors
    /// Returns a typed resource-limit error without mutating the counter when
    /// either the per-file or cumulative limit would be exceeded.
    pub fn file(&mut self, bytes: u64) -> Result<(), BudgetError> {
        if bytes > self.budget.max_file_bytes {
            return Err(BudgetError {
                kind: BudgetKind::FileBytes,
                limit: self.budget.max_file_bytes,
                attempted: bytes,
            });
        }
        Self::add(
            &mut self.snapshot_bytes,
            bytes,
            self.budget.max_snapshot_bytes,
            BudgetKind::SnapshotBytes,
        )
    }

    /// Account for one source-manifest entry.
    ///
    /// # Errors
    /// Returns a typed error when the entry budget is exhausted.
    pub fn entry(&mut self) -> Result<(), BudgetError> {
        Self::add(
            &mut self.entries,
            1,
            self.budget.max_entries,
            BudgetKind::Entries,
        )
    }

    /// Account for one IR node.
    ///
    /// # Errors
    /// Returns a typed error when the node budget is exhausted.
    pub fn node(&mut self) -> Result<(), BudgetError> {
        Self::add(&mut self.nodes, 1, self.budget.max_nodes, BudgetKind::Nodes)
    }

    /// Account for one IR edge.
    ///
    /// # Errors
    /// Returns a typed error when the edge budget is exhausted.
    pub fn edge(&mut self) -> Result<(), BudgetError> {
        Self::add(&mut self.edges, 1, self.budget.max_edges, BudgetKind::Edges)
    }
}
