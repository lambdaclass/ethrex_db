//! # ethrex_db
//!
//! A Paprika-inspired Ethereum state storage engine for ethrex.
//!
//! ## Architecture
//!
//! The library is split into two major components:
//!
//! 1. **Blockchain** - Handles "hot" blocks (latest/safe, not yet finalized)
//! 2. **PagedDb** - Handles finalized blocks (cold storage)
//!
//! ## Modules
//!
//! - `data` - Core data structures (NibblePath, SlottedArray)
//! - `store` - Page-based persistent storage
//! - `chain` - Block management for unfinalized state
//! - `merkle` - State root hash computation
//!
//! ## Public API
//!
//! The following types are re-exported for convenience:
//!
//! ### Chain Module
//! - `Blockchain` - Main blockchain manager for hot/cold state
//! - `Block` - Block representation during execution
//! - `BlockId` - Block identifier (hash + number)
//! - `Account` - Account state (nonce, balance, code_hash, storage_root)
//! - `WorldState` - Trait for mutable world state access
//! - `ReadOnlyWorldState` - Trait for read-only world state access
//! - `BlockchainError` - Error types for blockchain operations
//!
//! ### Store Module
//! - `PagedDb` - Memory-mapped database with CoW semantics
//! - `PagedStateTrie` - Persistent state trie
//! - `CodeStore` - Contract bytecode storage
//! - `AccountData` - Account data for trie storage
//! - `DbError` - Database error types
//! - `CommitOptions` - Options for committing batches
//! - `Snapshot` - Database snapshot for backup/restore
//!
//! ### Merkle Module
//! - `MerkleTrie` - In-memory Merkle Patricia Trie
//! - `keccak256` - Keccak256 hash function
//! - `EMPTY_ROOT` - Empty trie root hash

pub mod data;
pub mod store;
pub mod chain;
pub mod merkle;

// Re-export commonly used types for convenience
pub use chain::{Blockchain, Block, BlockId, Account, WorldState, ReadOnlyWorldState, BlockchainError};
pub use store::{
    PagedDb, PagedStateTrie, AccountData, CodeStore,
    DbError, BatchContext, ReadOnlyBatch, CommitOptions, Snapshot,
    DbAddress,
};
pub use merkle::{MerkleTrie, keccak256, EMPTY_ROOT};
pub use data::NibblePath;
