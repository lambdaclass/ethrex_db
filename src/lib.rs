//! EthrexDB is a lightweight Merkle Patricia Trie (MPT) based database, designed to serve as a foundational storage layer for Ethereum execution environments.

/// Database implementation.
mod db;
/// Interact with the file
mod file_manager;
/// Serialization and deserialization of the trie.
mod serialization;

// ETHREX COPY STRUCTURES
mod ethrex;
pub use ethrex::rlp;
pub use ethrex::trie;

pub use db::EthrexDB;
