//! Simple in-memory index: [`NodeHash`] -> offset lookups
//!
//! This is used to store the absolute offset of the node in the file
//! for each node hash. With this information, we can create new nodes and be able
//! to point to nodes that didn't change and exist in the file.

use crate::trie::NodeHash;
use std::collections::HashMap;

/// Simple in-memory index
#[derive(Debug, Default)]
pub struct Index {
    /// Index map
    /// TODO: Use a better data structure
    /// TODO: Read from file if it exists
    data: HashMap<NodeHash, u64>,
}

impl Index {
    /// Create a new empty index
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Get an offset by node hash
    pub fn get(&self, hash: &NodeHash) -> Option<u64> {
        self.data.get(hash).copied()
    }

    /// Insert a new node hash -> offset mapping
    pub fn insert(&mut self, hash: NodeHash, offset: u64) {
        self.data.insert(hash, offset);
    }

    /// Get the number of entries in the index
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the index is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_index() {
        let index = Index::new();
        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
    }

    #[test]
    fn test_insert_and_get() {
        let mut index = Index::new();
        let hash = NodeHash::default();
        let offset = 1234u64;

        index.insert(hash, offset);
        assert_eq!(index.get(&hash), Some(offset));
        assert_eq!(index.len(), 1);
        assert!(!index.is_empty());
    }

    #[test]
    fn test_multiple_hash_types() {
        let mut index = Index::new();

        // Test with different NodeHash variants
        let inline_hash = NodeHash::from_slice(&[1, 2, 3]);
        let hashed_hash = NodeHash::from_slice(&[0u8; 32]);

        index.insert(inline_hash, 100);
        index.insert(hashed_hash, 200);

        assert_eq!(index.get(&inline_hash), Some(100));
        assert_eq!(index.get(&hashed_hash), Some(200));
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut index = Index::new();
        let hash = NodeHash::default();

        index.insert(hash, 123);
        assert_eq!(index.len(), 1);

        index.clear();
        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
        assert_eq!(index.get(&hash), None);
    }
}
