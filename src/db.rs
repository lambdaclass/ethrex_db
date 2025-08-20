//! EthrexDB - Copy-on-Write Merkle Patricia Trie Database
//!
//! The database implements Copy-on-Write (CoW) optimization where only modified nodes
//! are written during commits. Unchanged nodes are referenced by their file offset,
//! avoiding duplication. All writes are append-only - data is never overwritten,
//! only appended to the end of the file.
//!
//! Each commit creates a new root that links to the previous root via a prepended
//! offset, forming a linked list of all historical states. This allows traversing
//! the entire version history if needed.

use crate::file_manager::FileManager;
use crate::index::Index;
use crate::serialization::{Deserializer, Serializer};
use crate::trie::{Node, NodeHash, TrieError};
use std::path::PathBuf;

/// Ethrex DB struct
pub struct EthrexDB {
    /// File manager
    file_manager: FileManager,
    /// Index mapping node hashes to their file offsets
    node_index: Index,
}

impl EthrexDB {
    /// Create a new database
    pub fn new(file_path: PathBuf) -> Result<Self, TrieError> {
        let file_manager = FileManager::create(file_path.clone())?;
        let node_index = Index::new();
        Ok(Self {
            file_manager,
            node_index,
        })
    }

    /// Open an existing database
    pub fn open(file_path: PathBuf) -> Result<Self, TrieError> {
        let file_manager = FileManager::open(file_path.clone())?;
        let node_index = Index::new();
        Ok(Self {
            file_manager,
            node_index,
        })
    }

    /// Commit a trie state to the database
    pub fn commit(&mut self, root_node: &Node) -> Result<NodeHash, TrieError> {
        let root_hash = root_node.compute_hash();

        let prev_root_offset = self.file_manager.read_latest_root_offset()?;
        let base_offset = self.file_manager.get_file_size()?;

        let serializer = Serializer::new(&self.node_index, base_offset);
        let (serialized_data, new_offsets, root_offset) =
            serializer.serialize_tree(root_node, prev_root_offset)?;

        self.file_manager.write_at_end(&serialized_data)?;

        // Update node index with new node offsets
        for (hash, absolute_offset) in new_offsets {
            self.node_index.insert(hash, absolute_offset);
        }

        // Update header to point to the root node
        self.file_manager.update_latest_root_offset(root_offset)?;
        Ok(root_hash)
    }

    /// Get the latest root node of the database
    pub fn root(&self) -> Result<Node, TrieError> {
        let latest_offset = self.file_manager.read_latest_root_offset()?;
        if latest_offset == 0 {
            return Err(TrieError::Other("No root node in database".to_string()));
        }

        let file_data = self.file_manager.get_slice_to_end(0)?;
        // All roots now have 8-byte prepended previous root offset
        let actual_root_offset = latest_offset + 8;

        Deserializer::new(file_data).decode_node_at(actual_root_offset as usize)
    }

    /// Get the value of the node with the given key
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        let latest_offset = self.file_manager.read_latest_root_offset()?;
        if latest_offset == 0 {
            return Ok(None);
        }

        let file_data = self.file_manager.get_slice_to_end(0)?;

        // All roots have 8-byte prepended previous root offset
        let actual_root_offset = latest_offset + 8;

        Deserializer::new(file_data).get_by_path_at(key, actual_root_offset as usize)
    }
}

#[cfg(test)]
mod tests {
    use crate::trie::{InMemoryTrieDB, Trie};

    use super::*;
    use tempdir::TempDir;

    // Helper function to generate test data
    fn generate_test_data(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        use sha3::{Digest, Keccak256};

        (1..=n)
            .map(|i| {
                // 32-byte key (hash)
                let key = Keccak256::new()
                    .chain_update(i.to_be_bytes())
                    .finalize()
                    .to_vec();

                // 104-byte value (account info: 2 hashes + u256 + u64)
                let mut value = Vec::with_capacity(104);
                value.extend_from_slice(
                    &Keccak256::new()
                        .chain_update((i * 2).to_be_bytes())
                        .finalize(),
                );
                value.extend_from_slice(
                    &Keccak256::new()
                        .chain_update((i * 3).to_be_bytes())
                        .finalize(),
                );
                value.extend_from_slice(&[0u8; 24]); // u256 padding
                value.extend_from_slice(&(i as u64).to_be_bytes()); // u256 value
                value.extend_from_slice(&(i as u64).to_be_bytes()); // u64

                (key, value)
            })
            .collect()
    }

    #[test]
    fn test_create_and_commit() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"hello".to_vec(), b"world".to_vec()).unwrap();
        trie.insert(b"foo".to_vec(), b"bar".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();

        let root_hash = db.commit(&root_node).unwrap();
        assert_ne!(root_hash.as_ref(), [0u8; 32]);
    }

    #[test]
    fn test_open_existing() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        {
            let mut db = EthrexDB::new(db_path.clone()).unwrap();

            let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
            trie.insert(b"key".to_vec(), b"value".to_vec()).unwrap();
            let root_node = trie.root_node().unwrap().unwrap();
            db.commit(&root_node).unwrap();
        }

        let db = EthrexDB::open(db_path).unwrap();
        let value = db.get(b"key").unwrap();
        assert_eq!(value, Some(b"value".to_vec()));
    }

    #[test]
    fn test_get_value() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        // Test getting from empty db
        assert_eq!(db.get(b"nonexistent").unwrap(), None);

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"hello".to_vec(), b"world".to_vec()).unwrap();
        trie.insert(b"foo".to_vec(), b"bar".to_vec()).unwrap();
        trie.insert(b"test".to_vec(), b"value".to_vec()).unwrap();

        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        // Test getting existing values
        assert_eq!(db.get(b"hello").unwrap(), Some(b"world".to_vec()));
        assert_eq!(db.get(b"foo").unwrap(), Some(b"bar".to_vec()));
        assert_eq!(db.get(b"test").unwrap(), Some(b"value".to_vec()));

        // Test getting non-existent value
        assert_eq!(db.get(b"nonexistent").unwrap(), None);
    }

    #[test]
    fn test_incremental_commit() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();
        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));

        // First commit: Add initial keys
        trie.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        trie.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        let initial_file_size = db.file_manager.get_file_size().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap(); // Convert NodeRef::Node to NodeRef::Hash
        let recovered_root = db.root().unwrap();
        assert_eq!(recovered_root, root_node);

        let size_after_first = db.file_manager.get_file_size().unwrap();
        assert!(size_after_first > initial_file_size);

        // Second commit: Add one more key (should only store new nodes)
        trie.insert(b"key3".to_vec(), b"value3".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        assert_eq!(db.root().unwrap(), root_node);
        trie.commit().unwrap();

        let size_after_second = db.file_manager.get_file_size().unwrap();
        // Should be smaller increment than first commit
        let first_increment = size_after_first - initial_file_size;
        let second_increment = size_after_second - size_after_first;
        assert!(
            second_increment < first_increment,
            "Second commit should add less data due to CoW"
        );

        // Verify all values are still accessible
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(b"key2").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(db.get(b"key3").unwrap(), Some(b"value3".to_vec()));

        // Third commit: Update existing key (should reuse many nodes)
        trie.insert(b"key2".to_vec(), b"value2_updated".to_vec())
            .unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();
        assert_eq!(db.root().unwrap(), root_node);

        // Verify updated value
        assert_eq!(db.get(b"key2").unwrap(), Some(b"value2_updated".to_vec()));
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(b"key3").unwrap(), Some(b"value3".to_vec()));
    }

    #[test]
    fn test_blockchain_simulation_with_incremental_storage() {
        let temp_dir = TempDir::new("ethrex_blockchain_sim").unwrap();
        let db_path = temp_dir.path().join("blockchain.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();
        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));

        // Batch 1: Initial accounts
        let batch1_data = generate_test_data(100);

        for (key, value) in batch1_data.iter() {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        let root_node1 = trie.root_node().unwrap().unwrap();
        let trie_root_hash1 = root_node1.compute_hash();
        let db_root_hash1 = db.commit(&root_node1).unwrap();
        trie.commit().unwrap(); // Convert to NodeRef::Hash

        assert_eq!(
            trie_root_hash1, db_root_hash1,
            "Root hashes must match after batch 1"
        );
        assert_eq!(
            db.root().unwrap(),
            root_node1,
            "DB root must match trie root after batch 1"
        );

        // Batch 2: New transactions + modify some existing accounts
        let new_accounts_batch2 = generate_test_data(150);

        // Add 50 new accounts (indices 100-149)
        for (key, value) in new_accounts_batch2[100..].iter() {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        // Modify some existing accounts from batch 1
        for i in [10, 25, 50, 75].iter() {
            if *i < batch1_data.len() {
                let (key, _) = &batch1_data[*i];
                let new_value = format!("modified_account_{}", i).into_bytes();
                trie.insert(key.clone(), new_value).unwrap();
            }
        }

        let root_node2 = trie.root_node().unwrap().unwrap();
        let trie_root_hash2 = root_node2.compute_hash();
        let db_root_hash2 = db.commit(&root_node2).unwrap();
        trie.commit().unwrap(); // Convert to NodeRef::Hash 

        assert_eq!(
            trie_root_hash2, db_root_hash2,
            "Root hashes must match after batch 2"
        );
        assert_eq!(
            db.root().unwrap(),
            root_node2,
            "DB root must match trie root after batch 2"
        );

        // Batch 3: More transactions
        let new_accounts_batch3 = generate_test_data(200);

        // Add 50 more new accounts (indices 150-199)
        for (key, value) in &new_accounts_batch3[150..] {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        // Modify more existing accounts
        for i in [5, 15, 35, 45, 110, 125].iter() {
            if *i < 150 {
                let test_data = generate_test_data(*i + 1);
                let (key, _) = &test_data[*i];
                let new_value = format!("batch3_modified_{}", i).into_bytes();
                trie.insert(key.clone(), new_value).unwrap();
            }
        }

        let root_node3 = trie.root_node().unwrap().unwrap();
        let trie_root_hash3 = root_node3.compute_hash();
        let db_root_hash3 = db.commit(&root_node3).unwrap();
        trie.commit().unwrap(); // Convert to NodeRef::Hash

        assert_eq!(
            trie_root_hash3, db_root_hash3,
            "Root hashes must match after batch 3"
        );
        assert_eq!(
            db.root().unwrap(),
            root_node3,
            "DB root must match trie root after batch 3"
        );

        // Batch 4: Large update batch
        let new_accounts_batch4 = generate_test_data(250);

        // Add 50 more new accounts (indices 200-249)
        for (key, value) in &new_accounts_batch4[200..] {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        // Modify many existing accounts
        for i in [1, 20, 30, 40, 60, 80, 90, 105, 115, 135, 145, 170, 180].iter() {
            if *i < 200 {
                let test_data = generate_test_data(*i + 1);
                let (key, _) = &test_data[*i];
                let new_value = format!("batch4_update_{}", i).into_bytes();
                trie.insert(key.clone(), new_value).unwrap();
            }
        }

        let root_node4 = trie.root_node().unwrap().unwrap();
        let trie_root_hash4 = root_node4.compute_hash();
        let db_root_hash4 = db.commit(&root_node4).unwrap();
        trie.commit().unwrap(); // Convert to NodeRef::Hash

        assert_eq!(
            trie_root_hash4, db_root_hash4,
            "Root hashes must match after batch 4"
        );
        assert_eq!(
            db.root().unwrap(),
            root_node4,
            "DB root must match trie root after batch 4"
        );

        // Batch 5: Final verification batch
        let new_accounts_batch5 = generate_test_data(300);

        // Add 50 final accounts (indices 250-299)
        for (key, value) in &new_accounts_batch5[250..] {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        // Few more modifications
        for i in [8, 28, 58, 88, 128, 158, 188, 218].iter() {
            if *i < 250 {
                let test_data = generate_test_data(*i + 1);
                let (key, _) = &test_data[*i];
                let new_value = format!("final_update_{}", i).into_bytes();
                trie.insert(key.clone(), new_value).unwrap();
            }
        }

        let root_node5 = trie.root_node().unwrap().unwrap();
        let trie_root_hash5 = root_node5.compute_hash();
        let db_root_hash5 = db.commit(&root_node5).unwrap();
        trie.commit().unwrap(); // Convert to NodeRef::Hash

        assert_eq!(
            trie_root_hash5, db_root_hash5,
            "Root hashes must match after batch 5"
        );
        assert_eq!(
            db.root().unwrap(),
            root_node5,
            "DB root must match trie root after batch 5"
        );

        // Random verification of some accounts
        for batch_num in 1..=5 {
            let test_data = generate_test_data(batch_num * 50);
            if let Some((key, _)) = test_data.get(batch_num * 10) {
                assert_eq!(db.get(key).unwrap(), trie.get(key).unwrap());
            }
        }
    }
}
