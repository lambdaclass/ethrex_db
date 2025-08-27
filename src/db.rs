//! EthrexDB - Merkle Patricia Trie Database with MVCC Transaction Support
//!
//! The database implements Copy-on-Write (CoW) optimization where only modified nodes
//! are written during commits. Unchanged nodes are referenced by their file offset,
//! avoiding duplication. All writes are append-only - data is never overwritten,
//! only appended to the end of the file.
//!
//! Each commit creates a new root that links to the previous root via a prepended
//! offset, forming a linked list of all historical states. This allows traversing
//! the entire version history if needed.
//!
//! ## Transaction System
//!
//! All data access must be performed through read transactions, which provide
//! snapshot isolation guarantees:
//!

use crate::file_manager::FileManager;
use crate::index::Index;
use crate::serialization::{Deserializer, Serializer};
use crate::transaction::ReadTransaction;
use crate::transaction_manager::TransactionManager;
use crate::trie::{Node, NodeHash, TrieError};
use std::path::PathBuf;
// TODO: Should we use Mutex or other sync?
use std::sync::{Mutex, RwLock};

/// Ethrex DB struct - A transactional Merkle Patricia Trie database
///
/// This database requires all read operations to be performed through transactions
/// to ensure snapshot isolation and data consistency. It includes reference counting
/// to prevent pruning of snapshots that are still in use.
pub struct EthrexDB {
    /// File manager
    file_manager: RwLock<FileManager>,
    /// Index mapping node hashes to their file offsets
    /// TODO: Read from file if it exists to
    node_index: RwLock<Index>,
    /// Transaction manager for reference counting and safe pruning
    transaction_manager: Mutex<TransactionManager>,
}

impl EthrexDB {
    /// Create a new database
    pub fn new(file_path: PathBuf) -> Result<Self, TrieError> {
        let file_manager = FileManager::create(file_path.clone())?;
        let node_index = Index::new();
        let transaction_manager = Mutex::new(TransactionManager::new());
        Ok(Self {
            file_manager: RwLock::new(file_manager),
            node_index: RwLock::new(node_index),
            transaction_manager,
        })
    }

    /// Open an existing database
    pub fn open(file_path: PathBuf) -> Result<Self, TrieError> {
        let file_manager = FileManager::open(file_path.clone())?;
        // TODO: Read node index from file if it exists
        let node_index = Index::new();
        let transaction_manager = Mutex::new(TransactionManager::new());
        Ok(Self {
            file_manager: RwLock::new(file_manager),
            node_index: RwLock::new(node_index),
            transaction_manager,
        })
    }

    /// Commit a trie state to the database
    pub fn commit(&self, root_node: &Node) -> Result<NodeHash, TrieError> {
        let root_hash = root_node.compute_hash();

        // Get write locks for both file_manager and node_index
        let mut file_manager = self
            .file_manager
            .write()
            .map_err(|_| TrieError::LockError)?;
        let mut node_index = self.node_index.write().map_err(|_| TrieError::LockError)?;

        let prev_root_offset = file_manager.read_latest_root_offset()?;
        let base_offset = file_manager.get_file_size()?;

        let serializer = Serializer::new(&node_index, base_offset);
        let (serialized_data, new_offsets, root_offset) =
            serializer.serialize_tree(root_node, prev_root_offset)?;

        file_manager.write_at_end(&serialized_data)?;

        // Update node index with new node offsets
        for (hash, absolute_offset) in new_offsets {
            node_index.insert(hash, absolute_offset);
        }

        // Update header to point to the root node
        file_manager.update_latest_root_offset(root_offset)?;
        Ok(root_hash)
    }

    /// Get the root node at a specific offset
    pub(crate) fn root_at_offset(&self, root_offset: u64) -> Result<Node, TrieError> {
        if root_offset == 0 {
            panic!("No root node at offset");
        }

        let file_manager = self.file_manager.read().map_err(|_| TrieError::LockError)?;
        let file_data = file_manager.get_slice_to_end(0)?;
        // All roots have 8-byte prepended previous root offset
        let actual_root_offset = root_offset + 8;

        Deserializer::new(file_data).decode_node_at(actual_root_offset as usize)
    }

    /// Get the value of a key at a specific root offset
    pub(crate) fn get_at_offset(
        &self,
        key: &[u8],
        root_offset: u64,
    ) -> Result<Option<Vec<u8>>, TrieError> {
        if root_offset == 0 {
            return Ok(None);
        }

        let file_manager = self.file_manager.read().map_err(|_| TrieError::LockError)?;
        let file_data = file_manager.get_slice_to_end(0)?;
        // All roots have 8-byte prepended previous root offset
        let actual_root_offset = root_offset + 8;

        Deserializer::new(file_data).get_by_path_at(key, actual_root_offset as usize)
    }

    /// Begin a new read transaction that captures the current state of the database
    /// The transaction will provide a consistent snapshot view and will not see
    /// any changes committed after the transaction is created
    pub fn begin_read(&self) -> Result<ReadTransaction, TrieError> {
        let snapshot_root_offset = {
            self.file_manager
                .read()
                .map_err(|_| TrieError::LockError)?
                .read_latest_root_offset()?
        };

        // Register the snapshot with the transaction manager
        let tx_id = self
            .transaction_manager
            .lock()
            .map_err(|_| TrieError::LockError)?
            .register_snapshot(snapshot_root_offset);

        Ok(ReadTransaction::new(self, snapshot_root_offset, tx_id))
    }

    /// Unregisters a snapshot from the transaction manager
    /// This is called internally when a transaction is dropped
    pub(crate) fn unregister_snapshot(&self, offset: u64) {
        if let Ok(mut tm) = self.transaction_manager.lock() {
            tm.unregister_snapshot(offset);
        }
    }

    /// Returns the total number of active transactions
    pub fn active_transaction_count(&self) -> usize {
        self.transaction_manager
            .lock()
            .map(|tm| tm.active_transaction_count())
            .unwrap_or(0)
    }

    /// Returns a list of all active snapshot offsets that should not be pruned
    pub fn get_protected_offsets(&self) -> Vec<u64> {
        self.transaction_manager
            .lock()
            .map(|tm| tm.get_active_offsets())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use crate::trie::{InMemoryTrieDB, Trie};

    use super::*;
    use tempdir::TempDir;

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
        assert!(root_hash.as_ref() != [0u8; 32]);
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
        let tx = db.begin_read().unwrap();
        let value = tx.get(b"key").unwrap();
        assert_eq!(value, Some(b"value".to_vec()));
    }

    #[test]
    fn test_get_value() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        // Test getting from empty db
        let tx = db.begin_read().unwrap();
        assert_eq!(tx.get(b"nonexistent").unwrap(), None);
        drop(tx);

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"hello".to_vec(), b"world".to_vec()).unwrap();
        trie.insert(b"foo".to_vec(), b"bar".to_vec()).unwrap();
        trie.insert(b"test".to_vec(), b"value".to_vec()).unwrap();

        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        // Test getting existing values
        let tx = db.begin_read().unwrap();
        assert_eq!(tx.get(b"hello").unwrap(), Some(b"world".to_vec()));
        assert_eq!(tx.get(b"foo").unwrap(), Some(b"bar".to_vec()));
        assert_eq!(tx.get(b"test").unwrap(), Some(b"value".to_vec()));

        // Test getting non-existent value
        assert_eq!(tx.get(b"nonexistent").unwrap(), None);
    }

    #[test]
    fn test_multi_version_trie() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        trie.insert(b"common".to_vec(), b"v1".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        let tx = db.begin_read().unwrap();
        assert_eq!(tx.root().unwrap(), root_node);
        drop(tx);

        trie.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();
        trie.insert(b"common".to_vec(), b"v2".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        let tx = db.begin_read().unwrap();
        assert_eq!(tx.root().unwrap(), root_node);
        drop(tx);

        trie.insert(b"key3".to_vec(), b"value3".to_vec()).unwrap();
        trie.insert(b"common".to_vec(), b"v3".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        let tx = db.begin_read().unwrap();
        assert_eq!(tx.root().unwrap(), root_node);

        assert_eq!(tx.get(b"key3").unwrap(), Some(b"value3".to_vec()));
        assert_eq!(tx.get(b"common").unwrap(), Some(b"v3".to_vec()));
        assert_eq!(tx.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(tx.get(b"key2").unwrap(), Some(b"value2".to_vec()));

        assert_eq!(tx.get(b"nonexistent").unwrap(), None);
    }

    #[test]
    fn test_complex_db_operations() {
        let temp_dir = TempDir::new("ethrex_db_complex_test").unwrap();
        let db_path = temp_dir.path().join("complex_test.edb");

        let test_data_v1 = vec![
            (b"app".to_vec(), b"application_v1".to_vec()),
            (b"apple".to_vec(), b"fruit_v1".to_vec()),
            (b"car".to_vec(), b"vehicle_v1".to_vec()),
            (b"test".to_vec(), b"examination_v1".to_vec()),
            (b"0x123456".to_vec(), b"hex_value_v1".to_vec()),
        ];

        let test_data_v2 = vec![
            (b"app".to_vec(), b"application_v2".to_vec()),
            (b"apple".to_vec(), b"fruit_v2".to_vec()),
            (b"banana".to_vec(), b"fruit_new".to_vec()),
            (b"car".to_vec(), b"vehicle_v2".to_vec()),
            (b"bike".to_vec(), b"vehicle_new".to_vec()), // New
            (b"test".to_vec(), b"examination_v2".to_vec()),
            (b"0x123456".to_vec(), b"hex_value_v2".to_vec()),
            (b"0xabcdef".to_vec(), b"hex_new".to_vec()),
        ];

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        for (key, value) in &test_data_v1 {
            trie.insert(key.clone(), value.clone()).unwrap();
        }
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        for (key, value) in &test_data_v2 {
            trie.insert(key.clone(), value.clone()).unwrap();
        }
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        let tx = db.begin_read().unwrap();
        for (key, expected_value) in &test_data_v2 {
            let result = tx.get(key).unwrap();
            assert_eq!(result, Some(expected_value.clone()));
        }

        assert_eq!(tx.get(b"nonexistent").unwrap(), None);
        drop(tx);

        let complex_test_data = vec![
            (
                b"very_long_key_with_complex_structure_123456789".to_vec(),
                b"complex_value".to_vec(),
            ),
            (b"short".to_vec(), b"val".to_vec()),
            (b"".to_vec(), b"empty_key_value".to_vec()),
        ];

        for (key, value) in &test_data_v2 {
            trie.insert(key.clone(), value.clone()).unwrap();
        }
        for (key, value) in &complex_test_data {
            trie.insert(key.clone(), value.clone()).unwrap();
        }
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        let tx = db.begin_read().unwrap();
        for (key, expected_value) in &complex_test_data {
            let result = tx.get(key).unwrap();
            assert_eq!(result, Some(expected_value.clone()));
        }
    }

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
        let tx = db.begin_read().unwrap();
        assert_eq!(
            tx.root().unwrap(),
            root_node1,
            "DB root must match trie root after batch 1"
        );
        drop(tx);

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
        let tx = db.begin_read().unwrap();
        assert_eq!(
            tx.root().unwrap(),
            root_node2,
            "DB root must match trie root after batch 2"
        );
        drop(tx);

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
        let tx = db.begin_read().unwrap();
        assert_eq!(
            tx.root().unwrap(),
            root_node3,
            "DB root must match trie root after batch 3"
        );
        drop(tx);

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
        let tx = db.begin_read().unwrap();
        assert_eq!(
            tx.root().unwrap(),
            root_node4,
            "DB root must match trie root after batch 4"
        );
        drop(tx);

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
        let tx = db.begin_read().unwrap();
        assert_eq!(
            tx.root().unwrap(),
            root_node5,
            "DB root must match trie root after batch 5"
        );
        drop(tx);

        // Random verification of some accounts
        let tx = db.begin_read().unwrap();
        for batch_num in 1..=5 {
            let test_data = generate_test_data(batch_num * 50);
            if let Some((key, _)) = test_data.get(batch_num * 10) {
                assert_eq!(tx.get(key).unwrap(), trie.get(key).unwrap());
            }
        }
    }

    #[test]
    fn test_file_size() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));

        // Insert 100,000 keys
        for i in 0..100_000 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            trie.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec())
                .unwrap();
        }
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();
        // Check file size after inserting 100,000 keys
        let insert_file_size = std::fs::metadata(db_path.clone()).unwrap().len();

        // Update a single key
        trie.insert(b"key_1".to_vec(), b"updated_value".to_vec())
            .unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();
        // Check file size after updating a single key
        let update_file_size = std::fs::metadata(db_path).unwrap().len();

        // File after update should have a very small increase
        assert!(insert_file_size < update_file_size);
        assert!(update_file_size < insert_file_size + 1000);
    }

    #[test]
    fn test_transaction_integration() {
        let temp_dir = TempDir::new("ethrex_db_tx_integration").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        // Create initial state
        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"account1".to_vec(), b"balance1".to_vec())
            .unwrap();
        trie.insert(b"account2".to_vec(), b"balance2".to_vec())
            .unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        // Test snapshot isolation with scoped transaction
        {
            let read_tx = db.begin_read().unwrap();

            // Verify initial state
            assert_eq!(
                read_tx.get(b"account1").unwrap(),
                Some(b"balance1".to_vec())
            );
            assert_eq!(
                read_tx.get(b"account2").unwrap(),
                Some(b"balance2".to_vec())
            );
            assert_eq!(read_tx.get(b"account3").unwrap(), None);

            // Store snapshot for later
            let snapshot_offset = read_tx.snapshot_offset();

            // End scope to release borrow
            drop(read_tx);

            // Make changes after transaction was created
            trie.insert(b"account1".to_vec(), b"updated_balance1".to_vec())
                .unwrap();
            trie.insert(b"account2".to_vec(), b"updated_balance2".to_vec())
                .unwrap();
            trie.insert(b"account3".to_vec(), b"new_balance3".to_vec())
                .unwrap();
            let root_node2 = trie.root_node().unwrap().unwrap();
            db.commit(&root_node2).unwrap();
            trie.commit().unwrap();

            // Create new transaction using the old snapshot
            let old_read_tx = crate::transaction::ReadTransaction::new(&db, snapshot_offset, 999); // Dummy tx_id for test

            // Verify transaction still sees old data
            assert_eq!(
                old_read_tx.get(b"account1").unwrap(),
                Some(b"balance1".to_vec())
            );
            assert_eq!(
                old_read_tx.get(b"account2").unwrap(),
                Some(b"balance2".to_vec())
            );
            assert_eq!(old_read_tx.get(b"account3").unwrap(), None);

            // But new transaction sees new data
            let new_read_tx = db.begin_read().unwrap();
            assert_eq!(
                new_read_tx.get(b"account1").unwrap(),
                Some(b"updated_balance1".to_vec())
            );
            assert_eq!(
                new_read_tx.get(b"account3").unwrap(),
                Some(b"new_balance3".to_vec())
            );
        }
    }

    #[test]
    fn test_transaction_manager_reference_counting() {
        let temp_dir = TempDir::new("ethrex_db_txmgr_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        // Initially no active transactions
        assert_eq!(db.active_transaction_count(), 0);

        // Create initial state
        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        // Create a transaction - should register snapshot
        let tx1 = db.begin_read().unwrap();
        assert_eq!(db.active_transaction_count(), 1);

        let tx1_offset = tx1.snapshot_offset();

        // Create another transaction at the same snapshot
        let tx2 = db.begin_read().unwrap();
        assert_eq!(db.active_transaction_count(), 2);

        // Drop transactions to allow commit
        drop(tx1);
        drop(tx2);

        // Commit new data and create another transaction
        trie.insert(b"key1".to_vec(), b"value2".to_vec()).unwrap();
        let root_node2 = trie.root_node().unwrap().unwrap();
        db.commit(&root_node2).unwrap();
        trie.commit().unwrap();

        // Check that no transactions are active after dropping
        assert_eq!(db.active_transaction_count(), 0);

        let tx3 = db.begin_read().unwrap();
        assert_eq!(db.active_transaction_count(), 1);

        let tx3_offset = tx3.snapshot_offset();
        assert_ne!(tx1_offset, tx3_offset);

        // Drop transaction
        drop(tx3);
        assert_eq!(db.active_transaction_count(), 0);
    }

    #[test]
    fn test_transaction_manager_info() {
        let temp_dir = TempDir::new("ethrex_db_txmgr_info_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let db = EthrexDB::new(db_path.clone()).unwrap();

        // Create initial state
        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"test".to_vec(), b"data".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        // Create multiple transactions
        let tx1 = db.begin_read().unwrap();
        let tx2 = db.begin_read().unwrap(); // Same snapshot

        // Commit new data
        trie.insert(b"test2".to_vec(), b"data2".to_vec()).unwrap();
        let root_node2 = trie.root_node().unwrap().unwrap();
        db.commit(&root_node2).unwrap();
        trie.commit().unwrap();

        assert_eq!(tx1.get(b"test").unwrap(), Some(b"data".to_vec()));
        assert_eq!(tx1.get(b"test2").unwrap(), None);
        assert_eq!(tx2.get(b"test").unwrap(), Some(b"data".to_vec()));
        assert_eq!(tx2.get(b"test2").unwrap(), None);

        // Create new transaction to test current state
        let tx3 = db.begin_read().unwrap(); // Latest snapshot

        let protected_offsets = db.get_protected_offsets();
        // tx1 and tx2 are protected in the same snapshot
        // tx3 is protected in the new snapshot
        assert_eq!(protected_offsets.len(), 2);

        // Verify transaction works
        assert_eq!(tx3.get(b"test").unwrap(), Some(b"data".to_vec()));
        assert_eq!(tx3.get(b"test2").unwrap(), Some(b"data2".to_vec()));
    }
}
