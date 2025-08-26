use crate::db::EthrexDB;
use crate::transaction_manager::TransactionId;
use crate::trie::{Node, TrieError};

/// A read-only transaction that provides a consistent snapshot view of the database
/// at the time the transaction was created. The transaction is automatically
/// unregistered from the transaction manager when dropped.
pub struct ReadTransaction<'a> {
    /// The root offset captured when the transaction was created
    snapshot_root_offset: u64,
    /// Reference to the database
    db: &'a EthrexDB,
    /// Unique transaction identifier
    tx_id: TransactionId,
}

impl<'a> ReadTransaction<'a> {
    /// Creates a new read transaction with the specified snapshot offset and transaction ID
    pub fn new(db: &'a EthrexDB, snapshot_root_offset: u64, tx_id: TransactionId) -> Self {
        Self {
            snapshot_root_offset,
            db,
            tx_id,
        }
    }

    /// Get the value for a key from this transaction's snapshot
    /// This will always return the value as it existed when the transaction was created,
    /// regardless of any commits that happen after the transaction started
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        self.db.get_at_offset(key, self.snapshot_root_offset)
    }

    /// Get the root node from this transaction's snapshot
    pub fn root(&self) -> Result<Node, TrieError> {
        self.db.root_at_offset(self.snapshot_root_offset)
    }

    /// Get the snapshot offset this transaction is reading from
    pub fn snapshot_offset(&self) -> u64 {
        self.snapshot_root_offset
    }

    /// Get the transaction ID
    pub fn transaction_id(&self) -> TransactionId {
        self.tx_id
    }
}

impl<'a> Drop for ReadTransaction<'a> {
    fn drop(&mut self) {
        // Automatically unregister the snapshot from the transaction manager
        self.db.unregister_snapshot(self.snapshot_root_offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::{InMemoryTrieDB, Trie};
    use tempdir::TempDir;

    #[test]
    fn test_read_transaction_snapshot_isolation() {
        let temp_dir = TempDir::new("ethrex_db_tx_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        // Setup initial state
        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        trie.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        // Create read transaction - captures current snapshot
        {
            let read_tx = db.begin_read().unwrap();

            // Verify transaction can read the initial state
            assert_eq!(read_tx.get(b"key1").unwrap(), Some(b"value1".to_vec()));
            assert_eq!(read_tx.get(b"key2").unwrap(), Some(b"value2".to_vec()));
            assert_eq!(read_tx.get(b"nonexistent").unwrap(), None);

            // Store the snapshot offset to verify later
            let snapshot_offset = read_tx.snapshot_offset();

            // Drop the transaction to release the immutable borrow
            drop(read_tx);

            // Make changes to the database after transaction creation
            trie.insert(b"key1".to_vec(), b"modified_value1".to_vec())
                .unwrap();
            trie.insert(b"key2".to_vec(), b"modified_value2".to_vec())
                .unwrap();
            trie.insert(b"key3".to_vec(), b"new_value3".to_vec())
                .unwrap();
            let root_node2 = trie.root_node().unwrap().unwrap();
            db.commit(&root_node2).unwrap();

            // Create a new transaction with the old snapshot to verify isolation
            let old_tx = ReadTransaction::new(&db, snapshot_offset, 999); // Dummy tx_id for test

            // Transaction should NOT see the new changes - snapshot isolation
            assert_eq!(old_tx.get(b"key1").unwrap(), Some(b"value1".to_vec())); // Still old value
            assert_eq!(old_tx.get(b"key2").unwrap(), Some(b"value2".to_vec())); // Still old value
            assert_eq!(old_tx.get(b"key3").unwrap(), None); // New key not visible

            // But new transaction sees the new values
            let new_tx = db.begin_read().unwrap();
            assert_eq!(
                new_tx.get(b"key1").unwrap(),
                Some(b"modified_value1".to_vec())
            );
            assert_eq!(
                new_tx.get(b"key2").unwrap(),
                Some(b"modified_value2".to_vec())
            );
            assert_eq!(new_tx.get(b"key3").unwrap(), Some(b"new_value3".to_vec()));
        }
    }

    #[test]
    fn test_multiple_read_transactions() {
        let temp_dir = TempDir::new("ethrex_db_multi_tx_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"counter".to_vec(), b"1".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        trie.commit().unwrap();

        let offset1 = db.begin_read().unwrap().snapshot_offset();

        trie.insert(b"counter".to_vec(), b"2".to_vec()).unwrap();
        let root_node2 = trie.root_node().unwrap().unwrap();
        db.commit(&root_node2).unwrap();
        trie.commit().unwrap();

        let offset2 = db.begin_read().unwrap().snapshot_offset();

        trie.insert(b"counter".to_vec(), b"3".to_vec()).unwrap();
        let root_node3 = trie.root_node().unwrap().unwrap();
        db.commit(&root_node3).unwrap();

        // Create transactions for each snapshot
        let tx1 = ReadTransaction::new(&db, offset1, 998); // Dummy tx_id for test
        let tx2 = ReadTransaction::new(&db, offset2, 999); // Dummy tx_id for test

        // Each transaction should see its own snapshot
        assert_eq!(tx1.get(b"counter").unwrap(), Some(b"1".to_vec()));
        assert_eq!(tx2.get(b"counter").unwrap(), Some(b"2".to_vec()));

        // Latest transaction sees current state
        let latest_tx = db.begin_read().unwrap();
        assert_eq!(latest_tx.get(b"counter").unwrap(), Some(b"3".to_vec()));

        // Verify snapshot offsets are different
        assert!(tx1.snapshot_offset() < tx2.snapshot_offset());
    }
}
