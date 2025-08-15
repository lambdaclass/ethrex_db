//! EthrexDB - A simple MPT database

use crate::file_manager::FileManager;
use crate::serialization::{Deserializer, serialize};
use crate::trie::{TrieError, Node, NodeHash};
use std::path::PathBuf;

/// Ethrex DB struct
pub struct EthrexDB {
    /// File manager
    file_manager: FileManager,
}

impl EthrexDB {
    /// Create a new database
    pub fn new(file_path: PathBuf) -> Result<Self, TrieError> {
        let file_manager = FileManager::create(file_path)?;
        Ok(Self { file_manager })
    }

    /// Open an existing database
    pub fn open(file_path: PathBuf) -> Result<Self, TrieError> {
        let file_manager = FileManager::open(file_path)?;
        Ok(Self { file_manager })
    }

    /// Commit a new trie to the database
    ///
    /// Creates a new version in the database by:
    /// 1. Reading the current latest version offset from header
    /// 2. Serializing the trie nodes
    /// 3. Writing [previous_offset][serialized_nodes] at the end of file
    /// 4. Updating the header to point to this new version
    ///
    /// NOTE: Right now, we are storing the complete trie in the database. We should
    /// store only the root node and the updated nodes.
    pub fn commit(&mut self, root_node: &Node) -> Result<NodeHash, TrieError> {
        let root_hash = root_node.compute_hash();

        // Read the previous root offset from header
        let previous_root_offset = self.file_manager.read_latest_root_offset()?;

        let serialized_trie = serialize(root_node);

        // Prepare version data: [prev_offset(8 bytes)] + [trie_data]
        let mut data_to_write = Vec::with_capacity(8 + serialized_trie.len());
        data_to_write.extend_from_slice(&previous_root_offset.to_le_bytes());
        data_to_write.extend_from_slice(&serialized_trie);

        // Write at the end and get the offset where this version starts
        let new_root_offset = self.file_manager.write_at_end(&data_to_write)?;

        // Update header to point to this new version
        self.file_manager
            .update_latest_root_offset(new_root_offset)?;

        Ok(root_hash)
    }

    /// Get the latest root node of the database
    pub fn root(&self) -> Result<Node, TrieError> {
        let latest_offset = self.file_manager.read_latest_root_offset()?;
        let trie_data = self.get_trie_data_at_version(latest_offset)?;
        let root_node = Deserializer::new(trie_data).decode_tree()?;
        Ok(root_node)
    }

    /// Get the value of the node with the given key
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        let latest_offset = self.file_manager.read_latest_root_offset()?;
        self.get_at_version(key, latest_offset)
    }

    /// Get the value of the node with the given key at a specific version
    pub fn get_at_version(
        &self,
        key: &[u8],
        version_offset: u64,
    ) -> Result<Option<Vec<u8>>, TrieError> {
        if version_offset == 0 {
            return Ok(None);
        }

        let trie_data = self.get_trie_data_at_version(version_offset)?;

        Deserializer::new(trie_data).get_by_path(key)
    }

    /// Get all the roots of the database
    /// TODO: Make this an iterator
    pub fn iter_roots(&self) -> Result<Vec<Node>, TrieError> {
        let mut roots = Vec::new();
        let mut current_offset = self.file_manager.read_latest_root_offset()?;

        while current_offset != 0 {
            let trie_data = self.get_trie_data_at_version(current_offset)?;

            // Deserialize the trie at this version
            let root_node = Deserializer::new(trie_data).decode_tree()?;
            roots.push(root_node);
            current_offset = self.read_previous_offset_at_version(current_offset)?;
        }

        Ok(roots)
    }

    /// Get trie data slice at a specific version
    ///
    /// Each version has format: [prev_offset: 8 bytes][trie_data]
    /// This function skips the prev_offset and returns only the trie_data portion
    fn get_trie_data_at_version(&self, version_offset: u64) -> Result<&[u8], TrieError> {
        // Skip the previous offset (8 bytes) to get to the trie data
        let trie_data_start = version_offset + 8;
        let next_version_offset = self.find_next_version_offset(version_offset)?;

        match next_version_offset {
            Some(next_offset) => {
                let size = (next_offset - trie_data_start) as usize;
                self.file_manager.get_slice_at(trie_data_start, size)
            }
            None => {
                // Last version, read until the end
                self.file_manager.get_slice_to_end(trie_data_start)
            }
        }
    }

    /// Read the previous offset at a specific version
    fn read_previous_offset_at_version(&self, version_offset: u64) -> Result<u64, TrieError> {
        let prev_offset_slice = self.file_manager.get_slice_at(version_offset, 8)?;
        Ok(u64::from_le_bytes([
            prev_offset_slice[0],
            prev_offset_slice[1],
            prev_offset_slice[2],
            prev_offset_slice[3],
            prev_offset_slice[4],
            prev_offset_slice[5],
            prev_offset_slice[6],
            prev_offset_slice[7],
        ]))
    }

    /// Find the offset of the next version after the given offset
    fn find_next_version_offset(&self, current_offset: u64) -> Result<Option<u64>, TrieError> {
        let mut offsets = Vec::new();
        let mut offset = self.file_manager.read_latest_root_offset()?;

        // Collect all version offsets by following the linked list
        while offset != 0 {
            offsets.push(offset);
            offset = self.read_previous_offset_at_version(offset)?;
        }

        // Find the next offset greater than the current offset
        Ok(offsets.into_iter().find(|&o| o > current_offset))
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
    fn test_multi_version_trie() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");

        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        trie.insert(b"common".to_vec(), b"v1".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        // Note: We can't call trie.commit() because it converts NodeRef::Node to NodeRef::Hash
        // and our serialization doesn't support hash references yet
        // trie.commit().unwrap();

        assert_eq!(db.root().unwrap(), root_node);

        // let mut trie2 = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        trie.insert(b"key2".to_vec(), b"value2".to_vec()).unwrap();
        trie.insert(b"common".to_vec(), b"v2".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        // Note: We can't call trie.commit() because it converts NodeRef::Node to NodeRef::Hash
        // and our serialization doesn't support hash references yet
        // trie.commit().unwrap();

        assert_eq!(db.root().unwrap(), root_node);

        trie.insert(b"key3".to_vec(), b"value3".to_vec()).unwrap();
        trie.insert(b"common".to_vec(), b"v3".to_vec()).unwrap();
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        // Note: We can't call trie.commit() because it converts NodeRef::Node to NodeRef::Hash
        // and our serialization doesn't support hash references yet
        // trie.commit().unwrap();

        assert_eq!(db.root().unwrap(), root_node);

        assert_eq!(db.get(b"key3").unwrap(), Some(b"value3".to_vec()));
        assert_eq!(db.get(b"common").unwrap(), Some(b"v3".to_vec()));
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(b"key2").unwrap(), Some(b"value2".to_vec()));

        assert_eq!(db.get(b"nonexistent").unwrap(), None);
        assert_eq!(db.iter_roots().unwrap().len(), 3);
    }

    #[test]
    fn test_iter_roots() {
        let temp_dir = TempDir::new("ethrex_db_test").unwrap();
        let db_path = temp_dir.path().join("test.edb");
        let mut db = EthrexDB::new(db_path.clone()).unwrap();

        // Empty DB should have no roots
        let roots: Vec<Node> = db.iter_roots().unwrap();
        assert_eq!(roots.len(), 0);

        for i in 1..=3 {
            let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
            trie.insert(
                format!("key{}", i).into_bytes(),
                format!("value{}", i).into_bytes(),
            )
            .unwrap();
            let root_node = trie.root_node().unwrap().unwrap();
            db.commit(&root_node).unwrap();
        }

        let roots: Vec<Node> = db.iter_roots().unwrap();
        assert_eq!(roots.len(), 3);

        for root in &roots {
            root.compute_hash();
        }
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

        let mut trie_v1 = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        for (key, value) in &test_data_v1 {
            trie_v1.insert(key.clone(), value.clone()).unwrap();
        }
        let root_node = trie_v1.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        let mut trie_v2 = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        for (key, value) in &test_data_v2 {
            trie_v2.insert(key.clone(), value.clone()).unwrap();
        }
        let root_node = trie_v2.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        for (key, expected_value) in &test_data_v2 {
            let result = db.get(key).unwrap();
            assert_eq!(result, Some(expected_value.clone()));
        }

        assert_eq!(db.get(b"nonexistent").unwrap(), None);

        let complex_test_data = vec![
            (
                b"very_long_key_with_complex_structure_123456789".to_vec(),
                b"complex_value".to_vec(),
            ),
            (b"short".to_vec(), b"val".to_vec()),
            (b"".to_vec(), b"empty_key_value".to_vec()),
        ];

        let mut trie_v3 = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
        for (key, value) in &test_data_v2 {
            trie_v3.insert(key.clone(), value.clone()).unwrap();
        }
        for (key, value) in &complex_test_data {
            trie_v3.insert(key.clone(), value.clone()).unwrap();
        }
        let root_node = trie_v3.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();

        for (key, expected_value) in &complex_test_data {
            let result = db.get(key).unwrap();
            assert_eq!(result, Some(expected_value.clone()));
        }

        let roots: Vec<Node> = db.iter_roots().unwrap();
        assert_eq!(roots.len(), 3);

        for root in roots.iter() {
            root.compute_hash();
        }
    }
}
