//! Incremental serialization with Copy-on-Write optimization
//!
//! ## Core Features:
//! - **Copy-on-Write (CoW)**: Only new/modified nodes are serialized
//! - **Linked List Versioning**: Each root has prepended offset to previous root
//! - **Append-Only Storage**: Data is only added, never overwritten
//! - **Node Reuse**: Existing nodes referenced by offset, not re-serialized
//!
//! ## Two-Node Serialization Format:
//! Instead of standard 3 node types (Branch, Extension, Leaf), we use 2:
//! - **Branch**: 16 children slots + 1 value slot
//! - **Extend**: 1 child slot + 1 value slot (represents both Extension and Leaf)
//!
//! Node type mapping:
//! - Leaf → Extend with value but no child (child_offset = 0)
//! - Extension → Extend with child but no value (value_offset = 0)
//! - Branch → Branch (unchanged)
//!
//! ## File Structure:
//! ```text
//! [header: 8 bytes] -> offset to latest root
//! [commit 1: [prev_root_offset: 8 bytes][root_node][other_nodes]]
//! [commit 2: [prev_root_offset: 8 bytes][root_node][other_nodes]]
//! [commit N: [prev_root_offset: 8 bytes][root_node][other_nodes]]
//! ```

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use crate::trie::{
    BranchNode, ExtensionNode, LeafNode, Nibbles, Node, NodeHash, NodeRef, TrieError,
};

/// Result type for incremental serialization: (serialized_data, new_node_offsets, root_offset)
type SerializationResult = Result<(Vec<u8>, HashMap<NodeHash, u64>, u64), TrieError>;

/// Tag for Branch node (16 children + 1 value)
const TAG_BRANCH: u8 = 0;
/// Tag for Extend node (combines Extension and Leaf)
const TAG_EXTEND: u8 = 1;

/// Serializes a Merkle Patricia Trie into a byte buffer using the two node format
#[derive(Default)]
pub struct Serializer {
    buffer: Vec<u8>,
    node_index: HashMap<NodeHash, u64>,
    new_nodes: HashMap<NodeHash, u64>,
    base_offset: u64,
}

impl Serializer {
    /// Create a new incremental serializer with existing node index
    pub fn new(node_index: &HashMap<NodeHash, u64>, base_offset: u64) -> Self {
        Self {
            buffer: Vec::new(),
            node_index: node_index.clone(),
            new_nodes: HashMap::new(),
            base_offset,
        }
    }

    /// Serializes a trie incrementally, only storing new nodes
    /// Always prepends the previous root offset (0 for first root)
    pub fn serialize_tree(mut self, root: &Node, prev_root_offset: u64) -> SerializationResult {
        // Store where the root structure starts (including prepended offset)
        let root_structure_offset = self.base_offset + self.buffer.len() as u64;

        // Always prepend the previous root offset (0 for first root)
        self.buffer
            .extend_from_slice(&prev_root_offset.to_le_bytes());

        // Serialize the actual root node
        self.serialize_node(root)?;

        // Return the offset to the start of the root structure (with prepended offset)
        Ok((self.buffer, self.new_nodes, root_structure_offset))
    }

    /// Serializes a node, checking CoW first
    fn serialize_node(&mut self, node: &Node) -> Result<u64, TrieError> {
        let hash = node.compute_hash();

        // Check if node already exists (CoW)
        if let Some(&existing_offset) = self.node_index.get(&hash) {
            return Ok(existing_offset);
        }

        // Check if we already serialized this node in this batch
        if let Some(&absolute_offset) = self.new_nodes.get(&hash) {
            return Ok(absolute_offset);
        }

        // Node is new, serialize it
        let buffer_offset = self.buffer.len() as u64;
        let absolute_offset = self.base_offset + buffer_offset;
        self.new_nodes.insert(hash, absolute_offset);

        match node {
            Node::Leaf(leaf) => self.serialize_leaf(leaf)?,
            Node::Extension(ext) => self.serialize_extension(ext)?,
            Node::Branch(branch) => self.serialize_branch(branch)?,
        }

        Ok(absolute_offset)
    }

    fn serialize_leaf(&mut self, leaf: &LeafNode) -> Result<(), TrieError> {
        self.buffer.push(TAG_EXTEND);
        let compact_nibbles = leaf.partial.encode_compact();
        self.write_bytes_with_len(&compact_nibbles);

        // Child offset = 0, value offset will be filled
        self.buffer.extend_from_slice(&0u64.to_le_bytes());
        let value_offset_pos = self.buffer.len();
        self.buffer.extend_from_slice(&0u64.to_le_bytes());

        let value_offset = self.base_offset + self.buffer.len() as u64;
        self.write_bytes_with_len(&leaf.value);

        // Write actual value offset
        self.buffer[value_offset_pos..value_offset_pos + 8]
            .copy_from_slice(&value_offset.to_le_bytes());

        Ok(())
    }

    fn serialize_extension(&mut self, ext: &ExtensionNode) -> Result<(), TrieError> {
        self.buffer.push(TAG_EXTEND);
        let compact_prefix = ext.prefix.encode_compact();
        self.write_bytes_with_len(&compact_prefix);

        // Child offset will be filled, value offset = 0
        let child_offset_pos = self.buffer.len();
        self.buffer.extend_from_slice(&0u64.to_le_bytes());
        self.buffer.extend_from_slice(&0u64.to_le_bytes());

        let child_offset = self.serialize_noderef(&ext.child)?;

        // Write actual child offset
        self.buffer[child_offset_pos..child_offset_pos + 8]
            .copy_from_slice(&child_offset.to_le_bytes());

        Ok(())
    }

    fn serialize_branch(&mut self, branch: &BranchNode) -> Result<(), TrieError> {
        self.buffer.push(TAG_BRANCH);

        // Reserve space for 16 child offsets + 1 value offset
        let offsets_start = self.buffer.len();
        for _ in 0..17 {
            self.buffer.extend_from_slice(&0u64.to_le_bytes());
        }

        // Serialize children
        let mut child_offsets = [0u64; 16];
        for (i, child) in branch.choices.iter().enumerate() {
            child_offsets[i] = self.serialize_noderef(child)?;
        }

        // Serialize value
        let value_offset = if branch.value.is_empty() {
            0u64
        } else {
            let offset = self.base_offset + self.buffer.len() as u64;
            self.write_bytes_with_len(&branch.value);
            offset
        };

        // Write all offsets
        let mut pos = offsets_start;
        for &child_offset in &child_offsets {
            self.buffer[pos..pos + 8].copy_from_slice(&child_offset.to_le_bytes());
            pos += 8;
        }
        self.buffer[pos..pos + 8].copy_from_slice(&value_offset.to_le_bytes());

        Ok(())
    }

    fn serialize_noderef(&mut self, noderef: &NodeRef) -> Result<u64, TrieError> {
        match noderef {
            NodeRef::Hash(hash) if hash.is_valid() => {
                self.node_index.get(hash).copied().ok_or_else(|| {
                    TrieError::Other(format!("Hash reference not found: {:?}", hash))
                })
            }
            NodeRef::Hash(_) => Ok(0), // Empty/invalid hash
            NodeRef::Node(node, _) => self.serialize_node(node),
        }
    }

    fn write_bytes_with_len(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u32;
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(bytes);
    }
}

/// Deserializes a Merkle Patricia Trie from a byte buffer.
pub struct Deserializer<'a> {
    buffer: &'a [u8],
}

impl<'a> Deserializer<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    /// Decodes a node at specific position
    pub fn decode_node_at(&self, pos: usize) -> Result<Node, TrieError> {
        if pos >= self.buffer.len() {
            return Err(TrieError::Other("Invalid buffer position".to_string()));
        }

        let tag = self.buffer[pos];
        let mut position = pos + 1;

        match tag {
            TAG_EXTEND => {
                let len = self.read_u32_at(position)? as usize;
                position += 4;

                let compact_nibbles = &self.buffer[position..position + len];
                let nibbles = Nibbles::decode_compact(compact_nibbles);
                position += len;

                let node_offset = self.read_u64_at(position)?;
                position += 8;
                let value_offset = self.read_u64_at(position)?;

                match (node_offset > 0, value_offset > 0) {
                    (false, true) => {
                        // Leaf node
                        let value = self
                            .read_value_at_offset(value_offset as usize)?
                            .unwrap_or_default();
                        Ok(Node::Leaf(LeafNode::new(nibbles, value)))
                    }
                    (true, false) => {
                        // Extension node
                        let child = self.decode_node_at(node_offset as usize)?;
                        Ok(Node::Extension(ExtensionNode::new(
                            nibbles,
                            NodeRef::Node(Arc::new(child), OnceLock::new()),
                        )))
                    }
                    _ => Err(TrieError::Other("Invalid Extend node".to_string())),
                }
            }
            TAG_BRANCH => {
                // Read 16 child offsets
                let mut child_offsets = [0u64; 16];
                for child in child_offsets.iter_mut() {
                    *child = self.read_u64_at(position)?;
                    position += 8;
                }
                let value_offset = self.read_u64_at(position)?;

                // Build children
                let mut children: [NodeRef; 16] = Default::default();
                for (i, &offset) in child_offsets.iter().enumerate() {
                    if offset > 0 {
                        let child = self.decode_node_at(offset as usize)?;
                        children[i] = NodeRef::Node(Arc::new(child), OnceLock::new());
                    }
                }

                // Read value
                let value = if value_offset > 0 {
                    self.read_value_at_offset(value_offset as usize)?
                        .unwrap_or_default()
                } else {
                    vec![]
                };

                Ok(Node::Branch(Box::new(BranchNode::new_with_value(
                    children, value,
                ))))
            }
            _ => Err(TrieError::Other(format!("Invalid node tag: {}", tag))),
        }
    }

    /// Gets a value by path starting at a specific offset
    pub fn get_by_path_at(&self, path: &[u8], offset: usize) -> Result<Option<Vec<u8>>, TrieError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        let nibbles = Nibbles::from_raw(path, false);
        self.get_by_path_inner(nibbles, offset)
    }

    fn get_by_path_inner(
        &self,
        mut path: Nibbles,
        pos: usize,
    ) -> Result<Option<Vec<u8>>, TrieError> {
        if pos >= self.buffer.len() {
            return Ok(None);
        }

        let tag = self.buffer[pos];
        let mut position = pos + 1;

        match tag {
            TAG_EXTEND => {
                let len =
                    u32::from_le_bytes(self.buffer[position..position + 4].try_into().unwrap())
                        as usize;
                position += 4;

                let compact_nibbles = &self.buffer[position..position + len];
                let nibbles = Nibbles::decode_compact(compact_nibbles);
                position += len;

                let node_offset =
                    u64::from_le_bytes(self.buffer[position..position + 8].try_into().unwrap());
                position += 8;
                let value_offset =
                    u64::from_le_bytes(self.buffer[position..position + 8].try_into().unwrap());

                if node_offset == 0 && value_offset > 0 {
                    // Leaf node
                    let leaf_path = if nibbles.is_leaf() {
                        nibbles.slice(0, nibbles.len() - 1)
                    } else {
                        nibbles
                    };

                    if path == leaf_path {
                        self.read_value_at_offset(value_offset as usize)
                    } else {
                        Ok(None)
                    }
                } else if node_offset > 0 && value_offset == 0 {
                    // Extension node
                    if !path.skip_prefix(&nibbles) {
                        return Ok(None);
                    }
                    self.get_by_path_inner(path, node_offset as usize)
                } else {
                    Ok(None)
                }
            }
            TAG_BRANCH => {
                if path.is_empty() {
                    // Skip 16 child offsets
                    position += 16 * 8;
                    let value_offset =
                        u64::from_le_bytes(self.buffer[position..position + 8].try_into().unwrap());

                    if value_offset > 0 {
                        self.read_value_at_offset(value_offset as usize)
                    } else {
                        Ok(None)
                    }
                } else {
                    let next_nibble = path
                        .next_choice()
                        .ok_or_else(|| TrieError::Other("Invalid path".to_string()))?;
                    let child_offset_pos = position + next_nibble * 8;
                    let child_offset = u64::from_le_bytes(
                        self.buffer[child_offset_pos..child_offset_pos + 8]
                            .try_into()
                            .unwrap(),
                    );

                    if child_offset > 0 {
                        self.get_by_path_inner(path, child_offset as usize)
                    } else {
                        Ok(None)
                    }
                }
            }
            _ => Err(TrieError::Other(format!("Invalid node tag: {}", tag))),
        }
    }

    fn read_value_at_offset(&self, offset: usize) -> Result<Option<Vec<u8>>, TrieError> {
        if offset + 4 > self.buffer.len() {
            return Ok(None);
        }

        let len = u32::from_le_bytes(self.buffer[offset..offset + 4].try_into().unwrap()) as usize;
        let data_start = offset + 4;

        if data_start + len > self.buffer.len() {
            return Ok(None);
        }

        let value = self.buffer[data_start..data_start + len].to_vec();
        Ok(Some(value))
    }

    fn read_u64_at(&self, pos: usize) -> Result<u64, TrieError> {
        if pos + 8 > self.buffer.len() {
            return Err(TrieError::Other("Invalid buffer length".to_string()));
        }
        Ok(u64::from_le_bytes(
            self.buffer[pos..pos + 8].try_into().unwrap(),
        ))
    }

    fn read_u32_at(&self, pos: usize) -> Result<u32, TrieError> {
        if pos + 4 > self.buffer.len() {
            return Err(TrieError::Other("Invalid buffer length".to_string()));
        }
        Ok(u32::from_le_bytes(
            self.buffer[pos..pos + 4].try_into().unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::{InMemoryTrieDB, Trie, node_hash::NodeHash};

    /// Offset to skip the prepended previous root offset (8 bytes)
    const ROOT_DATA_OFFSET: usize = 8;

    fn new_temp() -> Trie {
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::sync::Mutex;

        let hmap: HashMap<NodeHash, Vec<u8>> = HashMap::new();
        let map = Arc::new(Mutex::new(hmap));
        let db = InMemoryTrieDB::new(map);
        Trie::new(Box::new(db))
    }

    #[test]
    fn test_serialize_leaf() {
        let leaf = Node::Leaf(LeafNode {
            partial: Nibbles::from_hex(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]),
            value: b"long_path_value".to_vec(),
        });

        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&leaf, 0).unwrap();

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(leaf, recovered);
    }

    #[test]
    fn test_serialize_deserialize_branch_empty() {
        let branch = Node::Branch(Box::new(BranchNode {
            choices: Default::default(),
            value: vec![],
        }));

        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&branch, 0).unwrap();

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(branch, recovered);
    }

    #[test]
    fn test_serialize_deserialize_tree_extension_to_leaf() {
        let leaf = Node::Leaf(LeafNode {
            partial: Nibbles::from_hex(vec![5, 6, 7]),
            value: b"nested_leaf".to_vec(),
        });

        let ext = Node::Extension(ExtensionNode {
            prefix: Nibbles::from_hex(vec![1, 2]),
            child: NodeRef::Node(Arc::new(leaf), OnceLock::new()),
        });

        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&ext, 0).unwrap();

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(recovered, ext);
        match recovered {
            Node::Extension(ext_node) => {
                assert_eq!(ext_node.prefix, Nibbles::from_hex(vec![1, 2]));
                match &ext_node.child {
                    NodeRef::Node(arc_node, _) => match &**arc_node {
                        Node::Leaf(leaf_node) => {
                            assert_eq!(leaf_node.partial, Nibbles::from_hex(vec![5, 6, 7]));
                            assert_eq!(leaf_node.value, b"nested_leaf");
                        }
                        _ => panic!("Expected leaf node"),
                    },
                    _ => panic!("Expected embedded node"),
                }
            }
            _ => panic!("Expected extension node"),
        }
    }

    #[test]
    fn test_serialize_deserialize_deep_tree() {
        let leaf = Node::Leaf(LeafNode {
            partial: Nibbles::from_hex(vec![9, 8]),
            value: b"deep_leaf".to_vec(),
        });

        let inner_ext = Node::Extension(ExtensionNode {
            prefix: Nibbles::from_hex(vec![5, 6]),
            child: NodeRef::Node(Arc::new(leaf), OnceLock::new()),
        });

        let mut branch_choices: [NodeRef; 16] = Default::default();
        branch_choices[2] = NodeRef::Node(Arc::new(inner_ext), OnceLock::new());

        let branch = Node::Branch(Box::new(BranchNode {
            choices: branch_choices,
            value: vec![],
        }));

        let outer_ext = Node::Extension(ExtensionNode {
            prefix: Nibbles::from_hex(vec![1, 2, 3]),
            child: NodeRef::Node(Arc::new(branch), OnceLock::new()),
        });

        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&outer_ext, 0).unwrap();

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(recovered, outer_ext);
    }

    #[test]
    fn test_trie_serialization_empty() {
        let trie = new_temp();
        let root = trie.root_node().unwrap();
        assert!(root.is_none());
    }

    #[test]
    fn test_trie_serialization_single_insert() {
        let mut trie = new_temp();
        trie.insert(b"key".to_vec(), b"value".to_vec()).unwrap();

        let root = trie.root_node().unwrap().unwrap();
        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&root, 0).unwrap();
        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(root, recovered);
    }

    #[test]
    fn test_trie_serialization_multiple_inserts() {
        let mut trie = new_temp();

        let test_data = vec![
            (b"do".to_vec(), b"verb".to_vec()),
            (b"dog".to_vec(), b"puppy".to_vec()),
            (b"doge".to_vec(), b"coin".to_vec()),
            (b"horse".to_vec(), b"stallion".to_vec()),
        ];

        for (key, value) in &test_data {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        let root = trie.root_node().unwrap().unwrap();
        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&root, 0).unwrap();
        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(recovered, root);
    }

    #[test]
    fn test_file_io() {
        use std::fs;

        // Create trie
        let mut trie = new_temp();
        trie.insert(b"file_key".to_vec(), b"file_value".to_vec())
            .unwrap();

        // Serialize to file
        let root = trie.root_node().unwrap().unwrap();
        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&root, 0).unwrap();

        let path = "/tmp/test_trie.mpt";
        fs::write(path, &buffer).unwrap();

        // Read from file and deserialize
        let read_data = fs::read(path).unwrap();
        let deserializer = Deserializer::new(&read_data);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(root, recovered);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_get_by_path_serialized_simple() {
        let mut trie = new_temp();
        trie.insert(b"test".to_vec(), b"value".to_vec()).unwrap();

        let root = trie.root_node().unwrap().unwrap();
        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&root, 0).unwrap();

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(
            deserializer
                .get_by_path_at(b"test", ROOT_DATA_OFFSET)
                .unwrap(),
            Some(b"value".to_vec())
        );

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();
        assert_eq!(root, recovered);
    }

    #[test]
    fn test_get_by_path_serialized() {
        let mut trie = new_temp();

        let test_data = vec![
            (b"do".to_vec(), b"verb".to_vec()),
            (b"dog".to_vec(), b"puppy".to_vec()),
            (b"doge".to_vec(), b"coin".to_vec()),
            (b"horse".to_vec(), b"stallion".to_vec()),
        ];

        for (key, value) in &test_data {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        let root = trie.root_node().unwrap().unwrap();
        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&root, 0).unwrap();

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(
            deserializer
                .get_by_path_at(b"horse", ROOT_DATA_OFFSET)
                .unwrap(),
            Some(b"stallion".to_vec())
        );
        assert_eq!(
            deserializer
                .get_by_path_at(b"dog", ROOT_DATA_OFFSET)
                .unwrap(),
            Some(b"puppy".to_vec())
        );
        assert_eq!(
            deserializer
                .get_by_path_at(b"doge", ROOT_DATA_OFFSET)
                .unwrap(),
            Some(b"coin".to_vec())
        );
        assert_eq!(
            deserializer
                .get_by_path_at(b"do", ROOT_DATA_OFFSET)
                .unwrap(),
            Some(b"verb".to_vec())
        );
        assert_eq!(
            deserializer
                .get_by_path_at(b"cat", ROOT_DATA_OFFSET)
                .unwrap(),
            None
        );

        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();
        assert_eq!(root, recovered);
    }

    #[test]
    fn test_complex_trie_serialization() {
        let mut trie = new_temp();

        let test_data = vec![
            (b"app".to_vec(), b"application".to_vec()),
            (b"apple".to_vec(), b"fruit".to_vec()),
            (b"application".to_vec(), b"software".to_vec()),
            (b"append".to_vec(), b"add_to_end".to_vec()),
            (b"applied".to_vec(), b"past_tense".to_vec()),
            (b"car".to_vec(), b"vehicle".to_vec()),
            (b"card".to_vec(), b"playing_card".to_vec()),
            (b"care".to_vec(), b"attention".to_vec()),
            (b"career".to_vec(), b"profession".to_vec()),
            (b"careful".to_vec(), b"cautious".to_vec()),
            (b"test".to_vec(), b"examination".to_vec()),
            (b"testing".to_vec(), b"verification".to_vec()),
            (b"tester".to_vec(), b"one_who_tests".to_vec()),
            (b"testament".to_vec(), b"will_document".to_vec()),
            (b"a".to_vec(), b"letter_a".to_vec()),
            (b"b".to_vec(), b"letter_b".to_vec()),
            (b"c".to_vec(), b"letter_c".to_vec()),
            (b"d".to_vec(), b"letter_d".to_vec()),
            (b"e".to_vec(), b"letter_e".to_vec()),
            (b"0x123456".to_vec(), b"hex_value_1".to_vec()),
            (b"0x123abc".to_vec(), b"hex_value_2".to_vec()),
            (b"0x124000".to_vec(), b"hex_value_3".to_vec()),
            (b"0xabcdef".to_vec(), b"hex_value_4".to_vec()),
            (
                b"very_long_key_that_creates_deep_structure_in_trie_1234567890".to_vec(),
                b"long_value_1".to_vec(),
            ),
            (
                b"very_long_key_that_creates_deep_structure_in_trie_abcdefghijk".to_vec(),
                b"long_value_2".to_vec(),
            ),
            (b"empty_value_key".to_vec(), vec![]),
            (b"similar_key_1".to_vec(), b"value_1".to_vec()),
            (b"similar_key_2".to_vec(), b"value_2".to_vec()),
            (b"similar_key_3".to_vec(), b"value_3".to_vec()),
            (b"123".to_vec(), b"number_123".to_vec()),
            (b"1234".to_vec(), b"number_1234".to_vec()),
            (b"12345".to_vec(), b"number_12345".to_vec()),
        ];

        for (key, value) in &test_data {
            trie.insert(key.clone(), value.clone()).unwrap();
        }

        let root = trie.root_node().unwrap().unwrap();

        let serializer = Serializer::new(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree(&root, 0).unwrap();

        for (key, expected_value) in &test_data {
            let deserializer = Deserializer::new(&buffer);
            let retrieved_value = deserializer.get_by_path_at(key, ROOT_DATA_OFFSET).unwrap();
            assert_eq!(retrieved_value, Some(expected_value.clone()));
        }

        let non_existent_keys = vec![
            b"nonexistent".to_vec(),
            b"app_wrong".to_vec(),
            b"car_wrong".to_vec(),
            b"test_wrong".to_vec(),
            b"0x999999".to_vec(),
            b"similar_key_4".to_vec(),
            b"".to_vec(),
            b"very_long_nonexistent_key".to_vec(),
        ];

        for key in &non_existent_keys {
            let deserializer = Deserializer::new(&buffer);
            let result = deserializer.get_by_path_at(key, ROOT_DATA_OFFSET).unwrap();
            assert_eq!(result, None);
        }

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(ROOT_DATA_OFFSET).unwrap();

        assert_eq!(root, recovered);
    }
}
