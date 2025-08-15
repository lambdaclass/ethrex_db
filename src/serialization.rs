//! Serialization and deserialization of the trie
//!
//! Two-node serialization format:
//! Instead of the standard 3 node types (Branch, Extension, Leaf), we use 2:
//! - Branch: Has 16 children slots + 1 value slot
//! - Extend: Has 1 child slot + 1 value slot (can represent both Extension and Leaf)
//!
//! This simplifies serialization:
//! - Leaf -> Extend with value but no child (child_offset = 0)
//! - Extension -> Extend with child but no value (value_offset = 0)
//! - Branch -> Branch (unchanged)

use std::sync::{Arc, OnceLock};

use crate::trie::{
    branch::BranchNode,
    error::TrieError,
    extension::ExtensionNode,
    leaf::LeafNode,
    nibbles::Nibbles,
    node::{Node, NodeRef},
};

/// Tag for Branch node (16 children + 1 value)
const TAG_BRANCH: u8 = 0;
/// Tag for Extend node (combines Extension and Leaf)
const TAG_EXTEND: u8 = 1;

/// Serializes a Merkle Patricia Trie into a byte buffer using the two node format
///
/// - Branch: 16 node offsets + 1 value offset
/// - Extend: 1 node offset + 1 value offset (combines Extension and Leaf)
#[derive(Default)]
pub struct Serializer {
    /// Buffer where serialized data is accumulated
    buffer: Vec<u8>,
}

impl Serializer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializes a trie using the two node format
    pub fn serialize_tree(mut self, root: &Node) -> Result<Vec<u8>, TrieError> {
        self.serialize_node(root)?;
        Ok(self.buffer)
    }

    /// Serializes a node, converting from 3 node to 2 node system
    fn serialize_node(&mut self, node: &Node) -> Result<u64, TrieError> {
        let offset = self.buffer.len() as u64;

        match node {
            Node::Leaf(leaf) => {
                // Leaf becomes Extend with only value
                self.buffer.push(TAG_EXTEND);

                let compact_nibbles = leaf.partial.encode_compact();
                self.write_bytes_with_len(&compact_nibbles);

                // Reserve space for offsets
                let value_offset_pos = self.buffer.len();
                self.buffer.extend_from_slice(&0u64.to_le_bytes()); // node offset = 0
                self.buffer.extend_from_slice(&0u64.to_le_bytes()); // value offset placeholder

                let value_offset = self.buffer.len() as u64;
                self.write_bytes_with_len(&leaf.value);

                // Go back and write the actual value offset
                self.buffer[value_offset_pos + 8..value_offset_pos + 16]
                    .copy_from_slice(&value_offset.to_le_bytes());

                Ok(offset)
            }
            Node::Extension(ext) => {
                // Extension becomes Extend with only child
                self.buffer.push(TAG_EXTEND);

                let compact_prefix = ext.prefix.encode_compact();
                self.write_bytes_with_len(&compact_prefix);

                // Reserve space for offsets
                let child_offset_pos = self.buffer.len();
                self.buffer.extend_from_slice(&0u64.to_le_bytes()); // child offset placeholder
                self.buffer.extend_from_slice(&0u64.to_le_bytes()); // value offset = 0

                let child_offset = match &ext.child {
                    NodeRef::Hash(hash) => {
                        if hash.is_valid() {
                            panic!("Hash references not supported in serialization");
                        }
                        0u64 // Empty child
                    }
                    NodeRef::Node(node, _) => self.serialize_node(node)?,
                };

                // Go back and write the actual child offset
                if child_offset > 0 {
                    self.buffer[child_offset_pos..child_offset_pos + 8]
                        .copy_from_slice(&child_offset.to_le_bytes());
                }

                Ok(offset)
            }
            Node::Branch(branch) => {
                // Branch stays Branch but with offsets
                self.buffer.push(TAG_BRANCH);

                // Reserve space for all offsets
                let offsets_start = self.buffer.len();
                // 16 child offsets + 1 value offset
                for _ in 0..17 {
                    self.buffer.extend_from_slice(&0u64.to_le_bytes());
                }

                // Serialize all children and collect their offsets
                let mut child_offsets = [0u64; 16];
                for (i, child) in branch.choices.iter().enumerate() {
                    child_offsets[i] = match child {
                        NodeRef::Hash(hash) => {
                            if hash.is_valid() {
                                panic!("Hash references not supported in serialization");
                            }
                            0u64
                        }
                        NodeRef::Node(node, _) => self.serialize_node(node)?,
                    };
                }

                // Serialize value if present
                let value_offset = if branch.value.is_empty() {
                    0u64
                } else {
                    let offset = self.buffer.len() as u64;
                    self.write_bytes_with_len(&branch.value);
                    offset
                };

                // Go back and write all the actual offsets
                let mut pos = offsets_start;
                for &child_offset in &child_offsets {
                    self.buffer[pos..pos + 8].copy_from_slice(&child_offset.to_le_bytes());
                    pos += 8;
                }
                self.buffer[pos..pos + 8].copy_from_slice(&value_offset.to_le_bytes());

                Ok(offset)
            }
        }
    }

    fn write_bytes_with_len(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u32;
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(bytes);
    }
}

/// Deserializes a Merkle Patricia Trie from a byte buffer.
///
/// The deserializer reads the binary format produced by [`Serializer`].
/// It uses the two node format and converts back to the standard 3 node format.
pub struct Deserializer<'a> {
    /// The byte buffer containing serialized trie data
    buffer: &'a [u8],
}

impl<'a> Deserializer<'a> {
    /// Creates a new deserializer for the given buffer
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    /// Deserializes a tree from the two node format back to standard 3 node format
    pub fn decode_tree(&self) -> Result<Node, TrieError> {
        let node = self.decode_node_at(0)?;
        node.compute_hash();
        Ok(node)
    }

    /// Decodes a node from the two node format at specific position
    fn decode_node_at(&self, pos: usize) -> Result<Node, TrieError> {
        if pos >= self.buffer.len() {
            panic!("Invalid buffer position");
        }

        let tag = self.buffer[pos];
        let mut position = pos + 1;

        match tag {
            TAG_EXTEND => {
                // Read nibbles length
                if position + 4 > self.buffer.len() {
                    panic!("Invalid buffer length");
                }
                let len = u32::from_le_bytes([
                    self.buffer[position],
                    self.buffer[position + 1],
                    self.buffer[position + 2],
                    self.buffer[position + 3],
                ]) as usize;
                position += 4;

                // Read nibbles
                if position + len > self.buffer.len() {
                    panic!("Invalid buffer length");
                }
                let compact_nibbles = &self.buffer[position..position + len];
                let nibbles = Nibbles::decode_compact(compact_nibbles);
                position += len;

                // Read node offset
                if position + 8 > self.buffer.len() {
                    panic!("Invalid buffer length");
                }
                let node_offset = u64::from_le_bytes([
                    self.buffer[position],
                    self.buffer[position + 1],
                    self.buffer[position + 2],
                    self.buffer[position + 3],
                    self.buffer[position + 4],
                    self.buffer[position + 5],
                    self.buffer[position + 6],
                    self.buffer[position + 7],
                ]);
                position += 8;

                // Read value offset
                if position + 8 > self.buffer.len() {
                    panic!("Invalid buffer length");
                }
                let value_offset = u64::from_le_bytes([
                    self.buffer[position],
                    self.buffer[position + 1],
                    self.buffer[position + 2],
                    self.buffer[position + 3],
                    self.buffer[position + 4],
                    self.buffer[position + 5],
                    self.buffer[position + 6],
                    self.buffer[position + 7],
                ]);

                // Determine node type based on what's present
                match (node_offset > 0, value_offset > 0) {
                    (false, true) => {
                        // Only value = Leaf node
                        let value = self
                            .read_value_at_offset(value_offset as usize)?
                            .unwrap_or_default();
                        Ok(Node::Leaf(LeafNode::new(nibbles, value)))
                    }
                    (true, false) => {
                        // Only child = Extension node
                        let child = self.decode_node_at(node_offset as usize)?;
                        Ok(Node::Extension(ExtensionNode::new(
                            nibbles,
                            NodeRef::Node(Arc::new(child), OnceLock::new()),
                        )))
                    }
                    (true, true) => {
                        panic!("Extend node with both child and value not supported");
                    }
                    (false, false) => {
                        panic!("Invalid Extend node with no child or value");
                    }
                }
            }
            TAG_BRANCH => {
                // Read 16 child offsets
                let mut child_offsets = [0u64; 16];
                for child in child_offsets.iter_mut() {
                    if position + 8 > self.buffer.len() {
                        panic!("Invalid buffer length");
                    }
                    *child = u64::from_le_bytes([
                        self.buffer[position],
                        self.buffer[position + 1],
                        self.buffer[position + 2],
                        self.buffer[position + 3],
                        self.buffer[position + 4],
                        self.buffer[position + 5],
                        self.buffer[position + 6],
                        self.buffer[position + 7],
                    ]);
                    position += 8;
                }

                // Read value offset
                if position + 8 > self.buffer.len() {
                    panic!("Invalid buffer length");
                }
                let value_offset = u64::from_le_bytes([
                    self.buffer[position],
                    self.buffer[position + 1],
                    self.buffer[position + 2],
                    self.buffer[position + 3],
                    self.buffer[position + 4],
                    self.buffer[position + 5],
                    self.buffer[position + 6],
                    self.buffer[position + 7],
                ]);

                // Build children NodeRefs
                let mut children: [NodeRef; 16] = Default::default();
                for (i, &offset) in child_offsets.iter().enumerate() {
                    if offset > 0 {
                        let child = self.decode_node_at(offset as usize)?;
                        children[i] = NodeRef::Node(Arc::new(child), OnceLock::new());
                    }
                }

                // Read value if present
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
            _ => panic!("Invalid node tag: {}", tag),
        }
    }

    /// Gets a value by path without copying data
    pub fn get_by_path(&self, path: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let nibbles = Nibbles::from_raw(path, false);
        self.get_by_path_inner(nibbles, 0)
    }

    /// Internal helper for get_by_path with position tracking
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
                // Read nibbles length
                if position + 4 > self.buffer.len() {
                    return Ok(None);
                }
                let len = u32::from_le_bytes([
                    self.buffer[position],
                    self.buffer[position + 1],
                    self.buffer[position + 2],
                    self.buffer[position + 3],
                ]) as usize;
                position += 4;

                // Read nibbles data
                if position + len > self.buffer.len() {
                    return Ok(None);
                }
                let compact_nibbles = &self.buffer[position..position + len];
                let nibbles = Nibbles::decode_compact(compact_nibbles);
                position += len;

                // Read node offset
                if position + 8 > self.buffer.len() {
                    return Ok(None);
                }
                let node_offset = u64::from_le_bytes([
                    self.buffer[position],
                    self.buffer[position + 1],
                    self.buffer[position + 2],
                    self.buffer[position + 3],
                    self.buffer[position + 4],
                    self.buffer[position + 5],
                    self.buffer[position + 6],
                    self.buffer[position + 7],
                ]);
                position += 8;

                // Read value offset
                if position + 8 > self.buffer.len() {
                    return Ok(None);
                }
                let value_offset = u64::from_le_bytes([
                    self.buffer[position],
                    self.buffer[position + 1],
                    self.buffer[position + 2],
                    self.buffer[position + 3],
                    self.buffer[position + 4],
                    self.buffer[position + 5],
                    self.buffer[position + 6],
                    self.buffer[position + 7],
                ]);

                // Extend has only a child or a value
                if node_offset == 0 && value_offset > 0 {
                    // Leaf node
                    let leaf_path_without_flag = if nibbles.is_leaf() {
                        nibbles.slice(0, nibbles.len() - 1)
                    } else {
                        nibbles
                    };

                    if path == leaf_path_without_flag {
                        self.read_value_at_offset(value_offset as usize)
                    } else {
                        Ok(None)
                    }
                } else if node_offset > 0 && value_offset == 0 {
                    // Extension node
                    if !path.skip_prefix(&nibbles) {
                        return Ok(None);
                    }
                    // Recurse into the child
                    self.get_by_path_inner(path, node_offset as usize)
                } else {
                    panic!("Extend node with both child and value not supported");
                }
            }
            TAG_BRANCH => {
                if path.is_empty() {
                    // Skip 16 child offsets
                    position += 16 * 8;

                    if position + 8 > self.buffer.len() {
                        return Ok(None);
                    }
                    let value_offset = u64::from_le_bytes([
                        self.buffer[position],
                        self.buffer[position + 1],
                        self.buffer[position + 2],
                        self.buffer[position + 3],
                        self.buffer[position + 4],
                        self.buffer[position + 5],
                        self.buffer[position + 6],
                        self.buffer[position + 7],
                    ]);

                    if value_offset > 0 {
                        self.read_value_at_offset(value_offset as usize)
                    } else {
                        Ok(None)
                    }
                } else {
                    // Get next nibble and find corresponding child
                    let next_nibble = match path.next_choice() {
                        Some(nibble) => nibble,
                        None => return Ok(None),
                    };

                    // Read child offset at position next_nibble
                    let child_offset_pos = position + next_nibble * 8;
                    if child_offset_pos + 8 > self.buffer.len() {
                        return Ok(None);
                    }

                    let child_offset = u64::from_le_bytes([
                        self.buffer[child_offset_pos],
                        self.buffer[child_offset_pos + 1],
                        self.buffer[child_offset_pos + 2],
                        self.buffer[child_offset_pos + 3],
                        self.buffer[child_offset_pos + 4],
                        self.buffer[child_offset_pos + 5],
                        self.buffer[child_offset_pos + 6],
                        self.buffer[child_offset_pos + 7],
                    ]);

                    if child_offset > 0 {
                        self.get_by_path_inner(path, child_offset as usize)
                    } else {
                        Ok(None)
                    }
                }
            }
            _ => panic!("Invalid node tag: {}", tag),
        }
    }

    /// Read value at specific offset
    fn read_value_at_offset(&self, offset: usize) -> Result<Option<Vec<u8>>, TrieError> {
        if offset + 4 > self.buffer.len() {
            return Ok(None);
        }

        let len = u32::from_le_bytes([
            self.buffer[offset],
            self.buffer[offset + 1],
            self.buffer[offset + 2],
            self.buffer[offset + 3],
        ]) as usize;

        let data_start = offset + 4;
        if data_start + len > self.buffer.len() {
            return Ok(None);
        }

        Ok(Some(self.buffer[data_start..data_start + len].to_vec()))
    }
}

/// Helper function to serialize a Merkle Patricia Trie node to bytes.
pub fn serialize(node: &Node) -> Vec<u8> {
    Serializer::new().serialize_tree(node).unwrap()
}

#[cfg(test)]
mod test {
    use crate::trie::node_hash::NodeHash;
    use crate::trie::trie::{InMemoryTrieDB, Trie};

    use super::*;

    fn new_temp() -> Trie {
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::sync::Mutex;

        let hmap: HashMap<NodeHash, Vec<u8>> = HashMap::new();
        let map = Arc::new(Mutex::new(hmap));
        let db = InMemoryTrieDB::new(map);
        Trie::new(Box::new(db))
    }

    fn deserialize(buffer: &[u8]) -> Node {
        Deserializer::new(buffer).decode_tree().unwrap()
    }

    #[test]
    fn test_serialize_deserialize_empty_leaf() {
        let leaf = Node::Leaf(LeafNode {
            partial: Nibbles::from_hex(vec![]),
            value: vec![],
        });

        let bytes = serialize(&leaf);
        let recovered = deserialize(&bytes);

        assert_eq!(leaf, recovered);
    }

    #[test]
    fn test_serialize_deserialize_leaf_with_long_path() {
        let leaf = Node::Leaf(LeafNode {
            partial: Nibbles::from_hex(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]),
            value: b"long_path_value".to_vec(),
        });

        let bytes = serialize(&leaf);
        let recovered = deserialize(&bytes);

        assert_eq!(leaf, recovered);
    }

    #[test]
    fn test_serialize_deserialize_branch_empty() {
        let branch = Node::Branch(Box::new(BranchNode {
            choices: Default::default(),
            value: vec![],
        }));

        let bytes = serialize(&branch);
        let recovered = deserialize(&bytes);

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

        let bytes = serialize(&ext);
        let recovered = deserialize(&bytes);
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

        let bytes = serialize(&outer_ext);
        let recovered = deserialize(&bytes);

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
        let bytes = serialize(&root);
        let recovered = deserialize(&bytes);

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
        let bytes = serialize(&root);
        let recovered = deserialize(&bytes);

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
        let serialized = serialize(&root);

        let path = "/tmp/test_trie.mpt";
        fs::write(path, &serialized).unwrap();

        // Read from file and deserialize
        let read_data = fs::read(path).unwrap();
        let deserialized = deserialize(&read_data);

        assert_eq!(root, deserialized);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_get_by_path_serialized_simple() {
        let mut trie = new_temp();
        trie.insert(b"test".to_vec(), b"value".to_vec()).unwrap();

        let root = trie.root_node().unwrap().unwrap();
        let buffer = serialize(&root);

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(
            deserializer.get_by_path(b"test").unwrap(),
            Some(b"value".to_vec())
        );

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_tree().unwrap();
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
        let buffer = serialize(&root);

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(
            deserializer.get_by_path(b"horse").unwrap(),
            Some(b"stallion".to_vec())
        );

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(
            deserializer.get_by_path(b"dog").unwrap(),
            Some(b"puppy".to_vec())
        );

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(
            deserializer.get_by_path(b"doge").unwrap(),
            Some(b"coin".to_vec())
        );

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(
            deserializer.get_by_path(b"do").unwrap(),
            Some(b"verb".to_vec())
        );

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(deserializer.get_by_path(b"cat").unwrap(), None);

        let deserializer = Deserializer::new(&buffer);
        assert_eq!(deserializer.get_by_path(b"").unwrap(), None);

        // Reset position before decoding tree
        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_tree().unwrap();
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

        let buffer = serialize(&root);

        for (key, expected_value) in &test_data {
            let deserializer = Deserializer::new(&buffer);
            let retrieved_value = deserializer.get_by_path(key).unwrap();
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
            let result = deserializer.get_by_path(key).unwrap();
            assert_eq!(result, None);
        }

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_tree().unwrap();

        assert_eq!(root, recovered);
    }
}
