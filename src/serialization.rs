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
    pub fn new_incremental(node_index: &HashMap<NodeHash, u64>, base_offset: u64) -> Self {
        Self {
            buffer: Vec::new(),
            node_index: node_index.clone(),
            new_nodes: HashMap::new(),
            base_offset,
        }
    }

    /// Serializes a trie incrementally, only storing new nodes
    pub fn serialize_tree_incremental(mut self, root: &Node) -> SerializationResult {
        let root_offset = self.serialize_node(root)?;
        Ok((self.buffer, self.new_nodes, root_offset))
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
mod test {
    use super::*;
    use crate::trie::{InMemoryTrieDB, Trie, node_hash::NodeHash};

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
    fn test_simple_serialization() {
        let mut trie = new_temp();
        trie.insert(b"key".to_vec(), b"value".to_vec()).unwrap();

        let root = trie.root_node().unwrap().unwrap();
        let serializer = Serializer::new_incremental(&HashMap::new(), 0);
        let (buffer, _, _) = serializer.serialize_tree_incremental(&root).unwrap();

        let deserializer = Deserializer::new(&buffer);
        let recovered = deserializer.decode_node_at(0).unwrap();

        assert_eq!(root, recovered);
    }
}
