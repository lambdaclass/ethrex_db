//! File management
//!
//! The FileManager handles all low-level file operations for `EthrexDB`, implementing
//! an append-only storage strategy where data is never overwritten. All writes go
//! to the end of the file, preserving historical data and enabling version traversal.
//!
//! File Layout:
//! ```text
//! Offset 0: [header: 8 bytes]     // Points to latest root offset
//! Offset 8: [commit_1_data...]    // First commit's data
//! Offset X: [commit_2_data...]    // Second commit's data
//! Offset Y: [commit_N_data...]    // Latest commit's data
//! ```
//!
//! The header at offset 0 always contains the offset of the most recent root.
//! This is the only part of the file that gets updated in-place. Everything else
//! is append-only.
//!
//! Each commit's data starts with an 8-byte link to the previous root offset,
//! creating a linked list through all versions:
//! - First commit: prev_root_offset = 0 (marks end of chain)
//! - Later commits: prev_root_offset = offset of previous root

use crate::trie::TrieError;
use memmap2::{Mmap, MmapOptions};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

/// File manager for `EthrexDB`
pub struct FileManager {
    /// File where the data is stored
    file: File,
    /// Memory-mapped of the file
    /// TODO: Handle case when adding new nodes
    mmap: Mmap,
}

impl FileManager {
    /// Create a new file
    pub fn create(file_path: PathBuf) -> Result<Self, TrieError> {
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();

        // Write initial header: offset = 0
        let initial_offset = 0u64;
        file.write_all(&initial_offset.to_le_bytes()).unwrap();
        file.flush().unwrap();

        let mmap = unsafe { MmapOptions::new().map(&file).unwrap() };

        Ok(Self { file, mmap })
    }

    /// Open an existing file
    pub fn open(file_path: PathBuf) -> Result<Self, TrieError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();

        let mmap = unsafe { MmapOptions::new().map(&file).unwrap() };

        Ok(Self { file, mmap })
    }

    /// Read the offset of the latest root from the file header
    pub fn read_latest_root_offset(&self) -> Result<u64, TrieError> {
        if self.mmap.len() < 8 {
            return Ok(0);
        }

        let offset_bytes: [u8; 8] = self.mmap[0..8].try_into().unwrap();
        Ok(u64::from_le_bytes(offset_bytes))
    }

    /// Update the header to point to the new latest root offset
    pub fn update_latest_root_offset(&mut self, new_offset: u64) -> Result<(), TrieError> {
        self.file.seek(SeekFrom::Start(0)).unwrap();
        self.file.write_all(&new_offset.to_le_bytes()).unwrap();
        self.file.flush().unwrap();
        self.refresh_mmap();
        Ok(())
    }

    /// Write data at the end of the file and return the offset where it was written
    pub fn write_at_end(&mut self, data: &[u8]) -> Result<u64, TrieError> {
        let offset = self.file.seek(SeekFrom::End(0)).unwrap();
        self.file.write_all(data).unwrap();
        self.file.flush().unwrap();
        self.refresh_mmap();
        Ok(offset)
    }

    /// Refresh memory map after file modifications
    fn refresh_mmap(&mut self) {
        self.mmap = unsafe { MmapOptions::new().map(&self.file).unwrap() };
    }

    /// Get the current file size
    pub fn get_file_size(&self) -> Result<u64, TrieError> {
        Ok(self.mmap.len() as u64)
    }

    /// Get slice from a specific offset to the end of the file
    pub fn get_slice_to_end(&self, offset: u64) -> Result<&[u8], TrieError> {
        if offset as usize >= self.mmap.len() {
            return Ok(&[]);
        }

        Ok(&self.mmap[offset as usize..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempdir::TempDir;

    #[test]
    fn test_create_and_read_offset() {
        let temp_dir = TempDir::new("file_manager_test").unwrap();
        let file_path = temp_dir.path().join("test.db");

        let mut fm = FileManager::create(file_path.clone()).unwrap();

        // The initial offset should be 0
        assert_eq!(fm.read_latest_root_offset().unwrap(), 0);

        fm.update_latest_root_offset(123).unwrap();
        assert_eq!(fm.read_latest_root_offset().unwrap(), 123);
    }

    #[test]
    fn test_write_and_read_data() {
        let temp_dir = TempDir::new("file_manager_test").unwrap();
        let file_path = temp_dir.path().join("test.db");

        let mut fm = FileManager::create(file_path.clone()).unwrap();

        let test_data = b"hello, ethrexdb!";
        let offset = fm.write_at_end(test_data).unwrap();

        // The offset should be 8
        assert_eq!(offset, 8);

        let mut data = vec![0u8; test_data.len()];
        fm.file.seek(SeekFrom::Start(offset)).unwrap();
        fm.file.read_exact(&mut data).unwrap();

        assert_eq!(data, test_data);
    }

    #[test]
    fn test_open_existing() {
        let temp_dir = TempDir::new("file_manager_test").unwrap();
        let file_path = temp_dir.path().join("test.db");

        {
            let mut fm = FileManager::create(file_path.clone()).unwrap();
            assert_eq!(
                fm.get_file_size().unwrap(),
                8,
                "File is empty but should have 8 bytes for the header"
            );
            fm.update_latest_root_offset(456).unwrap();
            fm.write_at_end(b"persistent data").unwrap();
            assert_ne!(fm.get_file_size().unwrap(), 8);
        }

        let fm = FileManager::open(file_path).unwrap();
        assert_eq!(fm.read_latest_root_offset().unwrap(), 456);

        let data = fm.get_slice_to_end(8).unwrap().to_vec();
        assert_eq!(data, b"persistent data");
        assert_ne!(fm.get_file_size().unwrap(), 8);
    }
}
