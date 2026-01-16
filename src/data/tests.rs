//! Property-based tests for data structures.

#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;
    use crate::data::{NibblePath, SlottedArray};

    proptest! {
        #[test]
        fn nibble_path_from_bytes_roundtrip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let path = NibblePath::from_bytes(&bytes);
            assert_eq!(path.len(), bytes.len() * 2);

            // Verify each nibble
            for (i, byte) in bytes.iter().enumerate() {
                assert_eq!(path.get(i * 2), byte >> 4);
                assert_eq!(path.get(i * 2 + 1), byte & 0x0F);
            }
        }

        #[test]
        fn nibble_path_slice_from(bytes in proptest::collection::vec(any::<u8>(), 1..32), start in 0usize..64) {
            let path = NibblePath::from_bytes(&bytes);
            let start = start % path.len().max(1);

            let sliced = path.slice_from(start);
            assert_eq!(sliced.len(), path.len() - start);

            for i in 0..sliced.len() {
                assert_eq!(sliced.get(i), path.get(start + i));
            }
        }

        #[test]
        fn nibble_path_common_prefix_symmetric(
            bytes1 in proptest::collection::vec(any::<u8>(), 0..32),
            bytes2 in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let path1 = NibblePath::from_bytes(&bytes1);
            let path2 = NibblePath::from_bytes(&bytes2);

            // Common prefix should be symmetric
            assert_eq!(path1.common_prefix_len(&path2), path2.common_prefix_len(&path1));
        }

        #[test]
        fn slotted_array_insert_get(
            keys in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..8), 1..10),
            values in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..32), 1..10)
        ) {
            let mut arr = SlottedArray::new();

            // Insert entries
            let entries: Vec<_> = keys.iter().zip(values.iter()).collect();

            for (key, value) in &entries {
                let path = NibblePath::from_bytes(key);
                let _ = arr.try_insert(&path, value);
            }

            // Verify entries that were successfully inserted
            for (key, value) in &entries {
                let path = NibblePath::from_bytes(key);
                if let Some(retrieved) = arr.get(&path) {
                    assert_eq!(&retrieved, *value);
                }
            }
        }

        #[test]
        fn slotted_array_delete(
            key in proptest::collection::vec(any::<u8>(), 1..8),
            value in proptest::collection::vec(any::<u8>(), 1..32)
        ) {
            let mut arr = SlottedArray::new();
            let path = NibblePath::from_bytes(&key);

            // Insert
            if arr.try_insert(&path, &value) {
                assert!(arr.get(&path).is_some());

                // Delete
                assert!(arr.delete(&path));
                assert!(arr.get(&path).is_none());
            }
        }

        #[test]
        fn slotted_array_no_duplicates(
            key in proptest::collection::vec(any::<u8>(), 1..8),
            value1 in proptest::collection::vec(any::<u8>(), 1..16),
            value2 in proptest::collection::vec(any::<u8>(), 1..16)
        ) {
            let mut arr = SlottedArray::new();
            let path = NibblePath::from_bytes(&key);

            if arr.try_insert(&path, &value1) {
                // Delete and re-insert with different value
                arr.delete(&path);
                if arr.try_insert(&path, &value2) {
                    let retrieved = arr.get(&path);
                    assert_eq!(retrieved, Some(value2));
                }
            }
        }
    }
}
