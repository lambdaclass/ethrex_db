#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ethrex_db::data::{NibblePath, SlottedArray};

#[derive(Arbitrary, Debug)]
struct SlottedArrayInput {
    operations: Vec<SlottedOp>,
}

#[derive(Arbitrary, Debug)]
enum SlottedOp {
    Insert { key: Vec<u8>, value: Vec<u8> },
    Get { key: Vec<u8> },
    Delete { key: Vec<u8> },
    IterateAll,
    Defragment,
    CheckFreeSpace,
    LiveCount,
}

fuzz_target!(|input: SlottedArrayInput| {
    // Limit operations
    if input.operations.len() > 200 {
        return;
    }

    let mut arr = SlottedArray::new();
    let mut expected: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();

    for op in input.operations {
        match op {
            SlottedOp::Insert { key, value } => {
                // Limit key/value size
                if key.len() > 100 || value.len() > 500 {
                    continue;
                }

                let nibble_key = NibblePath::from_bytes(&key);
                if arr.try_insert(&nibble_key, &value) {
                    expected.insert(key, value);
                }
            }
            SlottedOp::Get { key } => {
                let nibble_key = NibblePath::from_bytes(&key);
                let result = arr.get(&nibble_key);

                if let Some(expected_val) = expected.get(&key) {
                    assert_eq!(result.as_deref(), Some(expected_val.as_slice()));
                }
            }
            SlottedOp::Delete { key } => {
                let nibble_key = NibblePath::from_bytes(&key);
                let existed = arr.get(&nibble_key).is_some();
                arr.delete(&nibble_key);

                if existed {
                    expected.remove(&key);
                }

                // After delete, get should return None
                assert!(arr.get(&nibble_key).is_none());
            }
            SlottedOp::IterateAll => {
                let count = arr.iter().count();
                let live_count = arr.live_count();
                assert_eq!(count, live_count);
            }
            SlottedOp::Defragment => {
                let before_count = arr.live_count();
                arr.defragment();
                let after_count = arr.live_count();
                assert_eq!(before_count, after_count);

                // Verify all entries still accessible
                for (key, value) in &expected {
                    let nibble_key = NibblePath::from_bytes(key);
                    assert_eq!(arr.get(&nibble_key).as_deref(), Some(value.as_slice()));
                }
            }
            SlottedOp::CheckFreeSpace => {
                let free = arr.free_space();
                assert!(free <= 4096 - 4); // header size
            }
            SlottedOp::LiveCount => {
                let live = arr.live_count();
                assert!(live <= arr.slot_count());
            }
        }
    }
});
