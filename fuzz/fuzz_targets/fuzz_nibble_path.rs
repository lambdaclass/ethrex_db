#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ethrex_db::data::NibblePath;

#[derive(Arbitrary, Debug)]
struct NibblePathInput {
    bytes: Vec<u8>,
    operations: Vec<NibbleOp>,
}

#[derive(Arbitrary, Debug)]
enum NibbleOp {
    Get(usize),
    SliceFrom(usize),
    SliceTo(usize),
    CommonPrefix(Vec<u8>),
    Iterate,
}

fuzz_target!(|input: NibblePathInput| {
    // Limit input size
    if input.bytes.len() > 1000 || input.operations.len() > 100 {
        return;
    }

    let path = NibblePath::from_bytes(&input.bytes);
    let len = path.len();

    for op in input.operations {
        match op {
            NibbleOp::Get(idx) => {
                if len > 0 {
                    let nibble = path.get(idx % len);
                    // Nibbles should be 0-15
                    assert!(nibble < 16);
                }
            }
            NibbleOp::SliceFrom(start) => {
                let sliced = path.slice_from(start);
                if start < len {
                    assert_eq!(sliced.len(), len - start);
                    // Verify first nibble matches
                    if sliced.len() > 0 {
                        assert_eq!(sliced.get(0), path.get(start));
                    }
                } else {
                    assert!(sliced.is_empty());
                }
            }
            NibbleOp::SliceTo(count) => {
                let sliced = path.slice_to(count);
                if count < len {
                    assert_eq!(sliced.len(), count);
                } else {
                    assert_eq!(sliced.len(), len);
                }
            }
            NibbleOp::CommonPrefix(other_bytes) => {
                let other = NibblePath::from_bytes(&other_bytes);
                let common = path.common_prefix_len(&other);
                assert!(common <= len);
                assert!(common <= other.len());

                // Verify common prefix nibbles match
                for i in 0..common {
                    assert_eq!(path.get(i), other.get(i));
                }
            }
            NibbleOp::Iterate => {
                let collected: Vec<u8> = path.iter().collect();
                assert_eq!(collected.len(), len);

                // Verify all nibbles are valid (0-15)
                for nibble in collected {
                    assert!(nibble < 16);
                }
            }
        }
    }
});
