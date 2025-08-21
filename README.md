# ethrex_db

**EthrexDB** is a lightweight Merkle Patricia Trie (MPT) based database, designed to serve as a foundational storage layer for Ethereum execution environments.

Most blockchains separate the world state from the proof structure, typically using a general purpose key value store alongside a Merkle Patricia Trie. This leads to redundant data storage and inefficiencies each state update can require O((log N)²) disk operations due to nested log time insertions. EthrexDB solves this by tightly coupling the Merkle tree with the state storage itself. This unified approach removes duplication, reduces I/O overhead, and enables faster state transitions with native proof support.

## Getting Started

### Installation

### Benchmarking and Profiling

To run a benchmark comparing this new implementation against libmdbx (as we do in Ethrex), run:

```bash
make bench
```

To profile using Samply, first install it:

```bash
cargo install --locked samply
```

Then, run the profile:

```bash
make profile
```

## EthrexDB MVP

> [!NOTE]
> This is a first version of the MVP. It is not yet production ready and is subject to change.

### Requirements

- Patricia Merkle Trie structure (internally).
- Supported APIs (\*):
    - Iterate over trie roots (assumes multi-trie is required)
    - Get by path
    - Get by hash (assumes hashing is required + support for this API)
    - Commit (batch update)

### MVP implementation

The simplest implementation supports multi-trie but does not support hash indexing (get by hash, nodes may have an associated hash but it will not be indexable).

### Parts

The database starts with the offset of the **latest** root node. This is the only part that is updated on each commit.

After that: root nodes, normal nodes and value nodes are appended (append-only, never modified) at the end.

**Trie roots**

The trie roots are exactly the same as normal nodes, but prepended with the offset of the **previous** root node. The previous root node is the one that was the latest before committing this new root node. The first root node will (last in the chain) will have an offset of zero, which ends the linked list.

**Node storage**

There are two kinds of nodes only:

- Branch: Equivalent to the branch nodes in a PMT.
- Extend: Combines both the extension and leaf nodes of a PMT.

The branch node has the following data:

- 16x node offsets
- 1x value offset

Each offset (both node and value) may be zero, but there's some conditions that are required for the integrity of the database, which are:

- At least two of the node offsets must not be zero. Rationale: A branch with a single child doesn't make sense.
- Everything else may be null (ex. a branch node may not have an associated value).

The extend node has the following data:

- 1x node offset
- 1x value offset

In this case, the integrity conditions are:

- Either the node or value offsets (or both) must be set. It is invalid if both of them are zero.
- If node is valid but has no value, the child must be a branch (rationale: the extend nodes should be merged otherwise). This does not apply if the node has an associated value (it is not restricted in that case).

**Nibbles**

The nibbles in a branch node are not a problem since they are implicitly encoded within the node itself as indexes over the array of child offsets.

However, on extend nodes, nibbles may pose a problem. My proposal is to support "shaving" a nibble at both ends of the string to avoid costly arbitrary-precision bit shifting instructions.

For example, if the path `0x01234567` was split at the 3rd nibble, the two halves would end as `0x0120` and `0x034567`. The first half would have length 3 (in nibbles) and not set the half flag, while the second one would have length 5 and set the half flag that marks the path as having a single (right-aligned) nibble in the first byte.

If required, computing a flag (bool) to check if the last byte is also a single (left-aligned) nibble at the end should be as easy as xoring the start flag with the LSB of the length: `end_flag = start_flag ^ ((length & 0x01) != 0)`.

Comparing paths should be easy if split in three paths:

- First byte: needs to check the start flag.
- Everything in the middle: it's already properly aligned with the value we're comparing against.
- Last byte: needs to check the end flag.

## Post-MVP implementation

- Database cursor:
    - This one can already be implemented over the MVP (it does require neither extra features nor radical design changes).
    - The cursor keeps the path followed up to the current node, and starts from there when searching the next nodes.
    - It should greatly increase batch retrieval requests, especially if the paths (or hashes in case of hash-based indexing) are sorted.
- File pagination:
    - Supports multiple separated streams (aka. "memory spaces") that are independent from each other.
    - Enables support for arbitrary data (not only a PMT), including:
        - Serialized data (does not need a parent collection like a table in SQL).
        - Makes multiple indexing possible.
    - Refactors the internal structure from the MVP one (offset + append) into a paginated one:
        - Splits the nodes (the tree structure) and values (actual values) into different streams.
            - Makes it so that nodes can be properly aligned, therefore reducing the bits required for storing offsets.
    - It should support pruning of old tries, but it may break cursors and other stuff. It would require implementing an allocator and/or defragmenter to avoid leaving spaces in-between.
- Hash-based indexation:
    - Requires multiple indexing (aka. pagination).
    - Does not require the node itself to hold the hash, but if so, the hash may not be available when retrieving a node by path.
    - Can be implemented as a B-trie (like libmdbx) or as another PMT with fixed-length paths thanks to separating the streams of the structure from the values themselves.
- Multithreading and multiprocessing (most likely requires shared memory):
    - It is possible to synchronize both between threads and processes when using pthreads.
    - Synchronization could be either global (the entire database is locked) or local (nodes are locked individually). Global synchronization may break cursors. Local synchronization may break even more stuff, care should be taken if implemented.
    - There will be a performance overhead, which may be greater if synchronizing between processes.
    - It **may** be possible to implement a lockfree algorithm.

## 📚 References and acknowledgements
The following links, repos, companies and projects have been important in the development of this library and we want to thank and acknowledge them.

- [NOMT](https://github.com/thrumdev/nomt)
- [QMDB](https://github.com/LayerZero-Labs/qmdb)
- [Paprika](https://github.com/NethermindEth/Paprika)
- [MonadDB](https://docs.monad.xyz/monad-arch/execution/monaddb)
- [Database Internals](https://www.databass.dev/)
- [PingCAP Talent Plan](https://github.com/pingcap/talent-plan)
- [Readings in Database System](http://www.redbook.io/)

We're thankful to the teams that created these databases since they were crucial for us to be able to create ethrex_db.
