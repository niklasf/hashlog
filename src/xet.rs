//! Xet file hashes, as used by Hugging Face.
//!
//! Derived from xet_data/src/deduplication/chunking.rs and
//! xet_core_structures/src/merklehash/ of https://github.com/huggingface/xet-core
//! at commit ce8c6b25, licensed under the Apache License 2.0 (see
//! COPYING.xet-core). Modified to hash chunks incrementally instead of
//! buffering them, and reduced to what is needed for file hashes.

use std::io::Write as _;

const TARGET_CHUNK_SIZE: usize = 64 * 1024;
const MIN_CHUNK_SIZE: usize = TARGET_CHUNK_SIZE / 8;
const MAX_CHUNK_SIZE: usize = TARGET_CHUNK_SIZE * 2;
const MASK: u64 = 0xffff_0000_0000_0000;

// Bytes further back than this do not affect the gear hash, so most of the
// minimum chunk size can be skipped without looking at it.
const GEAR_WINDOW_SIZE: usize = 64;

const MEAN_BRANCHING_FACTOR: u64 = 4;
const MIN_GROUP_SIZE: usize = 2;
const MAX_GROUP_SIZE: usize = 2 * MEAN_BRANCHING_FACTOR as usize + 1;

const DATA_KEY: [u8; 32] = [
    102, 151, 245, 119, 91, 149, 80, 222, 49, 53, 203, 172, 165, 151, 24, 28, 157, 228, 33, 16,
    155, 235, 43, 88, 180, 208, 176, 75, 147, 173, 242, 41,
];
const INTERNAL_NODE_KEY: [u8; 32] = [
    1, 126, 197, 199, 165, 71, 41, 150, 253, 148, 102, 102, 180, 138, 2, 230, 93, 221, 83, 111, 55,
    199, 109, 210, 248, 99, 82, 230, 74, 83, 113, 63,
];
const FILE_KEY: [u8; 32] = [0; 32];

pub struct XetHasher {
    gear: gearhash::Hasher<'static>,
    chunk: blake3::Hasher,
    chunk_size: usize,
    nodes: Vec<Node>,
}

#[derive(Copy, Clone)]
struct Node {
    hash: [u8; 32],
    size: u64,
}

impl Default for XetHasher {
    fn default() -> Self {
        XetHasher {
            gear: gearhash::Hasher::default(),
            chunk: blake3::Hasher::new_keyed(&DATA_KEY),
            chunk_size: 0,
            nodes: Vec::new(),
        }
    }
}

impl XetHasher {
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match self.next_boundary(data) {
                Some(boundary) => {
                    let (head, tail) = data.split_at(boundary);
                    self.chunk.update(head);
                    self.chunk_size += boundary;
                    self.finish_chunk();
                    data = tail;
                }
                None => {
                    self.chunk.update(data);
                    self.chunk_size += data.len();
                    break;
                }
            }
        }
    }

    // Returns the bytes of the canonical string representation (as displayed
    // by Hugging Face), so that hex encoding the result yields that string.
    pub fn finalize(mut self) -> [u8; 32] {
        if self.chunk_size > 0 {
            self.finish_chunk();
        }
        if self.nodes.is_empty() {
            return [0; 32];
        }
        let root = aggregate(self.nodes);
        canonical(*blake3::keyed_hash(&FILE_KEY, &root).as_bytes())
    }

    fn next_boundary(&mut self, data: &[u8]) -> Option<usize> {
        let mut pos = MIN_CHUNK_SIZE
            .saturating_sub(self.chunk_size + GEAR_WINDOW_SIZE + 1)
            .min(data.len());
        let end = data.len().min(MAX_CHUNK_SIZE - self.chunk_size);

        while let Some(offset) = self.gear.next_match(&data[pos..end], MASK) {
            pos += offset;
            if self.chunk_size + pos >= MIN_CHUNK_SIZE {
                return Some(pos);
            }
        }

        (self.chunk_size + end >= MAX_CHUNK_SIZE).then_some(end)
    }

    fn finish_chunk(&mut self) {
        self.nodes.push(Node {
            hash: *self.chunk.finalize().as_bytes(),
            size: self.chunk_size as u64,
        });
        self.gear.set_hash(0);
        self.chunk = blake3::Hasher::new_keyed(&DATA_KEY);
        self.chunk_size = 0;
    }
}

// Hashes are displayed as 4 little endian 64 bit integers.
fn canonical(mut hash: [u8; 32]) -> [u8; 32] {
    for group in hash.as_chunks_mut::<8>().0 {
        group.reverse();
    }
    hash
}

fn next_merge_cut(nodes: &[Node]) -> usize {
    if nodes.len() <= MIN_GROUP_SIZE {
        return nodes.len();
    }
    let end = nodes.len().min(MAX_GROUP_SIZE);
    (MIN_GROUP_SIZE..end)
        .find(|&i| {
            let last_word = nodes[i].hash[24..].try_into().expect("8 bytes");
            u64::from_le_bytes(last_word) % MEAN_BRANCHING_FACTOR == 0
        })
        .map_or(end, |i| i + 1)
}

fn merge(nodes: &[Node]) -> Node {
    let mut hasher = blake3::Hasher::new_keyed(&INTERNAL_NODE_KEY);
    for node in nodes {
        writeln!(
            hasher,
            "{} : {}",
            hex::encode(canonical(node.hash)),
            node.size
        )
        .expect("write to hasher");
    }
    Node {
        hash: *hasher.finalize().as_bytes(),
        size: nodes.iter().map(|node| node.size).sum(),
    }
}

fn aggregate(mut nodes: Vec<Node>) -> [u8; 32] {
    while nodes.len() > 1 {
        let mut read = 0;
        let mut write = 0;
        while read < nodes.len() {
            let cut = read + next_merge_cut(&nodes[read..]);
            nodes[write] = merge(&nodes[read..cut]);
            read = cut;
            write += 1;
        }
        nodes.truncate(write);
    }
    nodes[0].hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(data: &[u8], read_size: usize) -> String {
        let mut xet = XetHasher::default();
        for part in data.chunks(read_size) {
            xet.update(part);
        }
        hex::encode(xet.finalize())
    }

    // Expected values produced by the xet-data and xet-core-structures crates
    // (1.8.0).
    #[test]
    fn test_known_hashes() {
        assert_eq!(hash(&[], 1 << 16), "0".repeat(64));
        assert_eq!(
            hash(b"hello world", 1 << 16),
            "f15edd43b7e85cfd25e2758ffe13b99fdd09dfa817e8d9f6548722a7a126db7f"
        );
        assert_eq!(
            hash(&vec![0; 1 << 20], 1 << 16),
            "1e671fe124cea35586b1d1c30b9d4fc6b4e05ee60c93406986444f7c23d54056"
        );
    }

    #[test]
    fn test_known_hash_independent_of_read_size() {
        // Enough pseudo-random data to span many chunks.
        let mut state = 1u32;
        let data: Vec<u8> = (0..(1 << 21))
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();

        for read_size in [data.len(), 1 << 16, 4099, 1] {
            assert_eq!(
                hash(&data, read_size),
                "209950f85604ac570dcf53a4777369a87821a337c2abab0145c969b080e7b129"
            );
        }
    }
}
