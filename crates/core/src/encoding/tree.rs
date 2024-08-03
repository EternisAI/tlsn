use std::collections::HashMap;

use bimap::BiMap;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    conn::TranscriptLength,
    encoding::{
        proof::{EncodingProof, Opening},
        EncodingProvider,
    },
    hash::{Hash, HashAlgorithmId, TypedHash},
    merkle::MerkleTree,
    transcript::SubsequenceIdx,
    Direction, Transcript,
};

/// Encoding tree builder error.
#[derive(Debug, thiserror::Error)]
pub enum EncodingTreeError {
    /// Index is out of bounds of the transcript.
    #[error("index is out of bounds of the transcript")]
    OutOfBounds {
        /// The index.
        index: SubsequenceIdx,
        /// The transcript length.
        transcript_length: usize,
    },
    /// Encoding provider is missing an encoding for an index.
    #[error("encoding provider is missing an encoding for an index")]
    MissingEncoding {
        /// The index which is missing.
        index: SubsequenceIdx,
    },
    /// Index is missing from the tree.
    #[error("index is missing from the tree")]
    MissingLeaf {
        /// The index which is missing.
        index: SubsequenceIdx,
    },
}

/// A leaf in the encoding tree.
pub(crate) struct EncodingLeaf {
    pub(crate) encoding: Vec<u8>,
    pub(crate) nonce: [u8; 16],
}

impl EncodingLeaf {
    pub(super) fn new(encoding: Vec<u8>, nonce: [u8; 16]) -> Self {
        Self { encoding, nonce }
    }
}

/// A merkle tree of transcript encodings.
#[derive(Serialize, Deserialize)]
pub struct EncodingTree {
    /// Merkle tree of the commitments.
    tree: MerkleTree,
    /// Nonces used to blind the hashes.
    nonces: Vec<[u8; 16]>,
    /// Mapping between the index of a leaf and the subsequence it
    /// corresponds to.
    seqs: BiMap<usize, SubsequenceIdx>,
}

opaque_debug::implement!(EncodingTree);

impl EncodingTree {
    /// Creates a new encoding tree.
    ///
    /// # Arguments
    ///
    /// * `alg` - The hash algorithm to use.
    /// * `seqs` - The subsequence indices to commit to.
    /// * `provider` - The encoding provider.
    /// * `transcript_length` - The length of the transcript.
    pub fn new<'seq>(
        alg: HashAlgorithmId,
        seqs: impl Iterator<Item = &'seq SubsequenceIdx>,
        provider: &impl EncodingProvider,
        transcript_length: &TranscriptLength,
    ) -> Result<Self, EncodingTreeError> {
        let mut tree = Self {
            tree: MerkleTree::new(alg),
            nonces: Vec::new(),
            seqs: BiMap::new(),
        };

        for seq in seqs {
            let len = match seq.direction() {
                Direction::Sent => transcript_length.sent as usize,
                Direction::Received => transcript_length.received as usize,
            };

            if seq.end() > len {
                return Err(EncodingTreeError::OutOfBounds {
                    index: seq.clone(),
                    transcript_length: len,
                });
            }

            let encoding = provider
                .provide_subsequence(seq)
                .ok_or_else(|| EncodingTreeError::MissingEncoding { index: seq.clone() })?;

            tree.add_leaf(seq.clone(), encoding);
        }

        Ok(tree)
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> TypedHash {
        self.tree.root()
    }

    /// Returns the hash algorithm of the tree.
    pub fn algorithm(&self) -> HashAlgorithmId {
        self.tree.algorithm()
    }

    /// Generates a proof for the given subsequences.
    ///
    /// # Arguments
    ///
    /// * `transcript` - The transcript to prove against.
    /// * `seqs` - The subsequences to prove.
    pub fn proof<'seq>(
        &self,
        transcript: &Transcript,
        seqs: impl Iterator<Item = &'seq SubsequenceIdx>,
    ) -> Result<EncodingProof, EncodingTreeError> {
        let mut openings = HashMap::new();
        for seq in seqs {
            let idx = *self
                .seqs
                .get_by_right(&seq)
                .ok_or_else(|| EncodingTreeError::MissingLeaf { index: seq.clone() })?;

            let seq =
                transcript
                    .get_subsequence(seq)
                    .ok_or_else(|| EncodingTreeError::OutOfBounds {
                        index: seq.clone(),
                        transcript_length: transcript.len_of_direction(seq.direction()),
                    })?;
            let nonce = self.nonces[idx];

            openings.insert(idx, Opening { seq, nonce });
        }

        let mut indices = openings.keys().copied().collect::<Vec<_>>();
        indices.sort();
        let inclusion_proof = self.tree.proof(&indices);

        Ok(EncodingProof {
            inclusion_proof,
            openings,
        })
    }

    /// Returns whether the tree contains the given subsequence.
    pub fn contains(&self, seq: &SubsequenceIdx) -> bool {
        self.seqs.contains_right(seq)
    }

    pub(super) fn add_leaf(&mut self, seq: SubsequenceIdx, encoding: Vec<u8>) {
        if self.seqs.contains_right(&seq) {
            // The subsequence is already in the tree.
            return;
        }

        let nonce: [u8; 16] = rand::thread_rng().gen();
        let leaf = EncodingLeaf::new(encoding, nonce);

        self.tree.insert(&leaf);
        self.nonces.push(nonce);
        self.seqs.insert(self.seqs.len(), seq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encoding::EncodingCommitment,
        fixtures::{encoder_seed, encoding_provider},
        hash::BLAKE3,
    };
    use tlsn_data_fixtures::http::{request::POST_JSON, response::OK_JSON};

    fn new_tree<'seq>(
        transcript: &Transcript,
        seqs: impl Iterator<Item = &'seq SubsequenceIdx>,
    ) -> Result<EncodingTree, EncodingTreeError> {
        let provider = encoding_provider(transcript.sent(), transcript.received());
        let transcript_length = TranscriptLength {
            sent: transcript.sent().len() as u32,
            received: transcript.received().len() as u32,
        };
        EncodingTree::new(BLAKE3, seqs, &provider, &transcript_length)
    }

    #[test]
    fn test_encoding_tree() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let seq_0 = SubsequenceIdx::new(Direction::Sent, 0..POST_JSON.len()).unwrap();
        let seq_1 = SubsequenceIdx::new(Direction::Received, 0..OK_JSON.len()).unwrap();

        let tree = new_tree(&transcript, [&seq_0, &seq_1].into_iter()).unwrap();

        assert!(tree.contains(&seq_0));
        assert!(tree.contains(&seq_1));

        let proof = tree
            .proof(&transcript, [&seq_0, &seq_1].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            seed: encoder_seed().to_vec(),
        };

        let partial_transcript = proof.verify(&transcript.length(), &commitment).unwrap();

        assert_eq!(partial_transcript.sent_unsafe(), transcript.sent());
        assert_eq!(partial_transcript.received_unsafe(), transcript.received());
    }

    #[test]
    fn test_encoding_tree_multiple_ranges() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let seq_0 = SubsequenceIdx::new(Direction::Sent, 0..1).unwrap();
        let seq_1 = SubsequenceIdx::new(Direction::Sent, 1..POST_JSON.len()).unwrap();
        let seq_2 = SubsequenceIdx::new(Direction::Received, 0..1).unwrap();
        let seq_3 = SubsequenceIdx::new(Direction::Received, 1..OK_JSON.len()).unwrap();

        let tree = new_tree(&transcript, [&seq_0, &seq_1, &seq_2, &seq_3].into_iter()).unwrap();

        assert!(tree.contains(&seq_0));
        assert!(tree.contains(&seq_1));
        assert!(tree.contains(&seq_2));
        assert!(tree.contains(&seq_3));

        let proof = tree
            .proof(&transcript, [&seq_0, &seq_1, &seq_2, &seq_3].into_iter())
            .unwrap();

        let commitment = EncodingCommitment {
            root: tree.root(),
            seed: encoder_seed().to_vec(),
        };

        let partial_transcript = proof.verify(&transcript.length(), &commitment).unwrap();

        assert_eq!(partial_transcript.sent_unsafe(), transcript.sent());
        assert_eq!(partial_transcript.received_unsafe(), transcript.received());
    }

    #[test]
    fn test_encoding_tree_out_of_bounds() {
        let transcript = Transcript::new(POST_JSON, OK_JSON);

        let seq_0 = SubsequenceIdx::new(Direction::Sent, 0..POST_JSON.len() + 1).unwrap();
        let seq_1 = SubsequenceIdx::new(Direction::Received, 0..OK_JSON.len() + 1).unwrap();

        let result = new_tree(&transcript, [&seq_0].into_iter()).unwrap_err();
        assert!(matches!(result, EncodingTreeError::OutOfBounds { .. }));

        let result = new_tree(&transcript, [&seq_1].into_iter()).unwrap_err();
        assert!(matches!(result, EncodingTreeError::OutOfBounds { .. }));
    }

    #[test]
    fn test_encoding_tree_missing_encoding() {
        let provider = encoding_provider(&[], &[]);
        let transcript_length = TranscriptLength {
            sent: 8,
            received: 8,
        };

        let result = EncodingTree::new(
            BLAKE3,
            [SubsequenceIdx::new(Direction::Sent, 0..8).unwrap()].iter(),
            &provider,
            &transcript_length,
        )
        .unwrap_err();
        assert!(matches!(result, EncodingTreeError::MissingEncoding { .. }));

        let result = EncodingTree::new(
            BLAKE3,
            [SubsequenceIdx::new(Direction::Received, 0..8).unwrap()].iter(),
            &provider,
            &transcript_length,
        )
        .unwrap_err();
        assert!(matches!(result, EncodingTreeError::MissingEncoding { .. }));
    }
}
