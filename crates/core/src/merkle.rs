//! Merkle tree types.

use serde::{ser::Serializer, Deserialize, Deserializer, Serialize};
use utils::iter::DuplicateCheck;

use crate::{
    hash::{Blake3, Hash, HashAlgorithm, Hasher, Keccak256, Sha256},
    serialize::CanonicalSerialize,
};

/// Errors that can occur during operations with Merkle tree and Merkle proof
#[derive(Debug, thiserror::Error, PartialEq)]
#[allow(missing_docs)]
pub(crate) enum MerkleError {
    /// Hash algorithm mismatch
    #[error("hash algorithm mismatch: expected {expected:?}, got {actual:?}")]
    AlgorithmMismatch {
        expected: HashAlgorithm,
        actual: HashAlgorithm,
    },
    /// Invalid merkle proof.
    #[error("invalid merkle proof")]
    InvalidProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MerkleProof(MerkleProofAlg);

impl MerkleProof {
    /// Returns the hash algorithm of the proof.
    pub(crate) fn algorithm(&self) -> HashAlgorithm {
        match &self.0 {
            MerkleProofAlg::Sha256(_) => HashAlgorithm::Sha256,
            MerkleProofAlg::Blake3(_) => HashAlgorithm::Blake3,
            MerkleProofAlg::Keccak256(_) => HashAlgorithm::Keccak256,
        }
    }

    pub(crate) fn verify<T: CanonicalSerialize>(
        &self,
        root: &Hash,
        leaf_indices: &[usize],
        leafs: &[T],
    ) -> Result<(), MerkleError> {
        assert_eq!(
            leaf_indices.len(),
            leafs.len(),
            "leaf indices length must match leafs length"
        );

        assert!(
            !leaf_indices.iter().contains_dups(),
            "duplicate indices provided {:?}",
            leaf_indices
        );

        match (root, &self.0) {
            (Hash::Sha256(root), MerkleProofAlg::Sha256(proof)) => {
                proof.verify(root, leaf_indices, leafs)
            }
            (Hash::Blake3(root), MerkleProofAlg::Blake3(proof)) => {
                proof.verify(root, leaf_indices, leafs)
            }
            (Hash::Keccak256(root), MerkleProofAlg::Keccak256(proof)) => {
                proof.verify(root, leaf_indices, leafs)
            }
            _ => Err(MerkleError::AlgorithmMismatch {
                expected: root.algorithm(),
                actual: self.algorithm(),
            }),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum MerkleProofAlg {
    Sha256(MerkleProofInner<Sha256>),
    Blake3(MerkleProofInner<Blake3>),
    Keccak256(MerkleProofInner<Keccak256>),
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MerkleProofInner<H: Hasher> {
    #[serde(
        serialize_with = "merkle_proof_serialize",
        deserialize_with = "merkle_proof_deserialize"
    )]
    #[serde(bound(
        serialize = "H::Output: Serialize",
        deserialize = "H::Output: Deserialize<'de>"
    ))]
    proof: rs_merkle::MerkleProof<H>,
    total_leaves: usize,
}

impl<H: Hasher> std::fmt::Debug for MerkleProofInner<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MerkleProof {{ ... }}")
    }
}

impl<H> MerkleProofInner<H>
where
    H: Hasher,
{
    /// Checks if indices, hashes and leaves count are valid for the provided root
    ///
    /// # Panics
    ///
    /// - If the length of `leaf_indices` and `leaf_hashes` does not match.
    /// - If `leaf_indices` contains duplicates.
    fn verify<T: CanonicalSerialize>(
        &self,
        root: &H::Output,
        leaf_indices: &[usize],
        leafs: &[T],
    ) -> Result<(), MerkleError>
    where
        H: Hasher,
    {
        // zip indices and hashes
        let mut leaf_hashes: Vec<(usize, H::Output)> = leaf_indices
            .iter()
            .copied()
            .zip(leafs)
            .map(|(idx, leaf)| {
                let hash = <H as Hasher>::hash(&leaf.serialize());
                (idx, hash)
            })
            .collect();

        // sort by index and unzip
        leaf_hashes.sort_by_key(|(idx, _)| *idx);
        let (indices, leaf_hashes): (Vec<usize>, Vec<_>) = leaf_hashes.into_iter().unzip();

        if !self
            .proof
            .verify(*root, &indices, &leaf_hashes, self.total_leaves)
        {
            return Err(MerkleError::InvalidProof);
        }

        Ok(())
    }
}

fn merkle_proof_serialize<H, S>(
    proof: &rs_merkle::MerkleProof<H>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    H: Hasher,
    S: Serializer,
{
    let bytes = proof.serialize::<rs_merkle::proof_serializers::DirectHashesOrder>();
    serializer.serialize_bytes(&bytes)
}

fn merkle_proof_deserialize<'de, D, H>(
    deserializer: D,
) -> Result<rs_merkle::MerkleProof<H>, D::Error>
where
    H: Hasher,
    D: Deserializer<'de>,
{
    let bytes = Vec::deserialize(deserializer)?;
    rs_merkle::MerkleProof::<H>::from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MerkleTree(MerkleTreeAlg);

impl MerkleTree {
    pub(crate) fn new(alg: HashAlgorithm) -> Self {
        match alg {
            HashAlgorithm::Sha256 => MerkleTree(MerkleTreeAlg::Sha256(MerkleTreeInner::default())),
            HashAlgorithm::Blake3 => MerkleTree(MerkleTreeAlg::Blake3(MerkleTreeInner::default())),
            HashAlgorithm::Keccak256 => {
                MerkleTree(MerkleTreeAlg::Keccak256(MerkleTreeInner::default()))
            }
        }
    }

    pub(crate) fn algorithm(&self) -> HashAlgorithm {
        match &self.0 {
            MerkleTreeAlg::Sha256(_) => HashAlgorithm::Sha256,
            MerkleTreeAlg::Blake3(_) => HashAlgorithm::Blake3,
            MerkleTreeAlg::Keccak256(_) => HashAlgorithm::Keccak256,
        }
    }

    pub(crate) fn insert<T: CanonicalSerialize + ?Sized>(&mut self, leaf: &T) {
        match &mut self.0 {
            MerkleTreeAlg::Sha256(tree) => tree.insert(leaf),
            MerkleTreeAlg::Blake3(tree) => tree.insert(leaf),
            MerkleTreeAlg::Keccak256(tree) => tree.insert(leaf),
        }
    }

    pub(crate) fn proof(&self, indices: &[usize]) -> MerkleProof {
        match &self.0 {
            MerkleTreeAlg::Sha256(tree) => MerkleProof(MerkleProofAlg::Sha256(tree.proof(indices))),
            MerkleTreeAlg::Blake3(tree) => MerkleProof(MerkleProofAlg::Blake3(tree.proof(indices))),
            MerkleTreeAlg::Keccak256(tree) => {
                MerkleProof(MerkleProofAlg::Keccak256(tree.proof(indices)))
            }
        }
    }

    pub(crate) fn root(&self) -> Hash {
        match &self.0 {
            MerkleTreeAlg::Sha256(tree) => Hash::Sha256(tree.root()),
            MerkleTreeAlg::Blake3(tree) => Hash::Blake3(tree.root()),
            MerkleTreeAlg::Keccak256(tree) => Hash::Keccak256(tree.root()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum MerkleTreeAlg {
    Sha256(MerkleTreeInner<Sha256>),

    Blake3(MerkleTreeInner<Blake3>),

    Keccak256(MerkleTreeInner<Keccak256>),
}

/// A Merkle tree.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MerkleTreeInner<H: Hasher>(
    #[serde(
        serialize_with = "merkle_tree_serialize",
        deserialize_with = "merkle_tree_deserialize"
    )]
    rs_merkle::MerkleTree<H>,
);

impl<H: Hasher> std::fmt::Debug for MerkleTreeInner<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MerkleTreeInner {{ ... }}")
    }
}

impl<H: Hasher> Default for MerkleTreeInner<H> {
    fn default() -> Self {
        Self(rs_merkle::MerkleTree::<H>::default())
    }
}

impl<H> MerkleTreeInner<H>
where
    H: Hasher,
{
    /// Inserts a new leaf into the Merkle tree
    pub(crate) fn insert<T: CanonicalSerialize + ?Sized>(&mut self, leaf: &T) {
        self.0.insert(<H as Hasher>::hash(&leaf.serialize()));
        self.0.commit();
    }

    /// Creates an inclusion proof for the given `indices`
    ///
    /// # Panics
    ///
    /// - if `indices` is not sorted.
    /// - if `indices` contains duplicates
    fn proof(&self, indices: &[usize]) -> MerkleProofInner<H> {
        assert!(
            indices.windows(2).all(|w| w[0] < w[1]),
            "indices must be unique and sorted"
        );

        MerkleProofInner {
            proof: self.0.proof(indices),
            total_leaves: self.0.leaves_len(),
        }
    }

    /// Returns the Merkle root for this MerkleTree
    fn root(&self) -> H::Output {
        self.0
            .root()
            .expect("Merkle root should be available")
            .into()
    }
}

/// Serialize the rs_merkle's `MerkleTree` type
fn merkle_tree_serialize<S, H>(
    tree: &rs_merkle::MerkleTree<H>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    H: Hasher,
    S: Serializer,
{
    let mut bytes: Vec<u8> = Vec::with_capacity(tree.leaves_len() * H::BYTE_LEN);
    if let Some(leaves) = tree.leaves() {
        for leaf in leaves {
            bytes.extend_from_slice(leaf.as_ref());
        }
    }

    serializer.serialize_bytes(&bytes)
}

fn merkle_tree_deserialize<'de, D, H>(deserializer: D) -> Result<rs_merkle::MerkleTree<H>, D::Error>
where
    H: Hasher,
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    let leaves = bytes
        .chunks(H::BYTE_LEN)
        .map(|c| {
            c.try_into()
                .map_err(|_| serde::de::Error::custom("invalid hash length"))
        })
        .collect::<Result<Vec<H::Hash>, _>>()?;

    Ok(rs_merkle::MerkleTree::<H>::from_leaves(&leaves))
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::*;

    impl CanonicalSerialize for u64 {
        fn serialize(&self) -> Vec<u8> {
            self.to_be_bytes().to_vec()
        }
    }

    // Expect Merkle proof verification to succeed
    #[rstest]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_verify_success(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let proof = tree.proof(&[2, 3, 4]);

        assert!(proof
            .verify(&tree.root(), &[2, 3, 4], &[2u64, 3u64, 4u64])
            .is_ok());
    }

    #[rstest]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_verify_fail_wrong_leaf(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let proof = tree.proof(&[2, 3, 4]);

        // fail because the leaf is wrong
        assert_eq!(
            proof
                .verify(&tree.root(), &[2, 3, 4], &[1u64, 3u64, 4u64])
                .err()
                .unwrap(),
            MerkleError::InvalidProof
        );
    }

    #[rstest]
    #[should_panic]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[should_panic]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[should_panic]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_proof_fail_length_unsorted(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        _ = tree.proof(&[2, 4, 3]);
    }

    #[rstest]
    #[should_panic]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[should_panic]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[should_panic]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_proof_fail_length_duplicates(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        _ = tree.proof(&[2, 2, 3]);
    }

    #[rstest]
    #[should_panic]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[should_panic]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[should_panic]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_verify_fail_length_mismatch(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let proof = tree.proof(&[2, 3, 4]);

        _ = proof.verify(&tree.root(), &[1, 2, 3, 4], &[2u64, 3u64, 4u64]);
    }

    #[rstest]
    #[should_panic]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[should_panic]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[should_panic]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_verify_fail_duplicates(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let proof = tree.proof(&[2, 3, 4]);

        _ = proof.verify(&tree.root(), &[2, 2, 3], &[2u64, 2u64, 3u64]);
    }

    #[rstest]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_verify_fail_incorrect_leaf_count(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let mut proof = tree.proof(&[2, 3, 4]);

        match &mut proof.0 {
            MerkleProofAlg::Sha256(inner) => inner.total_leaves = 6,
            MerkleProofAlg::Blake3(inner) => inner.total_leaves = 6,
            MerkleProofAlg::Keccak256(inner) => inner.total_leaves = 6,
        }

        // fail because leaf count is wrong
        assert!(proof
            .verify(&tree.root(), &[2, 3, 4], &[2u64, 3u64, 4u64])
            .is_err());
    }

    #[rstest]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_verify_fail_incorrect_indices(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let proof = tree.proof(&[2, 3, 4]);

        // fail because leaf index is wrong
        assert!(proof
            .verify(&tree.root(), &[1, 3, 4], &[2u64, 3u64, 4u64])
            .is_err());
    }

    #[rstest]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_verify_fail_fewer_indices(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let proof = tree.proof(&[2, 3, 4]);

        // trying to verify less leaves than what was included in the proof
        assert!(proof.verify(&tree.root(), &[3, 4], &[3u64, 4u64]).is_err());
    }

    #[rstest]
    #[case::sha2(HashAlgorithm::Sha256)]
    #[case::blake3(HashAlgorithm::Blake3)]
    #[case::keccak(HashAlgorithm::Keccak256)]
    fn test_merkle_tree_serialization(#[case] alg: HashAlgorithm) {
        let mut tree = MerkleTree::new(alg);
        for i in 0..=4 {
            tree.insert(&i)
        }

        let proof = tree.proof(&[2, 3, 4]);

        let tree2: MerkleTree = bincode::deserialize(&bincode::serialize(&tree).unwrap()).unwrap();
        let proof2: MerkleProof =
            bincode::deserialize(&bincode::serialize(&proof).unwrap()).unwrap();

        assert_eq!(tree.root(), tree2.root());
        assert!(proof2
            .verify(&tree.root(), &[2, 3, 4], &[2u64, 3u64, 4u64])
            .is_ok());
    }
}
