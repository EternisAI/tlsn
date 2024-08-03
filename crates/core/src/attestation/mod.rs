//! Attestation types.

mod builder;
mod proof;

use std::{collections::HashMap, vec};

use serde::{Deserialize, Serialize};

use crate::{
    conn::{
        CertificateSecrets, ConnectionInfo, HandshakeData, ServerIdentity, ServerIdentityProof,
    },
    encoding::{EncodingCommitment, EncodingTree},
    hash::{Hash, HashAlgorithmId, PlaintextHash, PlaintextHashProof, TypedHash},
    merkle::MerkleTree,
    serialize::CanonicalSerialize,
    substring::{SubstringProof, SubstringProofConfig, SubstringProofConfigBuilder},
    transcript::SubsequenceIdx,
    Signature, Transcript, ValidationError,
};

pub use builder::AttestationBodyBuilder;
pub use proof::{
    AttestationProof, AttestationProofError, AttestationProofOutput, BodyProof, BodyProofError,
};

/// The current version of attestations.
pub static ATTESTATION_VERSION: AttestationVersion = AttestationVersion(0);

pub(crate) const ATTESTATION_VERSION_LEN: usize = 4;
pub(crate) const ATTESTATION_ID_LEN: usize = 16;

/// An attestation error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// Attestation is missing a field.
    #[error("missing field: {0:?}")]
    MissingField(FieldKind),
    /// Attestation is missing a secret.
    #[error("missing secret: {0:?}")]
    MissingSecret(SecretKind),
    /// Attestation is missing a commitment for a substring.
    #[error("missing substring commitment: {0:?}")]
    MissingSubstringCommitment(SubsequenceIdx),
}

/// An identifier for an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationId(pub [u8; ATTESTATION_ID_LEN]);

impl From<[u8; ATTESTATION_ID_LEN]> for AttestationId {
    fn from(id: [u8; ATTESTATION_ID_LEN]) -> Self {
        Self(id)
    }
}

/// The version of an attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationVersion(u32);

impl AttestationVersion {
    pub(crate) fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// A secret hidden from the Notary.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Secret {
    /// The certificate chain and signature.
    #[serde(rename = "cert")]
    Certificate(CertificateSecrets),
    /// The server's identity.
    #[serde(rename = "server_identity")]
    ServerIdentity(ServerIdentity),
    /// A merkle tree of transcript encodings.
    #[serde(rename = "encoding")]
    EncodingTree(EncodingTree),
    /// A hash of a range of plaintext in the transcript.
    #[serde(rename = "hash")]
    PlaintextHash {
        /// The subsequence of the transcript.
        seq: SubsequenceIdx,
        /// The nonce which was hashed with the plaintext.
        nonce: [u8; 16],
        /// The id of the plaintext hash public field.
        commitment: FieldId,
    },
}

opaque_debug::implement!(Secret);

impl Secret {
    /// Returns the kind of the secret.
    pub fn kind(&self) -> SecretKind {
        match self {
            Secret::Certificate(_) => SecretKind::Certificate,
            Secret::ServerIdentity(_) => SecretKind::ServerIdentity,
            Secret::EncodingTree(_) => SecretKind::EncodingTree,
            Secret::PlaintextHash { .. } => SecretKind::PlaintextHash,
        }
    }
}

/// The kind of a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SecretKind {
    /// The certificate chain and signature.
    Certificate = 0x00,
    /// The server's identity.
    ServerIdentity = 0x01,
    /// A merkle tree of transcript encodings.
    EncodingTree = 0x02,
    /// A hash of a range of plaintext in the transcript.
    PlaintextHash = 0x03,
}

/// The data of a public attestation field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldData<T>(T);

impl<T> FieldData<T> {
    pub(crate) fn to_inner(self) -> T {
        self.0
    }

    pub(crate) fn inner(&self) -> &T {
        &self.0
    }
}

impl<T: FieldKinded + CanonicalSerialize> CanonicalSerialize for FieldData<T> {
    fn serialize(&self) -> Vec<u8> {
        let Self(data) = self;

        let mut bytes = Vec::new();
        bytes.push(data.kind() as u8);
        bytes.extend_from_slice(&data.serialize());
        bytes
    }
}

/// A public attestation field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field<T> {
    id: FieldId,
    data: FieldData<T>,
}

impl<T> Field<T> {
    pub(crate) fn new(id: FieldId, data: T) -> Self {
        Self {
            id,
            data: FieldData(data),
        }
    }

    pub(crate) fn id(&self) -> FieldId {
        self.id
    }

    pub(crate) fn data(&self) -> &FieldData<T> {
        &self.data
    }
}

/// A field with a kind.
trait FieldKinded {
    /// Returns the kind of the field.
    fn kind(&self) -> FieldKind;
}

/// The kind of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FieldKind {
    /// TLS connection information.
    ConnectionInfo = 0x00,
    /// TLS handshake data.
    HandshakeData = 0x01,
    /// Commitment to the server's certificate and signature.
    CertificateCommitment = 0x02,
    /// Commitment to the certificate chain.
    CertificateChainCommitment = 0x03,
    /// Commitment to the encodings of the transcript plaintext.
    EncodingCommitment = 0x04,
    /// A hash of a range of plaintext in the transcript.
    PlaintextHash = 0x05,
    /// Arbitrary extra data bound to the attestation.
    ExtraData = 0xff,
}

impl FieldKinded for ConnectionInfo {
    fn kind(&self) -> FieldKind {
        FieldKind::ConnectionInfo
    }
}

impl FieldKinded for HandshakeData {
    fn kind(&self) -> FieldKind {
        FieldKind::HandshakeData
    }
}

impl FieldKinded for EncodingCommitment {
    fn kind(&self) -> FieldKind {
        FieldKind::EncodingCommitment
    }
}

/// A commitment to the server certificate and signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertCommitment(pub(crate) Hash);

impl FieldKinded for CertCommitment {
    fn kind(&self) -> FieldKind {
        FieldKind::CertificateCommitment
    }
}

impl CanonicalSerialize for CertCommitment {
    fn serialize(&self) -> Vec<u8> {
        CanonicalSerialize::serialize(&self.0)
    }
}

/// A commitment to the certificate chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChainCommitment(pub(crate) Hash);

impl FieldKinded for CertChainCommitment {
    fn kind(&self) -> FieldKind {
        FieldKind::CertificateChainCommitment
    }
}

impl CanonicalSerialize for CertChainCommitment {
    fn serialize(&self) -> Vec<u8> {
        CanonicalSerialize::serialize(&self.0)
    }
}

/// Extra data bound a the attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraData(Vec<u8>);

impl FieldKinded for ExtraData {
    fn kind(&self) -> FieldKind {
        FieldKind::ExtraData
    }
}

impl CanonicalSerialize for ExtraData {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.0);
        bytes
    }
}

/// An identifier for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldId(pub u32);

impl FieldId {
    pub(crate) fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

/// An attestation header.
///
/// A header is the data structure which is signed by the Notary. It contains
/// a unique identifier, the protocol version, and a Merkle root of the
/// attestation fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationHeader {
    /// An identifier for the attestation.
    pub id: AttestationId,
    /// Version of the attestation.
    pub version: AttestationVersion,
    /// Merkle root of the attestation fields.
    pub root: TypedHash,
}

impl AttestationHeader {
    /// Serializes the header to its canonical form.
    pub fn serialize(&self) -> Vec<u8> {
        CanonicalSerialize::serialize(self)
    }
}

/// A complete attestation body.
///
/// An attestation contains a set of fields which are cryptographically signed by
/// the Notary via an [`AttestationHeader`]. These fields include data which can be
/// used to verify aspects of a TLS connection, such as the server's identity, and facts
/// about the transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBody {
    conn_info: Field<ConnectionInfo>,
    handshake_data: Field<HandshakeData>,
    cert_commitment: Field<CertCommitment>,
    cert_chain_commitment: Field<CertChainCommitment>,
    encoding_commitment: Option<Field<EncodingCommitment>>,
    plaintext_hashes: Vec<Field<PlaintextHash>>,
    extra_data: Vec<Field<ExtraData>>,
}

impl AttestationBody {
    /// Computes the Merkle root of the attestation fields.
    pub(crate) fn root(&self, alg: HashAlgorithmId) -> Hash {
        let mut tree = MerkleTree::new(alg);
        for (_, field) in self.sorted_fields() {
            tree.insert(field)
        }
        tree.root()
    }

    pub(crate) fn sorted_fields(&self) -> Vec<(&FieldId, &dyn CanonicalSerialize)> {
        let mut fields: Vec<(&FieldId, &dyn CanonicalSerialize)> = vec![
            (&self.conn_info.id, &self.conn_info.data),
            (&self.handshake_data.id, &self.handshake_data.data),
            (&self.cert_commitment.id, &self.cert_commitment.data),
            (
                &self.cert_chain_commitment.id,
                &self.cert_chain_commitment.data,
            ),
        ];

        if let Some(encoding_commitment) = &self.encoding_commitment {
            fields.push((&encoding_commitment.id, &encoding_commitment.data));
        }

        for field in &self.extra_data {
            fields.push((&field.id, &field.data));
        }

        fields.sort_by_key(|(id, _)| *id);
        fields
    }

    pub(crate) fn conn_info(&self) -> &ConnectionInfo {
        &self.conn_info.data.0
    }

    pub(crate) fn handshake_data(&self) -> &HandshakeData {
        &self.handshake_data.data.0
    }

    pub(crate) fn cert_commitment(&self) -> &CertCommitment {
        &self.cert_commitment.data.0
    }

    pub(crate) fn cert_chain_commitment(&self) -> &CertChainCommitment {
        &self.cert_chain_commitment.data.0
    }

    pub(crate) fn encoding_commitment(&self) -> Option<&EncodingCommitment> {
        self.encoding_commitment.as_ref().map(|field| &field.data.0)
    }

    pub(crate) fn plaintext_hashes(&self) -> impl Iterator<Item = &Field<PlaintextHash>> {
        self.plaintext_hashes.iter()
    }
}

/// An attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// The signature of the attestation.
    pub sig: Signature,
    /// The attestation header.
    pub header: AttestationHeader,
    /// The attestation body.
    pub body: AttestationBody,
}

impl Attestation {
    /// Creates a new attestation builder.
    pub fn builder() -> AttestationBodyBuilder {
        AttestationBodyBuilder::default()
    }
}

/// The full data of an attestation, including private fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationFull {
    /// The signature of the attestation.
    pub sig: Signature,
    /// The attestation header.
    pub header: AttestationHeader,
    /// The attestation body.
    pub body: AttestationBody,
    /// Transcript of data communicated between the Prover and the Server.
    pub transcript: Transcript,
    /// Secret data of the attestation.
    pub secrets: Vec<Secret>,
}

impl AttestationFull {
    /// Returns the attestation.
    pub fn to_attestation(&self) -> Attestation {
        Attestation {
            sig: self.sig.clone(),
            header: self.header.clone(),
            body: self.body.clone(),
        }
    }

    /// Returns a server identity proof.
    pub fn identity_proof(&self) -> Result<ServerIdentityProof, AttestationError> {
        let cert_secrets = self
            .secrets
            .iter()
            .find_map(|secret| match secret {
                Secret::Certificate(cert_secrets) => Some(cert_secrets),
                _ => None,
            })
            .ok_or_else(|| AttestationError::MissingSecret(SecretKind::Certificate))?;

        let identity = self
            .secrets
            .iter()
            .find_map(|secret| match secret {
                Secret::ServerIdentity(identity) => Some(identity.clone()),
                _ => None,
            })
            .ok_or_else(|| AttestationError::MissingSecret(SecretKind::ServerIdentity))?;

        Ok(ServerIdentityProof {
            cert_secrets: cert_secrets.clone(),
            identity,
        })
    }

    /// Returns a substring proof config builder.
    pub fn substring_proof_config_builder(&self) -> SubstringProofConfigBuilder {
        SubstringProofConfigBuilder::new(&self.transcript)
    }

    /// Returns a substring proof.
    pub fn substring_proof(
        &self,
        config: &SubstringProofConfig,
    ) -> Result<SubstringProof, AttestationError> {
        let mut hash_proofs = Vec::new();
        let mut encoding_idx = Vec::new();
        let encoding_tree = self.get_encoding_tree();
        for idx in config.iter() {
            // Prefer hash proofs if available, otherwise check if the subsequence
            // is present in the encoding tree. If neither is present we return an error.
            if let Some((nonce, commitment)) = self.get_hash_secret(idx) {
                let (_, data) = self
                    .transcript
                    .get_subsequence(idx)
                    .expect("subsequence was checked to be in transcript")
                    .into_parts();

                hash_proofs.push(PlaintextHashProof {
                    data,
                    nonce: *nonce,
                    commitment: *commitment,
                });
            } else if encoding_tree
                .map(|tree| tree.contains(idx))
                .unwrap_or_default()
            {
                encoding_idx.push(idx);
            } else {
                return Err(AttestationError::MissingSubstringCommitment(idx.clone()));
            }
        }

        let encoding_proof = if !encoding_idx.is_empty() {
            let encoding_tree = encoding_tree.expect("encoding tree is present");
            let proof = encoding_tree
                .proof(&self.transcript, encoding_idx.into_iter())
                .expect("subsequences were checked to be in tree");
            Some(proof)
        } else {
            None
        };

        Ok(SubstringProof {
            encoding_proof,
            hash_proofs,
        })
    }

    fn get_hash_secret(&self, idx: &SubsequenceIdx) -> Option<(&[u8; 16], &FieldId)> {
        self.secrets.iter().find_map(|secret| match secret {
            Secret::PlaintextHash {
                seq,
                nonce,
                commitment,
            } if seq == idx => Some((nonce, commitment)),
            _ => None,
        })
    }

    fn get_encoding_tree(&self) -> Option<&EncodingTree> {
        self.secrets.iter().find_map(|secret| match secret {
            Secret::EncodingTree(tree) => Some(tree),
            _ => None,
        })
    }
}
