//! TLSNotary core protocol library.
//!
//! This crate contains core types for the TLSNotary protocol, including some functionality for selective disclosure.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod attestation;
pub mod conn;
pub mod encoding;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod hash;
pub(crate) mod merkle;
pub(crate) mod serialize;
mod signature;
pub mod substring;
pub mod transcript;

pub use signature::{NotaryPublicKey, Signature};
pub use transcript::{Direction, PartialTranscript, Transcript};

pub(crate) mod sealed {
    /// A sealed trait.
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}

/// A validation error.
#[derive(Debug, thiserror::Error)]
#[error("validation error: {0}")]
pub struct ValidationError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl ValidationError {
    pub(crate) fn new<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(err.into())
    }
}
