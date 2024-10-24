//! Common code shared between `tlsn-prover` and `tlsn-verifier`.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod config;
pub mod mux;

use serio::codec::Codec;

#[cfg(feature = "mpz")]
use crate::mux::MuxControl;

/// IO type.
pub type Io = <serio::codec::Bincode as Codec<uid_mux::yamux::Stream>>::Framed;
/// Base OT sender.
#[cfg(feature = "mpz")]
pub type BaseOTSender = mpz_ot::chou_orlandi::Sender;
/// Base OT receiver.
#[cfg(feature = "mpz")]
pub type BaseOTReceiver = mpz_ot::chou_orlandi::Receiver;
/// OT sender.
#[cfg(feature = "mpz")]
pub type OTSender = mpz_ot::kos::SharedSender<BaseOTReceiver>;
/// OT receiver.
#[cfg(feature = "mpz")]
pub type OTReceiver = mpz_ot::kos::SharedReceiver<BaseOTSender>;
/// MPC executor.
#[cfg(feature = "mpz")]
pub type Executor = mpz_common::executor::MTExecutor<MuxControl>;
/// MPC thread context.
#[cfg(feature = "mpz")]
pub type Context = mpz_common::executor::MTContext<MuxControl, Io>;
/// DEAP thread.
#[cfg(feature = "mpz")]
pub type DEAPThread = mpz_garble::protocol::deap::DEAPThread<Context, OTSender, OTReceiver>;

/// The party's role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
pub enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}
