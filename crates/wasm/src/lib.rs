//! TLSNotary WASM bindings.

#![deny(unreachable_pub, unused_must_use, clippy::all)]
#![allow(non_snake_case)]

pub(crate) mod io;
mod log;
pub mod prover;

#[cfg(feature = "test")]
pub mod tests;
pub mod types;
pub mod verifier;

use log::LoggingConfig;
use tracing::{error, info};
use tracing_subscriber::{
    filter::FilterFn,
    fmt::{format::FmtSpan, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing_web::MakeWebConsoleWriter;
use wasm_bindgen::prelude::*;

use base64::engine::{general_purpose::STANDARD, Engine};
use hex;
use remote_attestation_verifier::{parse_document, parse_payload, verify};
#[cfg(feature = "test")]
pub use tests::*;

#[cfg(target_arch = "wasm32")]
pub use wasm_bindgen_rayon::init_thread_pool;

/// Initializes logging.
#[wasm_bindgen]
pub fn init_logging(config: Option<LoggingConfig>) {
    let mut config = config.unwrap_or_default();

    // Default is NONE
    let fmt_span = config
        .span_events
        .take()
        .unwrap_or_default()
        .into_iter()
        .map(FmtSpan::from)
        .fold(FmtSpan::NONE, |acc, span| acc | span);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        .with_span_events(fmt_span)
        .without_time()
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console

    let res = tracing_subscriber::registry()
        .with(FilterFn::new(log::filter(config)))
        .with(fmt_layer)
        .try_init();

    if res.is_err() {
        error!("Failed to initialize logging: {:?}", res.err());
    }

    // https://github.com/rustwasm/console_error_panic_hook
    std::panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));
}

use serde::Deserialize;
use tsify_next::Tsify;
#[derive(Debug, Default, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct AttestationDocument {
    pub protected: Option<String>,
    pub signature: Option<String>,
    pub payload: Option<String>,
    pub certificate: Option<String>,
}

#[wasm_bindgen]
pub fn verify_attestation_document(
    attestation_document: String,
    nonce: String,
    timestamp: u64,
) -> bool {
    info!("🔍 Starting verification.. {:?}", attestation_document);

    let attestation_document =
        base64::decode(attestation_document).expect("failed to decode document");

    let attestation_document =
        parse_document(&attestation_document).expect("parse cbor document failed");

    let nonce = hex::decode(nonce).expect("decode nonce failed");

    let payload = parse_payload(&attestation_document.payload).expect("parse payload failed");

    let verify_result = verify(attestation_document, payload, nonce, timestamp, None);

    info!("verify_result: {:?}", verify_result);

    match verify_result {
        Ok(()) => true,
        Err(_) => false,
    }
}
