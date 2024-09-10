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
use remote_attestation_verifier::{parse_cbor_document, verify};

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

    tracing_subscriber::registry()
        .with(FilterFn::new(log::filter(config)))
        .with(fmt_layer)
        .init();

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
pub fn verify_attestation_document(attestation_document: AttestationDocument) {
    info!("🔍 Starting verification..");

    // let document_data  = STANDARD.decode("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")
    //         .expect("decode cbor document failed");
    // //info!("document_data: {:?}", document_data);
    // let attestation_document =
    //     parse_cbor_document(&document_data).expect("parse cbor document failed");

    let protected = base64::decode(attestation_document.protected.expect("protected is null"))
        .expect("failed to decode protected")
        .try_into()
        .expect("failed to decode protected");
    let signature = base64::decode(attestation_document.signature.expect("signature is null"))
        .expect("failed to decode signature")
        .try_into()
        .expect("failed to decode signature");
    let payload = base64::decode(attestation_document.payload.expect("payload is null"))
        .expect("failed to decode payload")
        .try_into()
        .expect("failed to decode payload");
    let certificate = base64::decode(
        attestation_document
            .certificate
            .expect("certificate is null"),
    )
    .expect("failed to decode certificate")
    .try_into()
    .expect("failed to decode certificate");

    //info!("attestation_document: {:?}", attestation_document);

    let verify_result = verify(&protected, &signature, &payload, &certificate);
    info!("✅ Verification complete: {:?}", verify_result);
}
