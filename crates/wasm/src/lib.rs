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

use base64::engine::{general_purpose, Engine};
use hex;
use log::LoggingConfig;
use remote_attestation_verifier::parse_verify_with;
#[cfg(feature = "test")]
pub use tests::*;
use tracing::{error, info};
use tracing_subscriber::{
    filter::FilterFn,
    fmt::{format::FmtSpan, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing_web::MakeWebConsoleWriter;
use wasm_bindgen::prelude::*;

use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    PublicKey, SecretKey,
};
use rand_core::OsRng;

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
    pcrs: Vec<String>,
    timestamp: u64,
) -> bool {
    info!("🔍 Starting verification.. {:?}", attestation_document);

    let attestation_document = general_purpose::STANDARD
        .decode(attestation_document)
        .expect("failed to decode document");

    let nonce = hex::decode(nonce).expect("decode nonce failed");

    let verify_result = parse_verify_with(
        attestation_document,
        nonce,
        pcrs.into_iter()
            .map(|s| hex::decode(s).expect("decode pcrs failed"))
            .collect(),
        timestamp,
    );

    info!("verify_result: {:?}", verify_result);

    match verify_result {
        Ok(()) => true,
        Err(_) => false,
    }
}

#[wasm_bindgen]
pub fn verify_attestation_signature(
    hex_application_data: String,
    hex_raw_signature: String,
    hex_raw_public_key: String,
    hash_appdata: bool,
) -> bool {
    info!("🔍 Starting verification of attestation signature..");
    info!(
        "\n{:?}\n {:?} \n{:?}",
        hex_raw_public_key, hex_application_data, hex_raw_signature
    );
    let bytes_public_key = hex::decode(hex_raw_public_key).expect("decode public key failed");

    println!("bytes_public_key: {:?}", bytes_public_key);
    let verifying_key = VerifyingKey::from_sec1_bytes(bytes_public_key.as_slice())
        .expect("decode P256 public key failed");

    //signature
    let signature_bytes = hex::decode(hex_raw_signature).expect("decode signature failed");
    println!("signature_bytes: {:?}", signature_bytes);

    let signature = Signature::from_slice(&signature_bytes).expect("Failed to decode signature");

    //message
    use sha2::{Digest, Sha256};
    let mut application_data =
        hex::decode(hex_application_data).expect("decode hex app data failed");

    if hash_appdata {
        let mut hasher = Sha256::new();
        hasher.update(&application_data);
        application_data = hasher.finalize().to_vec();
    }

    verifying_key.verify(&application_data, &signature).is_ok()
}

mod test {
    use crate::*;

    #[test]
    fn test_sign_p256() {
        // Generate a random private key
        let signing_key = SigningKey::random(&mut OsRng);

        // Message to be signed
        let message = b"test message";

        // Sign the message
        let signature: Signature = signing_key.sign(message);

        // Convert signature to bytes
        let signature_bytes = signature.to_der().as_bytes().to_vec();

        println!("Signature: {:?}", signature_bytes);

        // Verify the signature (optional, for demonstration)

        let verifying_key = VerifyingKey::from(&signing_key);

        println!("verifying_key: {:?}", verifying_key.to_sec1_bytes());
        assert!(verifying_key.verify(message, &signature).is_ok());
        println!("test");
    }

    #[test]
    fn test_verify_p256() {
        //notary public key in raw bytes format (not PEM)
        let bytes_public_key = hex::decode("0406fdfa148e1916ccc96b40d0149df05825ef54b16b711ccc1b991a4de1c6a12cc3bba705ab1dee116629146a3a0b410e5207fe98481b92d2eb5e872fe721f32a").expect("decode hex public key failed");

        println!("bytes_public_key: {:?}", bytes_public_key);
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes_public_key.as_slice())
            .expect("decode P256 public key failed");

        //signature
        let signature_bytes = hex::decode("CD0CD9AFF36378D602DA746E9411582D48074ECD04727CBBC5CC0C5A5681C1C2FCF4BA1A35E9E2FCEBAD22C843E95B04C5E595D04259F9ACE1D23FF41C07921E").expect("decode signature failed");
        println!("signature_bytes: {:?}", signature_bytes);

        let signature =
            Signature::from_slice(&signature_bytes).expect("Failed to decode signature");

        //message
        use sha2::{Digest, Sha256};
        let application_data = "statuses>100".as_bytes().to_vec();
        println!("application_data: {:?}", application_data);
        let application_data =
            hex::decode("73746174757365733e313030").expect("decode hex app data failed");
        println!("application_data 2: {:?}", application_data);

        let mut hasher = Sha256::new();
        hasher.update(&application_data);
        let hash = hasher.finalize();

        assert!(verifying_key.verify(&hash, &signature).is_ok());
    }

    #[test]
    fn test_verify_attribute_p256() {
        //notary public key in raw bytes format (not PEM)
        let bytes_public_key = hex::decode("0406fdfa148e1916ccc96b40d0149df05825ef54b16b711ccc1b991a4de1c6a12cc3bba705ab1dee116629146a3a0b410e5207fe98481b92d2eb5e872fe721f32a").expect("decode hex public key failed");

        println!("bytes_public_key: {:?}", bytes_public_key);
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes_public_key.as_slice())
            .expect("decode P256 public key failed");

        //signature
        let signature_bytes = hex::decode("B12101687A474B23E197CBAFEF17600756783BDDB551A72EDFD7C4CBE82135BF118F4562FE187A3E9D51C5F41357BCDA6E53CB16DC77E1AC12464DA56EBB3E66").expect("decode signature failed");
        println!("signature_bytes: {:?}", signature_bytes);

        let signature =
            Signature::from_slice(&signature_bytes).expect("Failed to decode signature");

        //message
        use sha2::{Digest, Sha256};
        let application_data = "statuses>100".as_bytes().to_vec();
        println!("application_data: {:?}", application_data);
        let application_data = hex::decode("73637265656e5f6e616d653d436f6c6f73737a73696e6765")
            .expect("decode hex app data failed");
        println!("application_data 2: {:?}", application_data);

        assert!(verifying_key.verify(&application_data, &signature).is_ok());
    }
}
