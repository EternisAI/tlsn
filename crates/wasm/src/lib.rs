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
        info!("Failed to initialize logging: {:?}", res.err());
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
        let signature_bytes = hex::decode("D754FEA3193F3115943BA6CD2DBF6FF88A32929D623B9D147514EF8313D9DD9B52EFA52A258C369695D304C1B5FF326895057B7C951A2D8A31B4C492505FB48C").expect("decode signature failed");
        println!("signature_bytes: {:?}", signature_bytes);

        let signature =
            Signature::from_slice(&signature_bytes).expect("Failed to decode signature");

        //message
        use sha2::{Digest, Sha256};
        let application_data = hex::decode("4745542068747470733a2f2f73776170692e6465762f6170692f70656f706c652f312f20485454502f312e310d0a686f73743a2073776170692e6465760d0a6163636570742d656e636f64696e673a206964656e746974790d0a7365632d66657463682d6d6f64653a20636f72730d0a6163636570742d6c616e67756167653a20656e2d55532c656e3b713d302e392c66722d46523b713d302e382c66723b713d302e372c656e2d46523b713d302e362c7a682d46523b713d302e352c7a683b713d302e342c61722d46523b713d302e332c61723b713d302e320d0a6163636570743a206170706c69636174696f6e2f6a736f6e2c20746578742f6a6176617363726970742c202a2f2a3b20713d302e30310d0a7365632d63682d75613a2022476f6f676c65204368726f6d65223b763d22313239222c20224e6f743d413f4272616e64223b763d2238222c20224368726f6d69756d223b763d22313239220d0a646e743a20310d0a7365632d66657463682d646573743a20656d7074790d0a726566657265723a2068747470733a2f2f73776170692e6465762f0d0a7365632d63682d75612d706c6174666f726d3a20224c696e7578220d0a636f6f6b69653a2063737266746f6b656e3d414d53436b6749554b696962434c48455357786c3033726e3645615055354b440d0a7365632d63682d75612d6d6f62696c653a203f300d0a7365632d66657463682d736974653a2073616d652d6f726967696e0d0a757365722d6167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29204368726f6d652f3132392e302e302e30205361666172692f3533372e33360d0a636f6e6e656374696f6e3a20636c6f73650d0a782d7265717565737465642d776974683a20584d4c48747470526571756573740d0a0d0a485454502f312e3120323030204f4b0d0a5365727665723a206e67696e782f312e31362e310d0a446174653a204d6f6e2c2033302053657020323032342032303a31323a303620474d540d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e0d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a436f6e6e656374696f6e3a20636c6f73650d0a566172793a204163636570742c20436f6f6b69650d0a582d4672616d652d4f7074696f6e733a2053414d454f524947494e0d0a455461673a20226565333938363130343335633332386634643061346531623064326637626263220d0a416c6c6f773a204745542c20484541442c204f5054494f4e530d0a5374726963742d5472616e73706f72742d53656375726974793a206d61782d6167653d31353736383030300d0a0d0a3238370d0a7b226e616d65223a224c756b6520536b7977616c6b6572222c22686569676874223a22313732222c226d617373223a223737222c22686169725f636f6c6f72223a22626c6f6e64222c22736b696e5f636f6c6f72223a2266616972222c226579655f636f6c6f72223a22626c7565222c2262697274685f79656172223a223139424259222c2267656e646572223a226d616c65222c22686f6d65776f726c64223a2268747470733a2f2f73776170692e6465762f6170692f706c616e6574732f312f222c2266696c6d73223a5b2268747470733a2f2f73776170692e6465762f6170692f66696c6d732f312f222c2268747470733a2f2f73776170692e6465762f6170692f66696c6d732f322f222c2268747470733a2f2f73776170692e6465762f6170692f66696c6d732f332f222c2268747470733a2f2f73776170692e6465762f6170692f66696c6d732f362f225d2c2273706563696573223a5b5d2c2276656869636c6573223a5b2268747470733a2f2f73776170692e6465762f6170692f76656869636c65732f31342f222c2268747470733a2f2f73776170692e6465762f6170692f76656869636c65732f33302f225d2c22737461727368697073223a5b2268747470733a2f2f73776170692e6465762f6170692f7374617273686970732f31322f222c2268747470733a2f2f73776170692e6465762f6170692f7374617273686970732f32322f225d2c2263726561746564223a22323031342d31322d30395431333a35303a35312e3634343030305a222c22656469746564223a22323031342d31322d32305432313a31373a35362e3839313030305a222c2275726c223a2268747470733a2f2f73776170692e6465762f6170692f70656f706c652f312f227d0d0a300d0a0d0a")
        .expect("couldn't decode app data");
        //println!("application_data: {:?}", application_data);

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
        let application_data = "statuses>100".as_bytes().to_vec();
        println!("application_data: {:?}", application_data);
        let application_data = hex::decode("73637265656e5f6e616d653d436f6c6f73737a73696e6765")
            .expect("decode hex app data failed");
        println!("application_data 2: {:?}", application_data);

        assert!(verifying_key.verify(&application_data, &signature).is_ok());
    }
}
