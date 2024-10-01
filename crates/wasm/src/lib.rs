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
) -> bool {
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
    let application_data = hex::decode(hex_application_data).expect("decode hex app data failed");
    let mut hasher = Sha256::new();
    hasher.update(&application_data);
    let hash = hasher.finalize();

    verifying_key.verify(&hash, &signature).is_ok()
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
        let signature_bytes = hex::decode("B2988F14660CA46B1D64D617AE239D0BF29740C8ED06587BEDE3FE29991FE3935EA6B3E913A9EBAEAC5D930560167A08C7577A1F9509B25599BA6437DD55E750").expect("decode signature failed");
        println!("signature_bytes: {:?}", signature_bytes);

        let signature =
            Signature::from_slice(&signature_bytes).expect("Failed to decode signature");

        //message
        use sha2::{Digest, Sha256};
        let application_data = hex::decode("4745542068747470733a2f2f64756d6d796a736f6e2e636f6d2f70726f64756374732f3120485454502f312e310d0a636f6e6e656374696f6e3a20636c6f73650d0a686f73743a2064756d6d796a736f6e2e636f6d0d0a636f6e74656e742d6c656e6774683a20320d0a0d0a7b7d485454502f312e3120323030204f4b0d0a5265706f72742d546f3a207b2267726f7570223a226865726f6b752d6e656c222c226d61785f616765223a333630302c22656e64706f696e7473223a5b7b2275726c223a2268747470733a2f2f6e656c2e6865726f6b752e636f6d2f7265706f7274733f74733d31373237373638383835267369643d65313137303764352d303261372d343365662d623435652d32636634643230333666376426733d34304b69437a4925324673334c6364777a30756b6452636a324741397157557058563653354575616933666467253344227d5d7d0d0a5265706f7274696e672d456e64706f696e74733a206865726f6b752d6e656c3d68747470733a2f2f6e656c2e6865726f6b752e636f6d2f7265706f7274733f74733d31373237373638383835267369643d65313137303764352d303261372d343365662d623435652d32636634643230333666376426733d34304b69437a4925324673334c6364777a30756b6452636a3247413971575570585636533545756169336664672533440d0a4e656c3a207b227265706f72745f746f223a226865726f6b752d6e656c222c226d61785f616765223a333630302c22737563636573735f6672616374696f6e223a302e3030352c226661696c7572655f6672616374696f6e223a302e30352c22726573706f6e73655f68656164657273223a5b22566961225d7d0d0a436f6e6e656374696f6e3a20636c6f73650d0a4163636573732d436f6e74726f6c2d416c6c6f772d4f726967696e3a202a0d0a582d446e732d50726566657463682d436f6e74726f6c3a206f66660d0a582d4672616d652d4f7074696f6e733a2053414d454f524947494e0d0a5374726963742d5472616e73706f72742d53656375726974793a206d61782d6167653d31353535323030303b20696e636c756465537562446f6d61696e730d0a582d446f776e6c6f61642d4f7074696f6e733a206e6f6f70656e0d0a582d436f6e74656e742d547970652d4f7074696f6e733a206e6f736e6966660d0a582d5873732d50726f74656374696f6e3a20313b206d6f64653d626c6f636b0d0a582d506f77657265642d42793a2043617473206f6e204b6579626f617264730d0a5365727665723a20426f625468654275696c6465720d0a582d526174656c696d69742d4c696d69743a203130300d0a582d526174656c696d69742d52656d61696e696e673a2039390d0a446174653a205475652c203031204f637420323032342030373a34383a303520474d540d0a582d526174656c696d69742d52657365743a20313732373736383839310d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e3b20636861727365743d7574662d380d0a436f6e74656e742d4c656e6774683a20313531330d0a457461673a20572f223565392d724e43734856684836586e573854394235766a64396d58552b7063220d0a566172793a204163636570742d456e636f64696e670d0a5669613a20312e312076656775720d0a0d0a7b226964223a312c227469746c65223a22457373656e6365204d617363617261204c617368205072696e63657373222c226465736372697074696f6e223a2254686520457373656e6365204d617363617261204c617368205072696e63657373206973206120706f70756c6172206d617363617261206b6e6f776e20666f722069747320766f6c756d697a696e6720616e64206c656e677468656e696e6720656666656374732e2041636869657665206472616d61746963206c617368657320776974682074686973206c6f6e672d6c617374696e6720616e6420637275656c74792d6672656520666f726d756c612e222c2263617465676f7279223a22626561757479222c227072696365223a392e39392c22646973636f756e7450657263656e74616765223a372e31372c22726174696e67223a342e39342c2273746f636b223a352c2274616773223a5b22626561757479222c226d617363617261225d2c226272616e64223a22457373656e6365222c22736b75223a225243483435513141222c22776569676874223a322c2264696d656e73696f6e73223a7b227769647468223a32332e31372c22686569676874223a31342e34332c226465707468223a32382e30317d2c2277617272616e7479496e666f726d6174696f6e223a2231206d6f6e74682077617272616e7479222c227368697070696e67496e666f726d6174696f6e223a22536869707320696e2031206d6f6e7468222c22617661696c6162696c697479537461747573223a224c6f772053746f636b222c2272657669657773223a5b7b22726174696e67223a322c22636f6d6d656e74223a225665727920756e68617070792077697468206d7920707572636861736521222c2264617465223a22323032342d30352d32335430383a35363a32312e3631385a222c2272657669657765724e616d65223a224a6f686e20446f65222c227265766965776572456d61696c223a226a6f686e2e646f6540782e64756d6d796a736f6e2e636f6d227d2c7b22726174696e67223a322c22636f6d6d656e74223a224e6f742061732064657363726962656421222c2264617465223a22323032342d30352d32335430383a35363a32312e3631385a222c2272657669657765724e616d65223a224e6f6c616e20476f6e7a616c657a222c227265766965776572456d61696c223a226e6f6c616e2e676f6e7a616c657a40782e64756d6d796a736f6e2e636f6d227d2c7b22726174696e67223a352c22636f6d6d656e74223a22566572792073617469736669656421222c2264617465223a22323032342d30352d32335430383a35363a32312e3631385a222c2272657669657765724e616d65223a22536361726c65747420577269676874222c227265766965776572456d61696c223a22736361726c6574742e77726967687440782e64756d6d796a736f6e2e636f6d227d5d2c2272657475726e506f6c696379223a22333020646179732072657475726e20706f6c696379222c226d696e696d756d4f726465725175616e74697479223a32342c226d657461223a7b22637265617465644174223a22323032342d30352d32335430383a35363a32312e3631385a222c22757064617465644174223a22323032342d30352d32335430383a35363a32312e3631385a222c22626172636f6465223a2239313634303335313039383638222c227172436f6465223a2268747470733a2f2f6173736574732e64756d6d796a736f6e2e636f6d2f7075626c69632f71722d636f64652e706e67227d2c22696d61676573223a5b2268747470733a2f2f63646e2e64756d6d796a736f6e2e636f6d2f70726f64756374732f696d616765732f6265617574792f457373656e63652532304d6173636172612532304c6173682532305072696e636573732f312e706e67225d2c227468756d626e61696c223a2268747470733a2f2f63646e2e64756d6d796a736f6e2e636f6d2f70726f64756374732f696d616765732f6265617574792f457373656e63652532304d6173636172612532304c6173682532305072696e636573732f7468756d626e61696c2e706e67227d").expect("decode hex app data failed");
        let mut hasher = Sha256::new();
        hasher.update(&application_data);
        let hash = hasher.finalize();

        assert!(verifying_key.verify(&hash, &signature).is_ok());
    }
}
