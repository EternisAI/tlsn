//! AWS Nitro Enclave Document material
//!
//! ## Authors
//!
//! @asa93 for Eternis.AI
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the repo for
//! information on licensing and copyright.
#![no_std]
pub mod remote_attestation_verifier {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use core::convert::TryInto;
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use rand_core::RngCore;
    use rsa::signature::SignerMut;
    use rsa::signature::Verifier;
    // use std::collections::BTreeMap;
    // use std::io::Read;
    use x509_cert::der::Encode;
    use x509_cert::{der::Decode, Certificate};

    #[derive(Debug)]
    struct AttestationDocument {
        protected: [u8; 4],
        payload: [u8; 4448],
        signature: [u8; 96],
        certificate: [u8; 640],
    }

    const DEFAULT_ENCLAVE_ENDPOINT: &str = "https://tlsn.eternis.ai/enclave/attestation";
    const DEFAULT_ROOT_CERT_PATH: &str = "src/aws_root.pem";

    pub fn verify(
        _protected: &[u8; 4],
        _signature: &[u8; 96],
        _payload: &[u8; 4448],
        _certificate: &[u8; 640],
    ) -> Result<(), p384::ecdsa::Error> {
        //@ok parse public key, convert from der to sec1 format
        let cert = x509_cert::Certificate::from_der(_certificate).expect("decode x509 cert failed");

        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("public key der failed");

        //println!("public key der: {:?}", public_key.clone());
        //sec1 doesnt comprise der headers
        let public_key = &public_key[public_key.len() - 97..];
        //println!("public key sec1: {:?}", hex::encode(public_key));

        //@ok public key valid
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");

        // Create a Signature object from the raw signature bytes
        let signature = Signature::from_slice(_signature).expect("Invalid signature");

        //@ok parse sign structure = message
        //correspond to Signature1D
        const HEADER: [u8; 13] = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
        let protected = _protected;
        //@todo sometimes last byte is 96 sometimes 95, need to figure out why
        const FILLER: [u8; 4] = [64, 89, 17, 96];
        let payload = _payload;

        let sign_structure = [
            HEADER.as_ref(),
            protected.as_ref(),
            FILLER.as_ref(),
            payload.as_ref(),
        ]
        .concat();

        //println!("pcrs: {:?}", document.pcrs);
        //@ok
        // Verify the signature
        verifying_key.verify(&sign_structure, &signature)
    }

    fn parse_cbor_document(document: &[u8]) -> Result<AttestationDocument, ()> {
        use serde_cbor;
        let document: serde_cbor::Value = serde_cbor::from_slice(&document).expect("");

        let elements = match document {
            serde_cbor::Value::Array(elements) => elements,
            _ => panic!(
                "AttestationVerifier::parse Unknown field cbor:{:?}",
                document
            ),
        };

        let protected = elements.get(0).expect("protected not found");
        let payload = elements.get(2).expect("payload not found");
        let signature = elements.get(3).expect("signature not found");

        //let payload: serde_cbor::Value = serde_cbor::from_slice(&payload).expect("");

        let protected_bytes: [u8; 5] = serde_cbor::to_vec(&protected)
            .expect("failed to parse protected")
            .try_into()
            .expect("error slice protected");

        let signature_bytes: [u8; 98] = serde_cbor::to_vec(&signature)
            .expect("failed to parse signature")
            .try_into()
            .expect("error slice signature");

        let payload_bytes: [u8; 4451] = serde_cbor::to_vec(&payload)
            .expect("failed to parse signature")
            .try_into()
            .expect("error slice signature");

        let payload: serde_cbor::Value =
            serde_cbor::from_slice(&payload_bytes[3..]).expect("failed to parse payload");

        let payload = match payload {
            serde_cbor::Value::Map(elements) => elements,
            _ => panic!("Failed to decode CBOR payload:{:?}", payload),
        };

        let certificate = payload
            .get(&serde_cbor::Value::Text("certificate".try_into().unwrap()))
            .expect("certificate not found");

        //println!("certificate: {:?}", certificate);

        let certifcate_bytes: [u8; 643] = serde_cbor::to_vec(&certificate)
            .expect("failed to parse signature")
            .try_into()
            .expect("error slice signature");

        //println!("certifcate_bytes: {:?}", certifcate_bytes);

        Ok(AttestationDocument {
            protected: protected_bytes[1..]
                .try_into()
                .expect("protected slice with incorrect length"),
            payload: payload_bytes[3..]
                .try_into()
                .expect("payload slice with incorrect length"),
            signature: signature_bytes[2..]
                .try_into()
                .expect("signature slice with incorrect length"),
            certificate: certifcate_bytes[3..]
                .try_into()
                .expect("certificate slice with incorrect length"),
        })
    }

    // fn parse(document_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    //     let cbor: serde_cbor::Value = serde_cbor::from_slice(document_data)
    //         .map_err(|err| format!("AttestationVerifier::parse from_slice failed:{:?}", err))?;
    //     let elements = match cbor {
    //         serde_cbor::Value::Array(elements) => elements,
    //         _ => panic!("AttestationVerifier::parse Unknown field cbor:{:?}", cbor),
    //     };
    //     let protected = match &elements[0] {
    //         serde_cbor::Value::Bytes(prot) => prot,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field protected:{:?}",
    //             elements[0]
    //         ),
    //     };
    //     let _unprotected = match &elements[1] {
    //         serde_cbor::Value::Map(unprot) => unprot,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field unprotected:{:?}",
    //             elements[1]
    //         ),
    //     };
    //     let payload = match &elements[2] {
    //         serde_cbor::Value::Bytes(payld) => payld,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field payload:{:?}",
    //             elements[2]
    //         ),
    //     };
    //     let signature = match &elements[3] {
    //         serde_cbor::Value::Bytes(sig) => sig,
    //         _ => panic!(
    //             "AttestationVerifier::parse Unknown field signature:{:?}",
    //             elements[3]
    //         ),
    //     };
    //     Ok((protected.to_vec(), payload.to_vec(), signature.to_vec()))
    // }

    // fn parse_payload(payload: &Vec<u8>) -> Result<AttestationDocument, String> {
    //     let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
    //         .map_err(|err| format!("document parse failed:{:?}", err))?;
    //     let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
    //         serde_cbor::Value::Map(map) => map,
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload field ain't what it should be:{:?}",
    //                 document_data
    //             ))
    //         }
    //     };
    //     let module_id = match document_map.get(&serde_cbor::Value::Text(
    //         "module_id".try_into().expect("module_id_fail"),
    //     )) {
    //         Some(serde_cbor::Value::Text(val)) => val.to_string(),
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload module_id is wrong type or not present"
    //             ))
    //         }
    //     };
    //     let timestamp: i128 =
    //         match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
    //             Some(serde_cbor::Value::Integer(val)) => *val,
    //             _ => {
    //                 return Err(format!(
    //                     "AttestationVerifier::parse_payload timestamp is wrong type or not present"
    //                 ))
    //             }
    //         };
    //     let timestamp: u64 = timestamp.try_into().map_err(|err| {
    //         format!(
    //             "AttestationVerifier::parse_payload failed to convert timestamp to u64:{:?}",
    //             err
    //         )
    //     })?;
    //     let public_key: Option<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
    //             Some(_null) => None,
    //             None => None,
    //         };
    //     let certificate: Vec<u8> =
    //         match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
    //             _ => {
    //                 return Err(format!(
    //                 "AttestationVerifier::parse_payload certificate is wrong type or not present"
    //             ))
    //             }
    //         };
    //     let pcrs: Vec<Vec<u8>> = match document_map
    //         .get(&serde_cbor::Value::Text("pcrs".to_string()))
    //     {
    //         Some(serde_cbor::Value::Map(map)) => {
    //             let mut ret_vec: Vec<Vec<u8>> = Vec::new();
    //             let num_entries:i128 = map.len().try_into()
    //                 .map_err(|err| format!("AttestationVerifier::parse_payload failed to convert pcrs len into i128:{:?}", err))?;
    //             for x in 0..num_entries {
    //                 match map.get(&serde_cbor::Value::Integer(x)) {
    //                     Some(serde_cbor::Value::Bytes(inner_vec)) => {
    //                         ret_vec.push(inner_vec.to_vec());
    //                     },
    //                     _ => return Err(format!("AttestationVerifier::parse_payload pcrs inner vec is wrong type or not there?")),
    //                 }
    //             }
    //             ret_vec
    //         }
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload pcrs is wrong type or not present"
    //             ))
    //         }
    //     };
    //     for (i, pcr) in pcrs.iter().enumerate() {
    //         let pcr_str = pcr.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    //         // println!("PCR {}: {}", i, pcr_str);
    //     }
    //     let nonce: Option<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
    //             None => None,
    //             _ => {
    //                 return Err(format!(
    //                     "AttestationVerifier::parse_payload nonce is wrong type or not present"
    //                 ))
    //             }
    //         };
    //     println!("nonce:{:?}", nonce);
    //     let user_data: Option<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
    //             Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
    //             None => None,
    //             Some(_null) => None,
    //         };
    //     let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string()))
    //     {
    //         Some(serde_cbor::Value::Text(val)) => val.to_string(),
    //         _ => {
    //             return Err(format!(
    //                 "AttestationVerifier::parse_payload digest is wrong type or not present"
    //             ))
    //         }
    //     };
    //     let cabundle: Vec<Vec<u8>> =
    //         match document_map.get(&serde_cbor::Value::Text("cabundle".to_string())) {
    //             Some(serde_cbor::Value::Array(outer_vec)) => {
    //                 let mut ret_vec: Vec<Vec<u8>> = Vec::new();
    //                 for this_vec in outer_vec.iter() {
    //                     match this_vec {
    //                         serde_cbor::Value::Bytes(inner_vec) => {
    //                             ret_vec.push(inner_vec.to_vec());
    //                         }
    //                         _ => {
    //                             return Err(format!(
    //                                 "AttestationVerifier::parse_payload inner_vec is wrong type"
    //                             ))
    //                         }
    //                     }
    //                 }
    //                 ret_vec
    //             }
    //             _ => {
    //                 return Err(format!(
    //                 "AttestationVerifier::parse_payload cabundle is wrong type or not present:{:?}",
    //                 document_map.get(&serde_cbor::Value::Text("cabundle".to_string()))
    //             ))
    //             }
    //         };
    //     Ok(AttestationDocument {
    //         module_id: module_id,
    //         timestamp: timestamp,
    //         digest: digest,
    //         pcrs: pcrs,
    //         certificate: certificate,
    //         cabundle: cabundle,
    //         public_key: public_key,
    //         user_data: user_data,
    //         nonce: nonce,
    //     })
    // }
    // // pub fn fetch_attestation_document(&self, nonce: &str) -> Result<Vec<u8>, String> {
    //     use reqwest::blocking::Client;
    //     use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
    //     let url = format!("{}?nonce={}", self.enclave_endpoint, nonce);
    //     let mut headers = HeaderMap::new();
    //     headers.insert(USER_AGENT, HeaderValue::from_static("attestation-client"));
    //     let client = Client::builder()
    //         .danger_accept_invalid_certs(true)
    //         .default_headers(headers)
    //         .build()
    //         .map_err(|e| format!("Failed to build client: {}", e))?;
    //     let response = client
    //         .get(&url)
    //         .send()
    //         .map_err(|e| format!("Failed to send request: {}", e))?;
    //     if !response.status().is_success() {
    //         return Err(format!("Request failed with status: {}", response.status()));
    //     }
    //     let decoded_response = response
    //         .text()
    //         .map_err(|e| format!("Failed to read response body as text: {}", e))?;
    //     STANDARD.decode(decoded_response.trim())
    //         .map_err(|e| format!("Failed to decode base64: {}", e))
    // }

    //use rustls_pemfile::{certs, pkcs8_private_keys};

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn test_verify() {
            //parsing cbor without std functions
            let document_data  = STANDARD.decode("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")
            .expect("decode cbor document failed");

            let attestation_document =
                parse_cbor_document(&document_data).expect("parse cbor document failed");

            verify(
                &attestation_document.protected,
                &attestation_document.signature,
                &attestation_document.payload,
                &attestation_document.certificate,
            )
            .expect("remote attestation verification failed");
        }

        // #[test]
        // fn test_std() {
        //     //@ok parse CBOR doc
        //     //@note from url
        //     // let attestation_verifier = AttestationVerifier::new(None, None);
        //     // let nonce = "0000000000000000000000000000000000000001";
        //     // let document_data = attestation_verifier
        //     //     .fetch_attestation_document(nonce)
        //     //     .map_err(|err| format!("Failed to fetch attestation document: {:?}", err))
        //     //     .expect("Failed to fetch attestation document");
        //     //println!("document_data: {:?}", base64::encode(document_data.clone()));
        //     //@note from file, using STD though
        //     // let document_data = std::fs::read_to_string("src/example_attestation")
        //     //     .expect("Failed to read example_attestation file");
        //     // let document_data =
        //     //     STANDARD.decode(document_data.trim()).expect("Failed to decode base64 data");
        //     //@note from array, using STD functions as well
        //     let document_data = STANDARD.decode("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").expect("decode doc failed");
        //     let (_protected, payload, _signature) =
        //         parse(&document_data).expect("AttestationVerifier::authenticate parse failed");
        //     println!("_protected: {:?}", payload);
        //     println!("signature: {:?}", _signature);
        //     println!("_protected: {:?}", _protected);
        //     // Step 2. Exract the attestation document from the COSE_Sign1 structure
        //     let document =
        //         parse_payload(&payload).expect("AttestationVerifier::authenticate failed");
        //     //@ok parse public key, convert from der to sec1 format
        //     let cert = x509_cert::Certificate::from_der(&document.certificate).unwrap();
        //     let public_key = cert
        //         .tbs_certificate
        //         .subject_public_key_info
        //         .to_der()
        //         .expect("public key der failed");
        //     //println!("public key der: {:?}", public_key.clone());
        //     //sec1 doesnt comprise der headers
        //     let public_key = &public_key[public_key.len() - 97..];
        //     //println!("public key sec1: {:?}", hex::encode(public_key));
        //     //@ok public key valid
        //     let verifying_key =
        //         VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid public key");
        //     //@ok signature valid
        //     //println!("signature: {:?}", _signature);
        //     //let signature = Signature::from_bytes(&signature.).expect("Invalid signature");
        //     // Create a Signature object from the raw signature bytes
        //     let signature = Signature::from_slice(&_signature).expect("Invalid signature");
        //     //@ok parse sig_bytes from doc
        //     //correspond to Signature1D
        //     let header = [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 68];
        //     let protected = _protected;
        //     //@todo sometimes last byte is 96 sometimes 95, need to figure out why
        //     let filler = [64, 89, 17, 96];
        //     let payload = payload;
        //     let sign_structure = [
        //         header.as_ref(),
        //         protected.as_ref(),
        //         filler.as_ref(),
        //         payload.as_ref(),
        //     ]
        //     .concat();
        //     //println!("pcrs: {:?}", document.pcrs);
        //     //@ok
        //     // Verify the signature
        //     verifying_key
        //         .verify(&sign_structure, &signature)
        //         .expect("Signature verification failed");
        //     //assert!(result, "Signature verification failed");
        // }
    }
}
