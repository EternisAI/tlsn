mod config;

pub use config::ProverConfig;

use enum_try_as_inner::EnumTryAsInner;
use futures::TryFutureExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use tls_client_async::TlsConnection;
use tlsn_prover::tls::{state, Prover};
use tracing::info;
use wasm_bindgen::{prelude::*, JsError};
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{io::FuturesIo, types::*};

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen(js_name = Prover)]
pub struct JsProver {
    state: State,
}

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
enum State {
    Initialized(Prover<state::Initialized>),
    Setup(Prover<state::Setup>),
    Closed(Prover<state::Closed>),
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new(config: ProverConfig) -> JsProver {
        JsProver {
            state: State::Initialized(Prover::new(config.into())),
        }
    }

    /// Set up the prover.
    ///
    /// This performs all Tee setup prior to establishing the connection to the
    /// application server.
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let prover = self.state.take().try_into_initialized()?;

        info!("connecting to verifier");

        let (_, verifier_conn) = WsMeta::connect(verifier_url, None).await?;

        info!("connected to verifier");

        let prover = prover.setup(verifier_conn.into_io()).await?;

        self.state = State::Setup(prover);

        Ok(())
    }

    /// Send the HTTP request to the server.
    pub async fn send_request(
        &mut self,
        ws_proxy_url: &str,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let prover = self.state.take().try_into_setup()?;

        info!("connecting to server");

        let (_, server_conn) = WsMeta::connect(ws_proxy_url, None).await?;

        info!("connected to server");

        let (tls_conn, prover_fut) = prover.connect(server_conn.into_io()).await?;
        let _prover_ctrl = prover_fut.control();

        info!("sending request");

        let (response, prover) = futures::try_join!(
            async move { send_request(tls_conn, request).await },
            prover_fut.map_err(Into::into),
        )?;

        info!("response received");

        self.state = State::Closed(prover);

        Ok(response)
    }

    /// Runs the notarization protocol.
    pub async fn notarize(&mut self) -> Result<String> {
        info!("starting notarization");

        let prover = self.state.take().try_into_closed()?.start_notarize();

        let notarized_session = prover.finalize().await?;

        info!(
            "notarization complete. Signature: {:?}\r\n attributes: {:?} attestations {:?} application_data {:?}",
            notarized_session.signature,
            notarized_session.attestations.keys(),
            notarized_session.attestations.values(),
            notarized_session.application_data
        );

        info!("attestations: {:?}", notarized_session.attestations);

        let mut attestations_vec = Vec::new();
        for (key, value) in notarized_session.attestations.iter() {
            info!("attestation: {} {:?}", key, value);
            attestations_vec.push(
                json!({
                    "attribute_name": key,
                    "attribute_hex": hex::encode(key.as_bytes()),
                    "signature": format!("{}", hex::encode(value.to_bytes())),
                })
                .to_string(),
            );
        }
        info!("attestations: {:?}", attestations_vec);
        info!("attestations: {:?}", attestations_vec.join("|"));

        use serde_json::json;

        let serialized = json!({
            "application_data": notarized_session.application_data,
            "signature": format!("{}", hex::encode(notarized_session.signature.to_bytes())),
            "attributes": attestations_vec

        })
        .to_string();

        Ok(serialized)
    }
}

impl From<Prover<state::Initialized>> for JsProver {
    fn from(value: Prover<state::Initialized>) -> Self {
        JsProver {
            state: State::Initialized(value),
        }
    }
}

async fn send_request(conn: TlsConnection, request: HttpRequest) -> Result<HttpResponse> {
    let conn = FuturesIo::new(conn);
    let request = hyper::Request::<Full<Bytes>>::try_from(request)?;

    let (mut request_sender, conn) = hyper::client::conn::http1::handshake(conn).await?;

    spawn_local(async move { conn.await.expect("connection runs to completion") });

    let response = request_sender.send_request(request).await?;

    let (response, body) = response.into_parts();

    let body = String::from_utf8(body.collect().await?.to_bytes().to_vec())?;

    let headers = response
        .headers
        .into_iter()
        .map(|(k, v)| {
            (
                k.map(|k| k.to_string()).unwrap_or_default(),
                v.as_bytes().to_vec(),
            )
        })
        .collect();

    Ok(HttpResponse {
        status: response.status.as_u16(),
        headers,
        body,
    })
}
