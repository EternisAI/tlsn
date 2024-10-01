use axum::{
    extract::Request,
    http::StatusCode,
    middleware::from_extractor_with_state,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use notify::{
    event::ModifyKind, Error, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{
    collections::HashMap,
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::{fs::File, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use tower_http::cors::CorsLayer;
use tower_service::Service;
use tracing::{debug, error, info};

use crate::{
    config::{NitridingProperties, NotaryServerProperties, NotarySigningKeyProperties},
    domain::{
        auth::{authorization_whitelist_vec_into_hashmap, AuthorizationWhitelistRecord},
        nitriding::SyncState,
        notary::NotaryGlobals,
        InfoResponse,
    },
    error::NotaryServerError,
    middleware::AuthorizationMiddleware,
    service::{initialize, upgrade_protocol},
    util::parse_csv_file,
};
use generic_array::GenericArray;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_process::Collector;
use prometheus::{register_counter, register_gauge, Counter, Encoder, Gauge, TextEncoder};
use structopt::lazy_static::lazy_static;

lazy_static! {
    static ref TOTAL_CONNECTION_COUNTER: Counter =
        register_counter!("total_connection_counter", "Total connections recorded").unwrap();
    static ref TOTAL_CONNECTION_ERROR_COUNTER: Counter = register_counter!(
        "total_connection_error_counter",
        "Total connection error recorded"
    )
    .unwrap();
    static ref ACTIVE_CONNECTION_COUNTER: Gauge =
        register_gauge!("active_connection_gauge", "Active connections").unwrap();
}

struct TaskGuard {
    gauge: Arc<Gauge>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        // Decrement the gauge when the guard is dropped
        info!("dropped prover's TCP connection",);
        self.gauge.dec();
    }
}

/// Start a TCP server (with or without TLS) to accept notarization request for both TCP and WebSocket clients
#[tracing::instrument(skip(config))]
pub async fn run_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    // Load the private key for notarized transcript signing
    let mut notary_signing_key = load_notary_signing_key(&config.notary_key).await?;
    // Build TLS acceptor if it is turned on
    let tls_acceptor = if !config.tls.enabled {
        debug!("Skipping TLS setup as it is turned off.");
        None
    } else {
        let (tls_private_key, tls_certificates) = load_tls_key_and_cert(
            &config.tls.private_key_pem_path,
            &config.tls.certificate_pem_path,
        )
        .await?;

        let mut server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(tls_certificates, tls_private_key)
            .map_err(|err| eyre!("Failed to instantiate notary server tls config: {err}"))?;

        // Set the http protocols we support
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_config = Arc::new(server_config);
        Some(TlsAcceptor::from(tls_config))
    };

    // Load the authorization whitelist csv if it is turned on
    let authorization_whitelist =
        load_authorization_whitelist(config)?.map(|whitelist| Arc::new(Mutex::new(whitelist)));
    // Enable hot reload if authorization whitelist is available
    let watcher =
        watch_and_reload_authorization_whitelist(config.clone(), authorization_whitelist.clone())?;
    if watcher.is_some() {
        debug!("Successfully setup watcher for hot reload of authorization whitelist!");
    }

    // Load the nitriding config if it is turned on
    let nitriding_config = load_nitriding_config(&config)?;
    match nitriding_config {
        Some(nitriding) => {
            debug!("Loading nitriding config");
            let np = NitridingProperties::new(nitriding);
            while np.get_sync_state().await.expect("Failed to get sync state")
                == SyncState::InProgress
            {
                debug!("Waiting for sync to complete");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if np.is_leader().await.expect("Failed to get leader status") {
                debug!("Setting initial state for leader");
                let key = Bytes::copy_from_slice(notary_signing_key.to_bytes().as_slice());
                np.set_state(key)
                    .await
                    .map_err(|e| NotaryServerError::Nitriding(e.to_string()))?;
                debug!("Successfully set initial state for leader");
            } else {
                debug!("Loading nitriding config with state for follower");
                let key = np
                    .get_state()
                    .await
                    .map_err(|e| NotaryServerError::Nitriding(e.to_string()))?;
                debug!("Successfully loaded nitriding config with state: {:?}", key);
                // if key.len() > 0 {
                //     notary_signing_key =
                //         SigningKey::from_bytes(&GenericArray::clone_from_slice(&key[..]))
                //             .expect("Invalid key format");
                // }
            }
        }
        None => {
            debug!("No nitriding config loaded");
        }
    };

    let notary_address = SocketAddr::new(
        IpAddr::V4(config.server.host.parse().map_err(|err| {
            eyre!("Failed to parse notary host address from server config: {err}")
        })?),
        config.server.port,
    );
    let mut listener = TcpListener::bind(notary_address)
        .await
        .map_err(|err| eyre!("Failed to bind server address to tcp listener: {err}"))?;

    info!("Listening for TCP traffic at {}", notary_address);

    let protocol = Arc::new(http1::Builder::new());
    let notary_globals = NotaryGlobals::new(
        notary_signing_key,
        config.notarization.clone(),
        authorization_whitelist,
    );

    // Parameters needed for the info endpoint
    let public_key = std::fs::read_to_string(&config.notary_key.public_key_pem_path)
        .map_err(|err| eyre!("Failed to load notary public signing key for notarization: {err}"))?;
    let version = env!("CARGO_PKG_VERSION").to_string();
    let git_commit_hash = env!("GIT_COMMIT_HASH").to_string();
    let git_commit_timestamp = env!("GIT_COMMIT_TIMESTAMP").to_string();

    // Parameters needed for the root / endpoint
    let html_string = config.server.html_info.clone();
    let html_info = Html(
        html_string
            .replace("{version}", &version)
            .replace("{git_commit_hash}", &git_commit_hash)
            .replace("{git_commit_timestamp}", &git_commit_timestamp)
            .replace("{public_key}", &public_key),
    );

    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("failed to install Prometheus recorder");
    let collector = Collector::default();
    collector.describe();

    let router = Router::new()
        .route(
            "/",
            get(|| async move { (StatusCode::OK, html_info).into_response() }),
        )
        .route(
            "/healthcheck",
            get(|| async move { (StatusCode::OK, "Ok").into_response() }),
        )
        .route(
            "/info",
            get(|| async move {
                (
                    StatusCode::OK,
                    Json(InfoResponse {
                        version,
                        public_key,
                        git_commit_hash,
                        git_commit_timestamp,
                    }),
                )
                    .into_response()
            }),
        )
        .route("/session", post(initialize))
        // Not applying auth middleware to /notarize endpoint for now as we can rely on our
        // short-lived session id generated from /session endpoint, as it is not possible
        // to use header for API key for websocket /notarize endpoint due to browser restriction
        // ref: https://stackoverflow.com/a/4361358; And putting it in url query param
        // seems to be more insecured: https://stackoverflow.com/questions/5517281/place-api-key-in-headers-or-url
        .route_layer(from_extractor_with_state::<
            AuthorizationMiddleware,
            NotaryGlobals,
        >(notary_globals.clone()))
        .route("/notarize", get(upgrade_protocol))
        .route(
            "/app-metrics",
            get(|| async move {
                let mut buffer = vec![];
                let metric_families = prometheus::gather();
                let encoder = TextEncoder::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                (StatusCode::OK, String::from_utf8(buffer).unwrap()).into_response()
            }),
        )
        .route(
            "/process-metrics",
            get(move || {
                collector.collect();
                std::future::ready(handle.render())
            }),
        )
        .layer(CorsLayer::permissive())
        .with_state(notary_globals);

    loop {
        // Poll and await for any incoming connection, ensure that all operations inside are infallible to prevent bringing down the server
        let stream =
            match poll_fn(|cx: &mut std::task::Context| Pin::new(&mut listener).poll_accept(cx))
                .await
            {
                Ok((stream, _)) => stream,
                Err(err) => {
                    error!("{}", NotaryServerError::Connection(err.to_string()));
                    TOTAL_CONNECTION_ERROR_COUNTER.inc();
                    continue;
                }
            };
        debug!("Received a prover's TCP connection");
        TOTAL_CONNECTION_COUNTER.inc();
        let tower_service = router.clone();
        let tls_acceptor = tls_acceptor.clone();
        let protocol = protocol.clone();

        // Spawn a new async task to handle the new connection
        tokio::spawn(async move {
            ACTIVE_CONNECTION_COUNTER.inc();
            let _guard = TaskGuard {
                gauge: Arc::new(ACTIVE_CONNECTION_COUNTER.clone()),
            };
            // When TLS is enabled
            if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(stream) => {
                        info!("Accepted prover's TLS-secured TCP connection");
                        // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
                        let io = TokioIo::new(stream);
                        let hyper_service =
                            hyper::service::service_fn(move |request: Request<Incoming>| {
                                tower_service.clone().call(request)
                            });
                        // Serve different requests using the same hyper protocol and axum router
                        let _ = protocol
                            .serve_connection(io, hyper_service)
                            // use with_upgrades to upgrade connection to websocket for websocket clients
                            // and to extract tcp connection for tcp clients
                            .with_upgrades()
                            .await
                            .unwrap();
                    }
                    Err(err) => {
                        TOTAL_CONNECTION_ERROR_COUNTER.inc();
                        error!("{}", NotaryServerError::Connection(err.to_string()));
                    }
                }
            } else {
                // When TLS is disabled
                info!("Accepted prover's TCP connection",);
                // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
                let io = TokioIo::new(stream);
                let hyper_service =
                    hyper::service::service_fn(move |request: Request<Incoming>| {
                        tower_service.clone().call(request)
                    });
                // Serve different requests using the same hyper protocol and axum router
                let _ = protocol
                    .serve_connection(io, hyper_service)
                    // use with_upgrades to upgrade connection to websocket for websocket clients
                    // and to extract tcp connection for tcp clients
                    .with_upgrades()
                    .await
                    .unwrap();
            }
        });
    }
}

/// Load notary signing key from static file
async fn load_notary_signing_key(config: &NotarySigningKeyProperties) -> Result<SigningKey> {
    debug!("Loading notary server's signing key");

    let notary_signing_key = SigningKey::read_pkcs8_pem_file(&config.private_key_pem_path)
        .map_err(|err| eyre!("Failed to load notary signing key for notarization: {err}"))?;

    debug!("Successfully loaded notary server's signing key!");
    Ok(notary_signing_key)
}

/// Read a PEM-formatted file and return its buffer reader
pub async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}

/// Load notary tls private key and cert from static files
async fn load_tls_key_and_cert(
    private_key_pem_path: &str,
    certificate_pem_path: &str,
) -> Result<(PrivateKey, Vec<Certificate>)> {
    debug!("Loading notary server's tls private key and certificate");

    let mut private_key_file_reader = read_pem_file(private_key_pem_path).await?;
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut private_key_file_reader)?;
    ensure!(
        private_keys.len() == 1,
        "More than 1 key found in the tls private key pem file"
    );
    let private_key = PrivateKey(private_keys.remove(0));

    let mut certificate_file_reader = read_pem_file(certificate_pem_path).await?;
    let certificates = rustls_pemfile::certs(&mut certificate_file_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    debug!("Successfully loaded notary server's tls private key and certificate!");
    Ok((private_key, certificates))
}

/// Load authorization whitelist if it is enabled
fn load_authorization_whitelist(
    config: &NotaryServerProperties,
) -> Result<Option<HashMap<String, AuthorizationWhitelistRecord>>> {
    let authorization_whitelist = if !config.authorization.enabled {
        debug!("Skipping authorization as it is turned off.");
        None
    } else {
        // Load the csv
        let whitelist_csv = parse_csv_file::<AuthorizationWhitelistRecord>(
            &config.authorization.whitelist_csv_path,
        )
        .map_err(|err| eyre!("Failed to parse authorization whitelist csv: {:?}", err))?;
        // Convert the whitelist record into hashmap for faster lookup
        let whitelist_hashmap = authorization_whitelist_vec_into_hashmap(whitelist_csv);
        Some(whitelist_hashmap)
    };
    Ok(authorization_whitelist)
}

// Setup a watcher to detect any changes to authorization whitelist
// When the list file is modified, the watcher thread will reload the whitelist
// The watcher is setup in a separate thread by the notify library which is synchronous
fn watch_and_reload_authorization_whitelist(
    config: NotaryServerProperties,
    authorization_whitelist: Option<Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>>,
) -> Result<Option<RecommendedWatcher>> {
    // Only setup the watcher if auth whitelist is loaded
    let watcher = if let Some(authorization_whitelist) = authorization_whitelist {
        let cloned_config = config.clone();
        // Setup watcher by giving it a function that will be triggered when an event is detected
        let mut watcher = RecommendedWatcher::new(
            move |event: Result<Event, Error>| {
                match event {
                    Ok(event) => {
                        // Only reload whitelist if it's an event that modified the file data
                        if let EventKind::Modify(ModifyKind::Data(_)) = event.kind {
                            debug!("Authorization whitelist is modified");
                            match load_authorization_whitelist(&cloned_config) {
                                Ok(Some(new_authorization_whitelist)) => {
                                    *authorization_whitelist.lock().unwrap() = new_authorization_whitelist;
                                    info!("Successfully reloaded authorization whitelist!");
                                }
                                Ok(None) => unreachable!(
                                    "Authorization whitelist will never be None as the auth module is enabled"
                                ),
                                // Ensure that error from reloading doesn't bring the server down
                                Err(err) => error!("{err}"),
                            }
                        }
                    },
                    Err(err) => {
                        error!("Error occured when watcher detected an event: {err}")
                    }
                }
            },
            notify::Config::default(),
        )
        .map_err(|err| eyre!("Error occured when setting up watcher for hot reload: {err}"))?;

        // Start watcher to listen to any changes on the whitelist file
        watcher
            .watch(
                Path::new(&config.authorization.whitelist_csv_path),
                RecursiveMode::Recursive,
            )
            .map_err(|err| eyre!("Error occured when starting up watcher for hot reload: {err}"))?;

        Some(watcher)
    } else {
        // Skip setup the watcher if auth whitelist is not loaded
        None
    };
    // Need to return the watcher to parent function, else it will be dropped and stop listening
    Ok(watcher)
}

/// Load nitriding config if it is turned on
fn load_nitriding_config(config: &NotaryServerProperties) -> Result<Option<NitridingProperties>> {
    let nitriding_config = if !config.nitriding.clone().enabled {
        debug!("Skipping nitriding as it is turned off.");
        None
    } else {
        Some(config.nitriding.clone())
    };
    let np =
        NitridingProperties::new(nitriding_config.expect("Nitriding config should not be None"));
    Ok(Some(np))
}

#[cfg(test)]
mod test {
    use std::{fs::OpenOptions, time::Duration};

    use csv::WriterBuilder;

    use crate::AuthorizationProperties;

    use super::*;

    #[tokio::test]
    async fn test_load_notary_key_and_cert() {
        let private_key_pem_path = "./fixture/tls/notary.key";
        let certificate_pem_path = "./fixture/tls/notary.crt";
        let result: Result<(PrivateKey, Vec<Certificate>)> =
            load_tls_key_and_cert(private_key_pem_path, certificate_pem_path).await;
        assert!(result.is_ok(), "Could not load tls private key and cert");
    }

    #[tokio::test]
    async fn test_load_notary_signing_key() {
        let config = NotarySigningKeyProperties {
            private_key_pem_path: "./fixture/notary/notary.key".to_string(),
            public_key_pem_path: "./fixture/notary/notary.pub".to_string(),
        };
        let result: Result<SigningKey> = load_notary_signing_key(&config).await;
        assert!(result.is_ok(), "Could not load notary private key");
    }

    #[tokio::test]
    async fn test_watch_and_reload_authorization_whitelist() {
        // Clone fixture auth whitelist for testing
        let original_whitelist_csv_path = "./fixture/auth/whitelist.csv";
        let whitelist_csv_path = "./fixture/auth/whitelist_copied.csv".to_string();
        std::fs::copy(original_whitelist_csv_path, &whitelist_csv_path).unwrap();

        // Setup watcher
        let config = NotaryServerProperties {
            authorization: AuthorizationProperties {
                enabled: true,
                whitelist_csv_path,
            },
            ..Default::default()
        };
        let authorization_whitelist = load_authorization_whitelist(&config)
            .expect("Authorization whitelist csv from fixture should be able to be loaded")
            .as_ref()
            .map(|whitelist| Arc::new(Mutex::new(whitelist.clone())));
        let _watcher = watch_and_reload_authorization_whitelist(
            config.clone(),
            authorization_whitelist.as_ref().map(Arc::clone),
        )
        .expect("Watcher should be able to be setup successfully")
        .expect("Watcher should be set up and not None");

        // Sleep to buy a bit of time for hot reload task and watcher thread to run
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Write a new record to the whitelist to trigger modify event
        let new_record = AuthorizationWhitelistRecord {
            name: "unit-test-name".to_string(),
            api_key: "unit-test-api-key".to_string(),
            created_at: "unit-test-created-at".to_string(),
        };
        let file = OpenOptions::new()
            .append(true)
            .open(&config.authorization.whitelist_csv_path)
            .unwrap();
        let mut wtr = WriterBuilder::new()
            .has_headers(false) // Set to false to avoid writing header again
            .from_writer(file);
        wtr.serialize(new_record).unwrap();
        wtr.flush().unwrap();

        // Sleep to buy a bit of time for updated whitelist to be hot reloaded
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(authorization_whitelist
            .unwrap()
            .lock()
            .unwrap()
            .contains_key("unit-test-api-key"));

        // Delete the cloned whitelist
        std::fs::remove_file(&config.authorization.whitelist_csv_path).unwrap();
    }
}
