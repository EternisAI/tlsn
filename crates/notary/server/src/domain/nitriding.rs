use crate::config::NitridingProperties;
use bytes::Bytes;
use reqwest;
use reqwest::ClientBuilder;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::debug;

#[derive(Error, Debug)]
pub enum NitridingError {
    #[error("Failed to signal ready to nitriding: {0}")]
    SignalReadyError(String),
    #[error("Failed to get config from nitriding: {0}")]
    GetConfigError(String),
    #[error("Failed to get state from nitriding: {0}")]
    GetStateError(String),
    #[error("Failed to set state to nitriding: {0}")]
    SetStateError(String),
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(from = "u8")]
pub enum SyncState {
    #[serde(alias = "no-sync")]
    NoSync,
    #[serde(alias = "in-progress")]
    InProgress,
    #[serde(alias = "leader")]
    Leader,
    #[serde(alias = "follower")]
    Follower,
    #[serde(alias = "unknown")]
    Unknown,
}

impl From<u8> for SyncState {
    fn from(value: u8) -> Self {
        match value {
            0 => SyncState::NoSync,
            1 => SyncState::InProgress,
            2 => SyncState::Leader,
            3 => SyncState::Follower,
            _ => SyncState::Unknown,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NitridingConfig {
    #[serde(rename = "SyncState")]
    pub sync_state: SyncState,
}

impl NitridingProperties {
    pub fn new(config: NitridingProperties) -> Self {
        Self { ..config }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn signal_ready(&self) -> Result<(), NitridingError> {
        let client = reqwest::Client::new();
        let res = client
            .get(&format!(
                "http://{}:{}/enclave/ready",
                self.host, self.int_port
            ))
            .send()
            .await;

        let res = match res {
            Ok(res) => res,
            Err(e) => return Err(NitridingError::SignalReadyError(e.to_string())),
        };
        debug!("Nitriding signal ready response: {:?}", res.status());

        if res.status().is_success() {
            Ok(())
        } else {
            Err(NitridingError::SignalReadyError(res.status().to_string()))
        }
    }

    pub async fn get_sync_state(&self) -> Result<SyncState, NitridingError> {
        let mut client_builder = ClientBuilder::new().timeout(Duration::from_secs(10));

        client_builder = client_builder.danger_accept_invalid_certs(true);

        let client = client_builder.build().map_err(|e| {
            NitridingError::GetConfigError(format!("Failed to build client: {}", e))
        })?;

        let res = client
            .get(&format!(
                "https://{}:{}/enclave/config",
                self.host, self.ext_port
            ))
            .send()
            .await;

        let res = match res {
            Ok(res) => res,
            Err(e) => return Err(NitridingError::GetConfigError(e.to_string())),
        };

        if res.status().is_success() {
            let config: NitridingConfig = res.json().await.map_err(|e| {
                NitridingError::GetConfigError(format!("Failed to parse JSON: {}", e))
            })?;
            Ok(config.sync_state)
        } else {
            Err(NitridingError::GetConfigError(res.status().to_string()))
        }
    }

    pub async fn get_state(&self) -> Result<Bytes, NitridingError> {
        if self.is_leader().await.expect("Failed to get leader status") {
            return Err(NitridingError::GetStateError("Not a follower".to_string()));
        }

        let client = reqwest::Client::new();
        let res = client
            .get(&format!(
                "http://{}:{}/enclave/state",
                self.host, self.int_port
            ))
            .send()
            .await;

        let res = match res {
            Ok(res) => res,
            Err(e) => return Err(NitridingError::GetStateError(e.to_string())),
        };

        debug!("Nitriding get state response: {:?}", res.status());

        if res.status().is_success() {
            let body = res
                .bytes()
                .await
                .map_err(|e| NitridingError::GetStateError(e.to_string()))?;
            Ok(body)
        } else {
            Err(NitridingError::GetStateError(res.status().to_string()))
        }
    }

    pub async fn set_state(&self, state: Bytes) -> Result<(), NitridingError> {
        if !self.is_leader().await.expect("Failed to get leader status") {
            return Err(NitridingError::SetStateError("Not a leader".to_string()));
        }

        let client = reqwest::Client::new();
        let res = client
            .put(&format!(
                "http://{}:{}/enclave/state",
                self.host, self.int_port
            ))
            .body(state)
            .send()
            .await;

        let res = match res {
            Ok(res) => res,
            Err(e) => return Err(NitridingError::SetStateError(e.to_string())),
        };

        debug!("Nitriding set state response: {:?}", res.status());

        if res.status().is_success() {
            Ok(())
        } else {
            Err(NitridingError::SetStateError(res.status().to_string()))
        }
    }

    pub async fn is_leader(&self) -> Result<bool, NitridingError> {
        let sync_state = self.get_sync_state().await?;
        Ok(sync_state == SyncState::Leader)
    }
}
