use crate::config::NitridingProperties;
use bytes::Bytes;
use reqwest;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NitridingError {
    #[error("Failed to signal ready to nitriding: {0}")]
    SignalReadyError(String),
    #[error("Failed to get state from nitriding: {0}")]
    GetStateError(String),
    #[error("Failed to set state to nitriding: {0}")]
    SetStateError(String),
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
            .get(&format!("http://{}:{}/enclave/ready", self.host, self.port))
            .send()
            .await;

        let res = match res {
            Ok(res) => res,
            Err(e) => return Err(NitridingError::SignalReadyError(e.to_string())),
        };

        if res.status().is_success() {
            Ok(())
        } else {
            Err(NitridingError::SignalReadyError(res.status().to_string()))
        }
    }

    pub fn is_leader(&self) -> bool {
        self.role == "leader"
    }

    pub async fn get_state(&self) -> Result<Bytes, NitridingError> {
        if self.is_leader() {
            return Err(NitridingError::GetStateError("Not a follower".to_string()));
        }

        let client = reqwest::Client::new();
        let res = client
            .get(&format!("http://{}:{}/enclave/state", self.host, self.port))
            .send()
            .await;

        let res = match res {
            Ok(res) => res,
            Err(e) => return Err(NitridingError::GetStateError(e.to_string())),
        };

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
        if !self.is_leader() {
            return Err(NitridingError::SetStateError("Not a leader".to_string()));
        }

        let client = reqwest::Client::new();
        let res = client
            .put(&format!("http://{}:{}/enclave/state", self.host, self.port))
            .body(state)
            .send()
            .await;

        let res = match res {
            Ok(res) => res,
            Err(e) => return Err(NitridingError::SetStateError(e.to_string())),
        };

        if res.status().is_success() {
            Ok(())
        } else {
            Err(NitridingError::SetStateError(res.status().to_string()))
        }
    }
}
