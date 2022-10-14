pub mod api;

use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

pub use reqwest::Error as ReqwestError;

static CLIENT: OnceCell<Client> = OnceCell::new();
// Separate client for uploads with NODELAY and long timeout
static UPLOAD_CLIENT: OnceCell<Client> = OnceCell::new();

/// Initialize global resources
pub fn init() {
    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("retain-rs {}", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .build()
        .unwrap();
    // NODELAY and 20 minutes timeout
    // Concurrency and large file threshold is automatically set s.t. uploads
    // should finish after ~10 minutes, regardless of size
    let up_client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(1200))
        .user_agent(format!("retain-rs {}", env!("CARGO_PKG_VERSION")))
        .tcp_nodelay(true)
        .https_only(true)
        .build()
        .unwrap();
    CLIENT.set(client).unwrap();
    UPLOAD_CLIENT.set(up_client).unwrap();
}

/// An error message, returned by the B2 API on failed requests
#[derive(Deserialize, Debug)]
pub struct B2Error {
    pub code: String,
    pub message: String,
    pub status: u16,
}

/// Different types of errors the API may return
#[derive(Debug)]
pub enum ApiError {
    BadBucketConfig(&'static str),
    FailedToGetClient,
    // Returned if we try to use the Arc<RwLock<Option<Auth>>> while it's None or expired/invalid
    Unauthorized,
    ReqwestError(ReqwestError),
    // Returned if the http request succeeded but we got a bad response, typically any non-200 status code
    RequestFailed(String),
    SerdeError(serde_json::Error),
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadBucketConfig(msg) => f.write_str(msg),
            ApiError::FailedToGetClient => f.write_str("Failed to get global client -- This should never happen. Was backblaze-api::init() called?"),
            ApiError::Unauthorized => f.write_str("Invalid or expired Auth"),
            ApiError::ReqwestError(err) => {
                match err.status() {
                    Some(status) =>  f.write_str(&format!("HTTP {}: {}", status.as_str(), err)),
                    None => {
                        f.write_str(&format!("Request failed: {}", err))
                    }
                }
            },
            ApiError::RequestFailed(response) => {
                f.write_str(response)
            },
            ApiError::SerdeError(err) => {
                f.write_str(&err.to_string())
            }
        }
    }
}

impl From<ReqwestError> for ApiError {
    fn from(err: ReqwestError) -> Self {
        Self::ReqwestError(err)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerdeError(err)
    }
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub account_id: String,
    pub authorization_token: String,
    pub api_url: String,
    pub download_url: String,
    pub recommended_part_size: u64,
    pub absolute_minimum_part_size: u64,
    pub bucket_id: String,
    pub bucket_name: String,
}

impl Auth {
    pub fn get_api_url(&self, call: &str) -> String {
        format!("{}/b2api/v2/{}", self.api_url, call)
    }
}

/// Generic function to call the B2 API
///
/// This takes in an authorization, the data to send, the endpoint to call and what type to return
/// The input must either be None or a struct implementing Serialize
/// The output must be a type implementing DeserializeOwned
pub async fn make_api_call<DATA, IN: Serialize, OUT: DeserializeOwned, F>
    (auth: Arc<RwLock<Option<Auth>>>, data: Option<DATA>, transformer: F, endpoint: &str) -> Result<OUT, ApiError>
where F: FnOnce(&Auth, DATA) -> IN {
    let client = CLIENT.get().ok_or(ApiError::FailedToGetClient)?;

    // Wait until we have a valid auth, then build the request
    let request = {
        let auth_option;
        let authorization;
        loop {
            {
                let a = auth.read().await;
                if a.is_some() {
                    auth_option = a;
                    authorization = auth_option.as_ref().unwrap();
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let mut request = client.post(authorization.get_api_url(endpoint))
            .header("Authorization", authorization.authorization_token.clone());

        if data.is_some() {
            let request_body = transformer(authorization, data.unwrap());
            request = request.body(serde_json::to_string(&request_body)?);
        }
        request
    };
    let response = request.send().await?;

    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return match serde_json::from_str::<B2Error>(&text) {
            Ok(error) => {
                println!("{error:?}");
                if status == StatusCode::UNAUTHORIZED {
                    auth.write().await.take();
                    Err(ApiError::Unauthorized)
                } else {
                    Err(ApiError::RequestFailed(format!("{} (HTTP {})", error.code, status.as_str())))
                }
            },
            Err(_) => {
                match text.len() {
                    0 => {
                        Err(ApiError::RequestFailed(format!("HTTP {} - {}",
                                                            status.as_str(),
                                                            status.canonical_reason().unwrap_or("Unknown status"))))
                    }
                    _ => {
                        let text = text.replace('\n', "");
                        Err(ApiError::RequestFailed(format!("HTTP {} - {}: {text}",
                                                            status.as_str(),
                                                            status.canonical_reason().unwrap_or("Unknown status"))))
                    }
                }
            }
        }
    }

    Ok(serde_json::from_str::<OUT>(&text)?)
}