use std::collections::HashMap;
use futures_core::TryStream;

use serde::{Deserialize, Serialize};

use crate::{ApiError, B2Error, UPLOAD_CLIENT};
use crate::api::b2_get_upload_url::UploadAuth;

pub async fn b2_upload_file<S>(
    auth: &UploadAuth,
    file: S,
    info: FileInfo
) -> Result<B2File, ApiError>
where S: TryStream + Send + Sync + 'static, S::Error: Into<Box<dyn std::error::Error + Send + Sync>>, bytes::Bytes: From<S::Ok> {
    let client = UPLOAD_CLIENT.get().ok_or(ApiError::FailedToGetClient)?;

    let body = reqwest::Body::wrap_stream(file);
    let response = client.post(&auth.upload_url)
        .header("Authorization", &auth.authorization_token)
        .header("X-Bz-File-Name", &info.file_name)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", info.size)
        .header("X-Bz-Content-Sha1", "hex_digits_at_end")
        .header("X-Bz-Info-src_last_modified_millis", info.modified.to_string())
        .body(body)
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return match serde_json::from_str::<B2Error>(&text) {
            Ok(error) => {
                eprintln!("Error during upload: {error:?}");
                Err(ApiError::RequestFailed(format!("{} (HTTP {})", error.code, status.as_str())))
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

    Ok(serde_json::from_str::<B2File>(&text)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub file_name: String,
    pub modified: u128,
    pub size: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FileList {
    pub files: Vec<B2File>,
    pub next_file_name: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct B2File {
    pub action: String,
    pub content_length: u64,
    pub content_sha1: String,
    pub file_id: String,
    pub file_name: String,
    pub upload_timestamp: u64,
    pub file_info: HashMap<String, String>,
}