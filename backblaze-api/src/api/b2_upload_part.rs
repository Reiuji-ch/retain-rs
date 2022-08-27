use futures_core::TryStream;

use serde::{Deserialize, Serialize};

use crate::{ApiError, B2Error, UPLOAD_CLIENT};
use crate::api::b2_get_upload_part_url::UploadPartAuth;

pub async fn b2_upload_part<S>(
    auth: &UploadPartAuth,
    part: S,
    info: PartInfo
) -> Result<B2Part, ApiError>
where S: TryStream + Send + Sync + 'static, S::Error: Into<Box<dyn std::error::Error + Send + Sync>>, bytes::Bytes: From<S::Ok> {
    let client = UPLOAD_CLIENT.get().ok_or(ApiError::FailedToGetClient)?;

    let body = reqwest::Body::wrap_stream(part);
    let response = client.post(&auth.upload_url)
        .header("Authorization", &auth.authorization_token)
        .header("X-Bz-Part-Number", &info.part_number.to_string())
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", info.part_size)
        .header("X-Bz-Content-Sha1", "hex_digits_at_end")
        .body(body)
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return match serde_json::from_str::<B2Error>(&text) {
            Ok(error) => {
                eprintln!("Error during part upload: {error:?}");
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

    Ok(serde_json::from_str::<B2Part>(&text)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartInfo {
    pub part_number: u16,
    pub part_size: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct B2Part {
    pub content_length: u64,
    pub part_number: u16,
    pub content_sha1: String,
}