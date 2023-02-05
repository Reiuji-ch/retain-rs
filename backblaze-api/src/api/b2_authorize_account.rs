use crate::{ApiError, B2Error, CLIENT};
use serde::Deserialize;

pub async fn b2_authorize_account(key: &str) -> Result<crate::Auth, ApiError> {
    let client = CLIENT.get().ok_or(ApiError::FailedToGetClient)?;
    let response = client
        .get("https://api.backblazeb2.com/b2api/v2/b2_authorize_account")
        .header("Authorization", format!("Basic {key}"))
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return match serde_json::from_str::<B2Error>(&text) {
            Ok(error) => Err(ApiError::RequestFailed(format!(
                "{} (HTTP {})",
                error.code,
                status.as_str()
            ))),
            Err(_) => match text.len() {
                0 => Err(ApiError::RequestFailed(format!(
                    "HTTP {} - {}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("Unknown status")
                ))),
                _ => {
                    let text = text.replace('\n', "");
                    Err(ApiError::RequestFailed(format!(
                        "HTTP {} - {}: {text}",
                        status.as_str(),
                        status.canonical_reason().unwrap_or("Unknown status")
                    )))
                }
            },
        };
    }

    let response = serde_json::from_str::<AuthResponse>(&text)?;

    if response.allowed.name_prefix.is_some() {
        return Err(ApiError::BadBucketConfig(
            "API key is restricted to a prefix, remove it.",
        ));
    }

    if response.allowed.bucket_id.is_none() {
        return Err(ApiError::BadBucketConfig(
            "API key is not restricted to a single bucket. It should be, for safety reasons.",
        ));
    }

    if response.allowed.bucket_name.is_none() {
        return Err(ApiError::BadBucketConfig(
            "Bucket is invalid. Has it been deleted?",
        ));
    }

    Ok(crate::Auth {
        account_id: response.account_id,
        authorization_token: response.authorization_token,
        api_url: response.api_url,
        download_url: response.download_url,
        recommended_part_size: response.recommended_part_size,
        absolute_minimum_part_size: response.absolute_minimum_part_size,
        bucket_id: response
            .allowed
            .bucket_id
            .expect("This should never happen"),
        bucket_name: response
            .allowed
            .bucket_name
            .expect("This should never happen"),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    pub account_id: String,
    pub authorization_token: String,
    pub api_url: String,
    pub download_url: String,
    pub recommended_part_size: u64,
    pub absolute_minimum_part_size: u64,
    pub allowed: Allowed,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Allowed {
    pub capabilities: Vec<String>,
    pub bucket_id: Option<String>,
    pub bucket_name: Option<String>,
    pub name_prefix: Option<String>,
}
