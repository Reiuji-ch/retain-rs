use reqwest::Response;
use crate::{ApiError, Auth};

pub async fn b2_download_file_by_name<T: AsRef<str>>(auth: Auth, name: T) -> Result<Response, ApiError> {
    let client = crate::CLIENT.get().ok_or(ApiError::FailedToGetClient)?;
    let endpoint = format!("{}/file/{}/{}", auth.download_url, auth.bucket_name, name.as_ref());
    client.get(&endpoint)
        .header("Authorization", &auth.authorization_token)
        .send()
        .await
        .map_err(|err| ApiError::ReqwestError(err))
}