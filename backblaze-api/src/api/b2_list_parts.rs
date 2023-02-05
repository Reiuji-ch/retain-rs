use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::api::B2Part;
use crate::{ApiError, Auth};

pub async fn b2_list_parts(
    auth: Arc<RwLock<Option<Auth>>>,
    file_id: String,
    start_part_number: Option<String>,
) -> Result<PartList, ApiError> {
    crate::make_api_call(
        auth,
        Some((file_id, start_part_number)),
        |_auth, data| ListPartsData {
            file_id: data.0,
            max_part_count: 1000,
            start_part_number: data.1,
        },
        "b2_list_parts",
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListPartsData {
    pub file_id: String,
    pub max_part_count: u16,
    pub start_part_number: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PartList {
    pub parts: Vec<B2Part>,
    // This is not guaranteed to be an actual number, so treat it as a string
    pub next_part_number: Option<String>,
}
