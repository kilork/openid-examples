use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub login: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub image_url: Option<String>,
    pub activated: bool,
    pub lang_key: Option<String>,
    pub authorities: Vec<String>,
}
