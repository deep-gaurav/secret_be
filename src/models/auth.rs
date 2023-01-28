use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthType {
    NoAuth,
    AnonAuth(String),
    GoogleAuth(String),
}
