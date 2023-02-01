use std::sync::{Arc, RwLock};

use async_graphql::Context;
use magic_crypt::{new_magic_crypt, MagicCrypt, MagicCrypt128, MagicCryptTrait};
use sqlx::SqlitePool;

use crate::{
    models::auth::AuthType,
    schema::{message::Message, secret::Secret, user::User},
};

pub mod graph_schema;
pub mod message;
pub mod secret;
pub mod sql_functions;
pub mod user;

lazy_static::lazy_static! {
    static ref MCRYPT: MagicCrypt128 = new_magic_crypt!(std::env::var("ENCRYPT_KEY").unwrap_or(std::env!("ENCRYPT_KEY").to_string()));
}

pub async fn get_pool_from_context<'ctx>(
    context: &Context<'ctx>,
) -> Result<SqlitePool, anyhow::Error> {
    let pool = context
        .data::<SqlitePool>()
        .map_err(|e| anyhow::anyhow!("Cant find pool {:#?}", e))?;
    Ok(pool.clone())
}

pub async fn get_user_id_from_context<'ctx>(
    context: &Context<'ctx>,
) -> Result<String, anyhow::Error> {
    let pool = context
        .data::<AuthType>()
        .map_err(|e| anyhow::anyhow!("Cant find user id {:#?}", e))?;
    match pool {
        AuthType::NoAuth => Err(anyhow::anyhow!("No header found")),
        AuthType::GoogleAuth(id) => {
            let new_id = MCRYPT.encrypt_str_to_base64(format!("Google{id}"));
            Ok(new_id)
        }
        AuthType::AnonAuth(id) => {
            let new_id = MCRYPT.encrypt_str_to_base64(format!("Anon{id}"));
            Ok(new_id)
        }
    }
}

lazy_static::lazy_static! {
    static ref BEARER_HOLDER:Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
}

pub async fn get_token_ref_from_context<'ctx>(
    context: &Context<'ctx>,
) -> Result<Arc<RwLock<Option<String>>>, anyhow::Error> {
    Ok(BEARER_HOLDER.clone())
}
