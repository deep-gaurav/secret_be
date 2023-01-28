use async_graphql::{Context, Object};

use super::{get_pool_from_context, sql_functions::get_user, user::User};

pub struct Message {
    pub id: String,
    pub creator_id: String,
    pub message: String,
    pub secret_id: String,
}

#[Object]
impl Message {
    pub async fn id(&self) -> String {
        self.id.to_string()
    }

    pub async fn creator_id(&self) -> String {
        self.creator_id.to_string()
    }

    pub async fn message(&self) -> String {
        self.message.to_string()
    }

    pub async fn secret_id(&self) -> String {
        self.secret_id.to_string()
    }

    pub async fn creator<'ctx>(&self, ctx: &Context<'ctx>) -> Result<User, anyhow::Error> {
        let pool = get_pool_from_context(ctx).await?;
        let user = get_user(&self.creator_id, &pool)
            .await
            .map_err(|e| anyhow::anyhow!("Query Failed {:#?}", e))?
            .ok_or(anyhow::anyhow!("Cant find creator"))?;
        Ok(user)
    }
}
