use async_graphql::{Context, Object};

use super::{
    get_pool_from_context, get_user_id_from_context, secret::Secret,
    sql_functions::get_secrets_with_user,
};

pub struct User {
    pub id: String,
    pub name: String,
    pub notification_token: Option<String>,
}

#[Object]
impl User {
    pub async fn id(&self) -> String {
        self.id.to_string()
    }

    pub async fn name(&self) -> String {
        self.name.to_string()
    }

    pub async fn secrets<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<Secret>, anyhow::Error> {
        let user_id = get_user_id_from_context(ctx).await?;
        if user_id != self.id {
            return Err(anyhow::anyhow!("You cant view others secrets"));
        }
        let pool = get_pool_from_context(ctx).await?;
        let secrets = get_secrets_with_user(&self.id, &pool).await?;
        Ok(secrets)
    }
}
