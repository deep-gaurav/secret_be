use async_graphql::{Context, Object};

use super::{
    get_pool_from_context, get_user_id_from_context,
    message::Message,
    secret::Secret,
    sql_functions::{create_message, create_secret, create_user, get_secret, get_user},
    user::User,
};

pub struct Query;

#[Object]
impl Query {
    pub async fn user<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Option<User>, anyhow::Error> {
        let user_id = get_user_id_from_context(ctx).await?;
        let pool = get_pool_from_context(ctx).await?;
        let user = get_user(&user_id, &pool).await?;
        Ok(user)
    }

    pub async fn secret<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        secret_id: String,
    ) -> Result<Secret, anyhow::Error> {
        let pool = get_pool_from_context(ctx).await?;
        let secret = get_secret(&secret_id, &pool).await;
        secret
    }
}

pub struct Mutation;

#[Object]
impl Mutation {
    pub async fn signup<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        name: String,
    ) -> Result<User, anyhow::Error> {
        let user_id = get_user_id_from_context(ctx).await?;
        let pool = get_pool_from_context(ctx).await?;
        let user = get_user(&user_id, &pool).await?;
        if user.is_some() {
            return Err(anyhow::anyhow!("User already exists"));
        }
        let user = create_user(&user_id, &name, &pool).await?;

        Ok(user)
    }

    pub async fn create_secret<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        title: String,
        message: String,
    ) -> Result<Secret, anyhow::Error> {
        let user_id = get_user_id_from_context(ctx).await?;
        let pool = get_pool_from_context(ctx).await?;
        let user = get_user(&user_id, &pool).await?;
        if user.is_none() {
            return Err(anyhow::anyhow!("User doesnt exist, signup first"));
        }
        let secret = create_secret(&user_id, &title, &pool).await?;
        let _ = create_message(&secret.id, &user_id, &message, &pool).await?;
        Ok(secret)
    }

    pub async fn create_message<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        secret_id: String,
        message: String,
    ) -> Result<Message, anyhow::Error> {
        let user_id = get_user_id_from_context(ctx).await?;
        let pool = get_pool_from_context(ctx).await?;
        let user = get_user(&user_id, &pool).await?;
        if user.is_none() {
            return Err(anyhow::anyhow!("User doesnt exist, signup first"));
        }
        let message = create_message(&secret_id, &user_id, &message, &pool).await?;
        Ok(message)
    }
}
