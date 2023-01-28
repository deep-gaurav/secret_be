use async_graphql::{Context, Object, SimpleObject, Union};

use super::{
    get_pool_from_context, get_user_id_from_context,
    message::Message,
    sql_functions::{get_messages_of_secret, get_user},
    user::User,
};

pub struct Secret {
    pub id: String,
    pub creator_id: String,
    pub limit_number: Option<i64>,
    pub title: String,
}

#[derive(Union)]
pub enum SecretMessages {
    Locked(LockedMessages),
    Unlocked(UnlockedMessages),
}

#[derive(SimpleObject)]
pub struct LockedMessages {
    pub reason: String,
}

#[derive(SimpleObject)]
pub struct UnlockedMessages {
    pub messages: Vec<Message>,
}

#[Object]
impl Secret {
    pub async fn id(&self) -> String {
        self.id.to_string()
    }

    pub async fn title(&self) -> String {
        self.title.to_string()
    }

    pub async fn creator_id(&self) -> String {
        self.creator_id.to_string()
    }

    pub async fn limit_number(&self) -> Option<i64> {
        self.limit_number.clone()
    }

    pub async fn creator<'ctx>(&self, ctx: &Context<'ctx>) -> Result<User, anyhow::Error> {
        let pool = get_pool_from_context(ctx).await?;
        let user = get_user(&self.creator_id, &pool)
            .await
            .map_err(|e| anyhow::anyhow!("Query Failed {:#?}", e))?
            .ok_or(anyhow::anyhow!("Cant find creator"))?;
        Ok(user)
    }

    pub async fn messages<'ctx>(
        &self,
        ctx: &Context<'ctx>,
    ) -> Result<SecretMessages, anyhow::Error> {
        let user_id = get_user_id_from_context(ctx).await?;
        let pool = get_pool_from_context(ctx).await?;
        let messages = get_messages_of_secret(&self.id, &pool).await?;
        if messages.iter().any(|message| message.creator_id == user_id) {
            Ok(SecretMessages::Unlocked(UnlockedMessages { messages }))
        } else {
            Ok(SecretMessages::Locked(LockedMessages {
                reason: "Answer secret to read others answers".into(),
            }))
        }
    }
}
