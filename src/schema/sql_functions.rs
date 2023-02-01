use sqlx::SqlitePool;
use uuid::Uuid;

use crate::schema::{message::Message, secret::Secret};

use super::user::User;

pub async fn create_user(id: &str, name: &str, pool: &SqlitePool) -> anyhow::Result<User> {
    let _result = sqlx::query!(
        "
        INSERT INTO users(id, name)
        VALUES ($1, $2)
    ",
        id,
        name
    )
    .execute(pool)
    .await?;

    let result = User {
        id: id.to_string(),
        name: name.to_string(),
        notification_token: None,
    };
    Ok(result)
}

pub async fn set_notification_token_for_user(
    user_id: &str,
    token: &str,
    pool: &SqlitePool,
) -> anyhow::Result<()> {
    let _result = sqlx::query!(
        "
        UPDATE users
        SET notification_token = $1
        WHERE id = $2
    ",
        token,
        user_id
    )
    .execute(pool)
    .await?;
    if _result.rows_affected() > 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("No Rows affected"))
    }
}

pub async fn create_secret(
    creator_id: &str,
    title: &str,
    pool: &SqlitePool,
) -> anyhow::Result<Secret> {
    let secret = Secret {
        id: Uuid::new_v4().to_string(),
        creator_id: creator_id.to_string(),
        limit_number: None,
        title: title.to_string(),
    };
    let _result = sqlx::query!(
        "
        INSERT INTO secret(id, creator_id, title)
        VALUES ($1, $2, $3)
    ",
        secret.id,
        creator_id,
        title,
    )
    .execute(pool)
    .await?;
    Ok(secret)
}

pub async fn create_message(
    secret_id: &str,
    creator_id: &str,
    message: &str,
    pool: &SqlitePool,
) -> anyhow::Result<Message> {
    let message = Message {
        id: Uuid::new_v4().to_string(),
        creator_id: creator_id.to_string(),
        message: message.to_string(),
        secret_id: secret_id.to_string(),
    };
    let _result = sqlx::query!(
        "
        INSERT INTO message(id, creator_id, secret_id, message)
        VALUES ($1, $2, $3, $4)

    ",
        message.id,
        creator_id,
        secret_id,
        message.message
    )
    .execute(pool)
    .await?;
    Ok(message)
}

pub async fn get_messages_of_user(
    user_id: &str,
    pool: &SqlitePool,
) -> anyhow::Result<Vec<Message>> {
    let messages = sqlx::query_as!(
        Message,
        "SELECT * 
        FROM message 
        WHERE creator_id = $1
        ",
        user_id
    )
    .fetch_all(pool)
    .await?;
    Ok(messages)
}

pub async fn get_secrets_with_user(
    user_id: &str,
    pool: &SqlitePool,
) -> anyhow::Result<Vec<Secret>> {
    let secrets = sqlx::query_as!(
        Secret,
        "SELECT * from secret
        WHERE id IN (SELECT secret_id FROM message where creator_id = $1 GROUP BY secret_id)",
        user_id
    )
    .fetch_all(pool)
    .await?;
    Ok(secrets)
}

pub async fn get_secret(secret_id: &str, pool: &SqlitePool) -> anyhow::Result<Secret> {
    let secrets = sqlx::query_as!(
        Secret,
        "SELECT * from secret
        WHERE id = $1",
        secret_id
    )
    .fetch_one(pool)
    .await?;
    Ok(secrets)
}

pub async fn get_assosicated_users_with_user(
    user_id: &str,
    pool: &SqlitePool,
) -> anyhow::Result<Vec<User>> {
    let users = sqlx::query_as!(
        User,
        "SELECT u.* from users u INNER JOIN message e ON e.creator_id = u.id INNER JOIN message m ON e.secret_id = m.secret_id
        WHERE u.id != $1
        ",
        user_id
    )
    .fetch_all(pool)
    .await?;
    Ok(users)
}

pub async fn get_user(user_id: &str, pool: &SqlitePool) -> anyhow::Result<Option<User>> {
    let user = sqlx::query_as!(User, "SELECT * from users WHERE id = $1", user_id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_messages_of_secret(
    secret_id: &str,
    pool: &SqlitePool,
) -> anyhow::Result<Vec<Message>> {
    let secrets = sqlx::query_as!(
        Message,
        "
        SELECT * from message where secret_id = $1
    ",
        secret_id
    )
    .fetch_all(pool)
    .await?;
    Ok(secrets)
}
