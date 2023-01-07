use poem::{get, handler, Route};
use shuttle_service::error::CustomError;
use sqlx::{Executor, PgPool};

#[handler]
fn hello_world() -> &'static str {
    "Hello, world!"
}

#[shuttle_service::main]
async fn poem(
    #[shuttle_shared_db::Postgres] pool: PgPool,
) -> shuttle_service::ShuttlePoem<impl poem::Endpoint> {
    pool.execute(include_str!("../sql/schema1.sql"))
        .await
        .map_err(CustomError::new)?;

    let app = Route::new().at("/hello", get(hello_world));

    Ok(app)
}
