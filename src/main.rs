use std::sync::{Arc, RwLock};

use async_graphql::{
    http::{playground_source, GraphQLPlaygroundConfig},
    EmptySubscription, Schema,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, Method, Request, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Extension, Router, Server,
};
use axum_auth::AuthBearer;
use base64::Engine;
use include_dir::Dir;
use models::auth::AuthType;
use schema::{
    graph_schema::{Mutation, Query},
    sql_functions::{get_secret, get_user},
};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, SqlitePool};
use tower::ServiceExt;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
};

pub mod models;
pub mod schema;

lazy_static::lazy_static! {
    static ref FRONTEND_DIR: String = std::env::var("FRONTEND_DIR").unwrap_or(".".into());
    pub static  ref FIREBASE_VALUES:FirebaseValues = {
        let service_json_file = std::env::var("SERVICE_JSON").expect("No SERVICE_JSON defined");
        let data = std::fs::read_to_string(&service_json_file).unwrap();
        let data = serde_json::from_str(&data).unwrap();
        data
    };
}

#[derive(Serialize, Deserialize)]
pub struct FirebaseValues {
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    dotenvy::dotenv().ok().expect("No env");
    pretty_env_logger::init();

    let _firebase_client = FIREBASE_VALUES.client_id.clone();

    let pool = SqlitePool::connect(
        &std::env::var("DATABASE_URL").expect("NO DATABASE_URL in environment"),
    )
    .await
    .expect("Cannot connect to pool");
    pool.execute(include_str!("../sql/schema1.sql"))
        .await
        .expect("Execution failed");

    let schema = Schema::new(Query, Mutation, EmptySubscription);

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        // allow requests from any origin
        .allow_origin(Any);
    let app = Router::new()
        .route("/playground", get(graphql_playground))
        .route("/", post(graphql_handler))
        .route("/*secretId", get(secret_meta))
        .route("/", get(files_handler))
        // .route("/*path", get(files_handler))
        .with_state(pool)
        .layer(Extension(schema))
        .layer(cors);

    let port = std::env::var("PORT").unwrap_or("8000".into());
    Server::bind(&format!("0.0.0.0:{port}").parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn secret_meta(
    Path(secret_id): Path<String>,
    State(pool): State<SqlitePool>,
    req: Request<Body>,
) -> Response {
    let secret = get_secret(&secret_id, &pool).await;

    match secret {
        Ok(secret) => {
            let creator = get_user(&secret.creator_id, &pool)
                .await
                .unwrap_or_default()
                .map(|user| user.name)
                .unwrap_or_default();
            let tags = format!(
                r###"
<meta property="og:title" content="{title}" />
<meta property="og:description" content="{creator} is asking you to answer their question. Answer to know their answer too!" />
            "###,
                title = secret.title,
            );
            let path = std::path::Path::new(FRONTEND_DIR.as_str());
            let path = path.join("index.html");
            let index_file = std::fs::read_to_string(path);
            match index_file {
                Ok(file) => {
                    let replaced = file.replace("<!-- OG META -->", &tags);
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, mime_guess::mime::HTML.to_string())],
                        replaced,
                    )
                        .into_response();
                }
                Err(err) => {
                    log::warn!("Index file not found {err:#?}");
                }
            }
        }
        Err(err) => {
            log::debug!("Secret not found {err:#?}");
        }
    }
    return files_handler(req).await;
}

async fn files_handler(mut req: Request<Body>) -> Response {
    let mut path = req.uri().path().to_string();
    if path.starts_with("/") {
        path = path.replacen("/", "", 1);
    }
    let file_path = std::path::Path::new(FRONTEND_DIR.as_str()).join(&path);
    log::debug!("Check path {file_path:#?}");
    let mut new_path = path.to_string();
    if !file_path.exists() {
        new_path = "index.html".to_string();
    }
    let uri = req.uri();
    *req.uri_mut() = Uri::builder().path_and_query(new_path).build().unwrap();
    let serve_dir = ServeDir::new(FRONTEND_DIR.as_str());
    let serve_dir = serve_dir.not_found_service(ServeFile::new(format!(
        "{}/index.html",
        FRONTEND_DIR.as_str()
    )));
    match serve_dir.oneshot(req).await {
        Ok(res) => res.into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", err),
        )
            .into_response(),
    }
}

async fn graphql_handler(
    Extension(schema): Extension<Schema<Query, Mutation, EmptySubscription>>,

    token: Option<AuthBearer>,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();
    let auth_type = {
        if let Some(AuthBearer(token)) = token {
            let data = base64::engine::general_purpose::STANDARD.decode(token);
            if let Ok(data) = data {
                let authdata = serde_json::from_slice::<AuthType>(&data);
                if let Ok(auth) = authdata {
                    auth
                } else {
                    log::debug!("token cant be decoded");

                    AuthType::NoAuth
                }
            } else {
                log::debug!("token invalid base64");

                AuthType::NoAuth
            }
        } else {
            log::debug!("no token found");

            AuthType::NoAuth
        }
    };

    log::debug!("Setting authType {auth_type:#?}");
    req = req.data(auth_type);
    req = req.data(pool);

    // headers.get("Auth")
    schema.execute(req).await.into()
}

async fn graphql_playground() -> impl IntoResponse {
    Html(playground_source(GraphQLPlaygroundConfig::new("/")))
}
