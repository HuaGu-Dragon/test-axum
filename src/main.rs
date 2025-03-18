use std::{fmt::Display, sync::LazyLock, time::Duration};

use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::net::TcpListener;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .pretty(),
        )
        .init();

    let db_connection_str = "postgres://postgres:root@127.0.0.1:5432/postgres";

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&db_connection_str)
        .await
        .expect("can't connect to database");

    let app = Router::new()
        .route("/hello", get(|| async { Html("Hello, World!") }))
        .route(
            "/",
            get(using_connection_pool_extractor).post(using_connection_extractor),
        )
        .route("/user/{id}", get(get_user).delete(delete_user))
        .route("/user", post(create_user))
        .route("/protected", get(protected))
        .route("/authorize", post(authorize))
        .with_state(pool);

    let listener = TcpListener::bind("localhost:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Debug, Deserialize)]
struct User {
    id: i32,
    name: String,
    pwd: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct UserResponse {
    id: i32,
    name: String,
}

// test database
async fn using_connection_pool_extractor(
    State(pool): State<PgPool>,
) -> Result<String, (StatusCode, String)> {
    sqlx::query_scalar("select 'hello world from pg'")
        .fetch_one(&pool)
        .await
        .map_err(internal_error)
}

struct DatabaseConnection(sqlx::pool::PoolConnection<sqlx::Postgres>);

impl<S> FromRequestParts<S> for DatabaseConnection
where
    PgPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = PgPool::from_ref(state);

        let conn = pool.acquire().await.map_err(internal_error)?;

        Ok(Self(conn))
    }
}

async fn using_connection_extractor(
    DatabaseConnection(mut conn): DatabaseConnection,
) -> Result<String, (StatusCode, String)> {
    sqlx::query_scalar("select 'hello world from pg'")
        .fetch_one(&mut *conn)
        .await
        .map_err(internal_error)
}

fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
async fn create_user(
    State(pool): State<PgPool>,
    user: axum::Json<User>,
) -> Result<axum::Json<UserResponse>, (StatusCode, String)> {
    let user = user.0;
    let user = sqlx::query_as::<_, UserResponse>(
        r#"
        insert into users (id, name, pwd)
        values ($1, $2, $3)
        returning id, name
        "#,
    )
    .bind(user.id)
    .bind(user.name)
    .bind(user.pwd)
    .fetch_one(&pool)
    .await
    .map_err(internal_error)?;

    Ok(axum::Json(user))
}

async fn get_user(
    State(pool): State<PgPool>,
    id: axum::extract::Path<i32>,
) -> Result<axum::Json<UserResponse>, (StatusCode, String)> {
    let user = sqlx::query_as::<_, UserResponse>(
        r#"
        select id, name
        from users
        where id = $1
        "#,
    )
    .bind(id.0)
    .fetch_one(&pool)
    .await
    .map_err(internal_error)?;

    Ok(axum::Json(user))
}

async fn delete_user(
    State(pool): State<PgPool>,
    id: axum::extract::Path<i32>,
) -> Result<axum::Json<UserResponse>, (StatusCode, String)> {
    let user = sqlx::query_as::<_, UserResponse>(
        r#"
        delete from users
        where id = $1
        returning id, name
        "#,
    )
    .bind(id.0)
    .fetch_one(&pool)
    .await
    .map_err(internal_error)?;

    Ok(axum::Json(user))
}
// end test database

// test jwt
static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        tracing::debug!("Keys created");
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}

#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

async fn protected(claims: Claims) -> Result<Html<String>, AuthError> {
    Ok(Html(format!(
        "Welcome to the protected area :)\nYour data:\n{claims}",
    )))
}

async fn authorize(Json(payload): Json<User>) -> Result<Json<AuthBody>, AuthError> {
    if payload.name.is_empty() || payload.pwd.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    if payload.name != "HuaGu_Dragon" || payload.pwd != "123456" {
        return Err(AuthError::WrongCredentials);
    }

    // link to database
    // let user = sqlx::query_as::<_, UserResponse>(
    //     r#"
    //     select id, name
    //     from users
    //     where name = $1 and pwd = $2
    //     "#,
    // )
    // .bind(payload.name)
    // .bind(payload.pwd)
    // .fetch_one(&pool)
    // .await
    // .map_err(internal_error)?;

    let claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
        exp: 2000000000,
    };

    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    Ok(Json(AuthBody::new(token)))
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}\nCompany: {}", self.sub, self.company)
    }
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
// end test jwt
