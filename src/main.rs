use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize,Serialize};
use sqlx::SqlitePool;

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::HeaderMap;

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Signup {
    username: String,
    password: String,
    re_password: String,
}

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}

#[derive(sqlx::FromRow)]
struct User {
    id: i64,
    username: String,
    password: String,
}

const JWT_SECRET: &[u8] = b"657fecd7df7ea86c21418c2d77105b23662930561785b1a1ba6cbb1c486d3fea";

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: i64,         
    username: String,
    exp: usize,      
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

fn create_token(user: &User) -> Result<String, jsonwebtoken::errors::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: user.id,
        username: user.username.clone(),
        exp: now + 60 * 60 * 24,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))

}

fn verify_token(headers: &HeaderMap) -> Result<Claims, (StatusCode, String)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "missing token".to_string()))?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "invalid auth header".to_string()))?;

    let data = decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &Validation::default())
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {}", e)))?;

    Ok(data.claims)
}

async fn get_all_users(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as("SELECT id, username, password FROM users")
        .fetch_all(pool)
        .await
}

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("sqlite:auth.db?mode=rwc").await.unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("failed to create users table");


    get_all_users(&pool).await.expect("failed to load users");

    let app: Router<> = Router::new()
        .route("/", get(root))
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/me", get(me))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

async fn root() -> String {
    return String::from("Welcome to rust auth ;)");
}

async fn signup(State(pool): State<SqlitePool> ,Json(req): Json<Signup>) -> Result<String, (StatusCode, String)> { 
    let username = req.username;
    let password = req.password;
    let re_password = req.re_password;

    if password != re_password {
        return Err((StatusCode::BAD_REQUEST, "passwords do not match".into()));
    }

    let result = sqlx::query("SELECT id, username FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
   

    if result.is_some() {
        return Err((StatusCode::CONFLICT, "username already exists".into()));
    }

    let user: User = sqlx::query_as("INSERT INTO users (username, password) VALUES (?, ?) RETURNING id, username, password")
        .bind(&username)
        .bind(&password)
        .fetch_one(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
   

    Ok(format!("created user {} with id {}", user.username, user.id))
}
async fn login(State(pool): State<SqlitePool>, Json(req): Json<Login>) -> Result<Json<TokenResponse>, (StatusCode, String)>  {
    let username = req.username;
    let password = req.password;

    let user: Option<User> = sqlx::query_as("SELECT id, username, password FROM users WHERE username = ? ")
        .bind(&username)
        .fetch_optional(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let user = match user {
        Some(u) => u,
        None => return Err((StatusCode::UNAUTHORIZED, "invalid username or password".to_string())),
    };

    if user.password != password {
        return Err((StatusCode::UNAUTHORIZED, "Invalid username or password".to_string()));
    }    

    let token = create_token(&user)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TokenResponse { token })) 
}

async fn me(headers: HeaderMap) -> Result<String, (StatusCode, String)> {
    let claims = verify_token(&headers)?;
    Ok(format!("hello {} (id {})", claims.username, claims.sub))
}
