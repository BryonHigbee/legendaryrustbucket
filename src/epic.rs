//! Native Rust implementation of the initial Epic authentication and library calls.
//! No Python interpreter, subprocess or Legendary executable is used.
use crate::store::{data_dir, save_json};
use reqwest::blocking::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::time::Duration;

// Public client identifiers originally used by Legendary; configurable for API rotation.
const DEFAULT_CLIENT_ID: &str = "34a02cf8f4414e29b15921876da36f9a";
const DEFAULT_CLIENT_SECRET: &str = "daafbccc737745039dffe53d94fc76cf";
const OAUTH_BASE: &str = "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth";
const LIBRARY_URL: &str = "https://library-service.live.use1a.on.epicgames.com/library/api/public/items";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    access_token: String,
    refresh_token: String,
    account_id: String,
    #[serde(rename = "displayName", default)]
    display_name: String,
}

fn client_id() -> String {
    std::env::var("LRB_EPIC_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.into())
}
fn client_secret() -> String {
    std::env::var("LRB_EPIC_CLIENT_SECRET").unwrap_or_else(|_| DEFAULT_CLIENT_SECRET.into())
}

pub fn login_url() -> Result<String, String> {
    let mut redirect = Url::parse("https://www.epicgames.com/id/api/redirect").map_err(|e| e.to_string())?;
    redirect.query_pairs_mut().append_pair("clientId", &client_id()).append_pair("responseType", "code");
    let mut url = Url::parse("https://www.epicgames.com/id/login").map_err(|e| e.to_string())?;
    url.query_pairs_mut().append_pair("redirectUrl", redirect.as_str());
    Ok(url.to_string())
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("LRB/0.2.0 (Native Rust Rocket League launcher)")
        .build()
        .map_err(|err| format!("HTTP client initialization failed: {err}"))
}

fn issue_token(grant: &[(&str, &str)]) -> Result<Session, String> {
    let response = http_client()?
        .post(format!("{OAUTH_BASE}/token"))
        .basic_auth(client_id(), Some(client_secret()))
        .form(grant)
        .send()
        .map_err(|err| format!("Epic login request failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Epic refused authentication (HTTP {status}). Check code/session and log in again."));
    }
    response.json().map_err(|err| format!("Epic returned invalid token data: {err}"))
}

pub fn authorize(code: &str, exchange_code: bool) -> Result<(), String> {
    if code.trim().is_empty() {
        return Err("Authorization code cannot be empty".into());
    }
    let grant = if exchange_code { "exchange_code" } else { "authorization_code" };
    let session = issue_token(&[("grant_type", grant), (if exchange_code { "exchange_code" } else { "code" }, code), ("token_type", "eg1")])?;
    save_session(&session)?;
    println!("Authenticated as {}", display_name(&session));
    Ok(())
}

fn save_session(session: &Session) -> Result<(), String> {
    save_json(&data_dir()?.join("session.json"), session)
}

pub fn load_session() -> Result<Session, String> {
    let path = data_dir()?.join("session.json");
    let data = fs::read(&path).map_err(|_| "Not logged in. Run 'lrb auth' first.".to_string())?;
    serde_json::from_slice(&data).map_err(|_| "Stored session invalid. Run 'lrb auth' again.".to_string())
}

pub fn logout() -> Result<(), String> {
    let path = data_dir()?.join("session.json");
    match fs::remove_file(path) {
        Ok(()) => println!("Local Epic login removed."),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => println!("No saved login found."),
        Err(err) => return Err(format!("Unable to delete saved login: {err}")),
    }
    Ok(())
}

pub fn display_name(session: &Session) -> &str {
    if session.display_name.is_empty() { &session.account_id } else { &session.display_name }
}

pub fn refreshed_session() -> Result<Session, String> {
    let session = load_session()?;
    if session.refresh_token.trim().is_empty() {
        return Err("No refresh token saved; run 'lrb auth'.".into());
    }
    let refresh = issue_token(&[("grant_type", "refresh_token"), ("refresh_token", session.refresh_token.as_str()), ("token_type", "eg1")])?;
    save_session(&refresh)?;
    Ok(refresh)
}

pub fn game_exchange_token(session: &Session) -> Result<String, String> {
    let response = http_client()?
        .get(format!("{OAUTH_BASE}/exchange"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| format!("Game token request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("Game token request failed (HTTP {})", response.status()));
    }
    let body: Value = response.json().map_err(|err| format!("Invalid game token response: {err}"))?;
    body.get("code").and_then(Value::as_str).map(str::to_owned)
        .ok_or_else(|| "Epic did not return a game exchange code".into())
}

pub fn auth_status() -> Result<(), String> {
    let session = load_session()?;
    println!("Local session found for {}. Use 'lrb library' to check the online session.", display_name(&session));
    Ok(())
}

pub fn list_library() -> Result<(), String> {
    let session = refreshed_session()?;
    let client = http_client()?;
    let mut cursor: Option<String> = None;
    let mut count = 0usize;
    for _ in 0..100 {
        let mut request = client.get(LIBRARY_URL)
            .bearer_auth(&session.access_token)
            .query(&[("includeMetadata", "true")]);
        if let Some(cursor) = &cursor { request = request.query(&[("cursor", cursor)]); }
        let response = request.send().map_err(|err| format!("Library request failed: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("Epic library request failed (HTTP {})", response.status()));
        }
        let data: Value = response.json().map_err(|err| format!("Invalid library response: {err}"))?;
        if let Some(records) = data.get("records").and_then(Value::as_array) {
            for record in records {
                if let Some(app) = record.get("appName").and_then(Value::as_str) {
                    let title = record.get("metadata").and_then(|v| v.get("title")).and_then(Value::as_str).unwrap_or(app);
                    println!("{app}  |  {title}");
                    count += 1;
                }
            }
        }
        cursor = data.get("responseMetadata")
            .and_then(|v| v.get("nextCursor"))
            .and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
        if cursor.is_none() { println!("Library entries: {count}"); return Ok(()); }
    }
    Err("Epic library exceeds 100 pages; stopping to avoid unbounded requests".into())
}

pub fn session_identity(session: &Session) -> (&str, &str) {
    (&session.account_id, display_name(session))
}

#[cfg(test)]
mod tests {
    #[test]
    fn url_builds_epic_authorization_redirect() {
        let url = super::login_url().expect("valid url");
        assert!(url.starts_with("https://www.epicgames.com/id/login?redirectUrl="));
        assert!(url.contains("clientId"));
    }
}
