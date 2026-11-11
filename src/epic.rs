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

/// Validate the live OAuth session and native game exchange-code endpoint.
/// This cannot establish EAC or matchmaking compatibility without launching a game.
pub fn online_preflight() -> Result<(), String> {
    let session = refreshed_session()?;
    let client = http_client()?;
    let response = client
        .get(format!("{OAUTH_BASE}/verify"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| format!("Epic OAuth verification failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("Epic OAuth verification returned HTTP {}", response.status()));
    }
    let verification: Value = response.json()
        .map_err(|err| format!("Invalid Epic OAuth verification data: {err}"))?;
    let verified_id = verification.get("account_id").and_then(Value::as_str)
        .ok_or_else(|| "Epic OAuth verify response has no account_id".to_string())?;
    if verified_id != session.account_id {
        return Err("Epic OAuth account ID does not match saved session".into());
    }
    println!("Epic OAuth session: verified (account ID matches)");
    let code = game_exchange_token(&session)?;
    if code.is_empty() {
        return Err("Epic issued an empty game exchange code".into());
    }
    println!("Epic game exchange-code endpoint: passed (token kept private)");
    println!("EAC / multiplayer server access: requires real in-game validation");
    Ok(())
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


/// Network metadata for a legitimate Epic-owned Windows game installation.
/// Token and signed CDN URL query strings are never written to stdout.
pub struct DownloadPlan {
    pub manifest: crate::manifest::Manifest,
    pub bases: Vec<String>,
    pub raw_manifest: Vec<u8>,
    pub app_name: String,
    pub namespace: String,
}

pub fn download_plan(selector: &str) -> Result<DownloadPlan, String> {
    use sha1::{Digest, Sha1};
    use std::io::Read;
    let session = refreshed_session()?;
    let client = http_client()?;
    const LAUNCHER: &str = "https://launcher-public-service-prod06.ol.epicgames.com";
    let response = client
        .get(format!("{LAUNCHER}/launcher/api/public/assets/Windows"))
        .bearer_auth(&session.access_token)
        .query(&[("label", "Live")])
        .send()
        .map_err(|e| format!("Epic assets request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("Epic Windows game asset lookup returned HTTP {}", response.status()));
    }
    let assets: Value = response.json().map_err(|e| format!("Invalid Epic assets response: {e}"))?;
    let records = assets.as_array().ok_or("Epic Windows game assets response was not an array")?;
    let game = records.iter().find(|asset| {
        let name = asset.get("appName").and_then(Value::as_str).unwrap_or_default();
        name.eq_ignore_ascii_case(selector) ||
        (selector.eq_ignore_ascii_case("Rocket League") && name.eq_ignore_ascii_case("Sugar"))
    }).ok_or_else(|| format!("Game {selector:?} not available in Epic Windows game assets for this account"))?;
    let field = |key: &str| -> Result<String, String> {
        game.get(key).and_then(Value::as_str).filter(|s|!s.is_empty())
            .map(str::to_owned).ok_or_else(|| format!("Epic game asset missing {key}"))
    };
    let app_name=field("appName")?;
    let namespace=field("namespace")?;
    let catalog=field("catalogItemId")?;
    // The API returns signed/expiring CDN URLs. Do not reuse them from previous runs.
    let mut url=reqwest::Url::parse(LAUNCHER).map_err(|e|e.to_string())?;
    url.path_segments_mut().map_err(|_|"Invalid launcher URL")?.extend([
        "launcher","api","public","assets","v2","platform","Windows",
        "namespace",namespace.as_str(),"catalogItem",catalog.as_str(),
        "app",app_name.as_str(),"label","Live"
    ]);
    let response=client.get(url).bearer_auth(&session.access_token)
        .send().map_err(|e| format!("Epic manifest lookup failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("Epic manifest lookup returned HTTP {}",response.status()));
    }
    let response:Value=response.json().map_err(|e|format!("Invalid Epic manifest response: {e}"))?;
    let elements=response.get("elements").and_then(Value::as_array).ok_or("No Epic manifest elements")?;
    let element=elements.first().ok_or("Epic returned an empty manifest list")?;
    if element.get("isPreloaded").and_then(Value::as_bool)==Some(true) {
        return Err("Epic reports a preloaded but not yet released build; installation is blocked".into());
    }
    let expected_hash=element.get("hash").and_then(Value::as_str)
        .ok_or("Manifest API did not supply a SHA-1 hash")?.to_ascii_lowercase();
    let manifests=element.get("manifests").and_then(Value::as_array)
        .ok_or("Epic manifest URLs missing")?;
    let mut bases=Vec::new();
    let mut errors=Vec::new();
    for entry in manifests {
        let Some(uri)=entry.get("uri").and_then(Value::as_str) else {continue;};
        let mut url=match reqwest::Url::parse(uri) {
            Ok(url) if url.scheme()=="https" =>url,
            _=>{errors.push("Ignored insecure/invalid CDN URI".to_string());continue;},
        };
        // Honor short-lived query parameters that Epic may include with signed CDN URLs.
        if let Some(params)=entry.get("queryParams").and_then(Value::as_array) {
            for param in params {
                if let (Some(k),Some(v))=(param.get("name").and_then(Value::as_str),param.get("value").and_then(Value::as_str)) {
                    url.query_pairs_mut().append_pair(k,v);
                }
            }
        }
        if let Some((base,_))=uri.rsplit_once('/') {
            if !bases.iter().any(|b|b==base) {bases.push(base.to_string());}
        }
        let response=match client.get(url).send() {
            Ok(response)=>response,
            Err(e)=>{errors.push(format!("CDN manifest request failed: {e}"));continue;},
        };
        if !response.status().is_success() {
            errors.push(format!("CDN manifest returned HTTP {}",response.status()));
            continue;
        }
        let mut bytes=Vec::new();
        let mut limited=response.take(128*1024*1024+1);
        if limited.read_to_end(&mut bytes).is_err() || bytes.len()>128*1024*1024 {
            errors.push("CDN manifest response too large or unreadable".into());continue;
        }
        let actual=hex::encode(Sha1::digest(&bytes));
        if actual!=expected_hash {errors.push("CDN manifest SHA-1 mismatch".into());continue;}
        let manifest=crate::manifest::parse(&bytes)?;
        if !manifest.app_name.is_empty() && !manifest.app_name.eq_ignore_ascii_case(&app_name) {
            return Err("Epic manifest AppName differs from authenticated asset".into());
        }
        if bases.is_empty() {return Err("No chunk CDN base URL was returned".into());}
        return Ok(DownloadPlan{manifest,bases,raw_manifest:bytes,app_name,namespace});
    }
    Err(format!("Could not retrieve a valid Epic game manifest: {}",errors.join("; ")))
}
