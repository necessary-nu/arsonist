//! OpenBao, and the Ed25519 key in its transit engine that the agent signs
//! with. The key never leaves OpenBao.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};
use ureq::Body;
use ureq::http::Response;

/// How the agent knows itself to OpenBao.
#[derive(Debug, Clone, PartialEq)]
pub enum Login {
    /// `{"role_id": "…", "secret_id": "…"}` in `file`, read at every login,
    /// so a new secret id needs no restart. For machines.
    AppRole { mount: String, file: PathBuf },
    /// A token given directly, such as a person's from `bao login`. It is
    /// used until OpenBao refuses it.
    Token(String),
}

#[derive(Deserialize)]
struct AppRole {
    role_id: String,
    secret_id: String,
}

/// Credentials go to this address, so only over TLS, or to this machine.
pub fn check_address(address: &str) -> Result<()> {
    let local = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"];
    let rest = address.strip_prefix("https://").or_else(|| {
        local
            .iter()
            .any(|l| address.starts_with(l))
            .then_some("local")
    });
    match rest {
        Some(host) if !host.is_empty() => Ok(()),
        _ => bail!("{address:?}: an https:// address, such as https://vault.example"),
    }
}

pub struct OpenBao {
    http: ureq::Agent,
    address: String,
    login: Login,
    /// The token in use, and when to log in again for a new one: at two
    /// thirds of its lease, or never for a token without one.
    token: Mutex<Option<(String, Option<Instant>)>>,
}

/// Each `errors` entry of an answer OpenBao refused, for the message.
fn errors(response: &mut Response<Body>) -> String {
    let body = response
        .body_mut()
        .with_config()
        .limit(16 * 1024)
        .lossy_utf8(true)
        .read_to_string()
        .unwrap_or_default();
    match serde_json::from_str::<Value>(&body) {
        Ok(v) => v["errors"]
            .as_array()
            .map(|e| {
                e.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default(),
        Err(_) => body.trim().to_string(),
    }
}

fn json_of(response: &mut Response<Body>, what: &str) -> Result<Value> {
    let body = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_string()
        .with_context(|| format!("reading the answer to {what}"))?;
    serde_json::from_str(&body).with_context(|| format!("the answer to {what} is not JSON"))
}

impl OpenBao {
    pub fn new(address: &str, login: Login) -> Result<OpenBao> {
        check_address(address)?;
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(concat!("bao-ssh-agent/", env!("CARGO_PKG_VERSION")))
            .timeout_global(Some(Duration::from_secs(30)))
            .build();
        let token = match &login {
            Login::Token(token) => Some((token.clone(), None)),
            Login::AppRole { .. } => None,
        };
        Ok(OpenBao {
            http: ureq::Agent::new_with_config(config),
            address: address.trim_end_matches('/').to_string(),
            login,
            token: Mutex::new(token),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.address)
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.call(path, None)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.call(path, Some(body))
    }

    /// Call OpenBao, logging in again once if an AppRole token is refused,
    /// and return the answer's `data`.
    fn call(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        let method = if body.is_some() { "POST" } else { "GET" };
        let attempts = match self.login {
            Login::AppRole { .. } => 2,
            Login::Token(_) => 1,
        };
        for attempt in 1..=attempts {
            let token = self.token(attempt > 1)?;
            let url = self.url(path);
            let response = match body {
                None => self.http.get(&url).header("X-Vault-Token", &token).call(),
                Some(body) => self
                    .http
                    .post(&url)
                    .header("X-Vault-Token", &token)
                    .content_type("application/json")
                    .send(body.to_string()),
            };
            let mut response = response.with_context(|| format!("{method} {url}"))?;
            let status = response.status().as_u16();
            // A revoked or expired token: OpenBao says 403 for both.
            if status == 403 && attempt < attempts {
                continue;
            }
            if status == 204 {
                return Ok(Value::Null);
            }
            if status != 200 {
                bail!(
                    "OpenBao answered {status} to {method} {path}: {}",
                    errors(&mut response)
                );
            }
            return Ok(json_of(&mut response, path)?["data"].clone());
        }
        unreachable!("the last attempt always returns")
    }

    fn token(&self, refresh: bool) -> Result<String> {
        let mut current = self.token.lock().unwrap_or_else(|e| e.into_inner());
        if !refresh
            && let Some((token, renew_at)) = &*current
            && renew_at.is_none_or(|at| Instant::now() < at)
        {
            return Ok(token.clone());
        }
        let Login::AppRole { mount, file } = &self.login else {
            unreachable!("a given token is never refreshed")
        };

        let approle: AppRole = serde_json::from_slice(
            &fs::read(file).with_context(|| format!("reading {}", file.display()))?,
        )
        .with_context(|| {
            format!(
                "{}: not {{\"role_id\": …, \"secret_id\": …}}",
                file.display()
            )
        })?;
        let path = format!("auth/{mount}/login");
        let body = json!({ "role_id": approle.role_id, "secret_id": approle.secret_id });
        let mut response = self
            .http
            .post(&self.url(&path))
            .content_type("application/json")
            .send(body.to_string())
            .with_context(|| format!("logging in to {}", self.address))?;
        let status = response.status().as_u16();
        if status != 200 {
            bail!(
                "OpenBao refused the AppRole in {} ({status}): {}",
                file.display(),
                errors(&mut response)
            );
        }
        let answer = json_of(&mut response, &path)?;
        let token = answer["auth"]["client_token"]
            .as_str()
            .with_context(|| format!("no token from {path}"))?
            .to_string();
        let lease = Duration::from_secs(answer["auth"]["lease_duration"].as_u64().unwrap_or(0));
        let renew_at = (!lease.is_zero()).then(|| Instant::now() + lease * 2 / 3);
        *current = Some((token.clone(), renew_at));
        Ok(token)
    }
}

/// One Ed25519 key in the transit engine.
pub struct Transit {
    openbao: OpenBao,
    mount: String,
    key: String,
}

impl Transit {
    pub fn new(openbao: OpenBao, mount: &str, key: &str) -> Transit {
        Transit {
            openbao,
            mount: mount.to_string(),
            key: key.to_string(),
        }
    }

    /// `transit/<key>`, to say which key in messages.
    pub fn name(&self) -> String {
        format!("{}/{}", self.mount, self.key)
    }

    /// The key's latest version, and that version's public key.
    pub fn latest(&self) -> Result<(u64, [u8; 32])> {
        let path = format!("{}/keys/{}", self.mount, self.key);
        let data = self.openbao.get(&path)?;
        if data["type"] != "ed25519" {
            bail!(
                "{path} is a {} key; the ssh agent signs with ed25519 keys",
                data["type"]
            );
        }
        let version = data["latest_version"]
            .as_u64()
            .with_context(|| format!("{path}: no latest_version"))?;
        let public_key = data["keys"][version.to_string()]["public_key"]
            .as_str()
            .and_then(|key| STANDARD.decode(key).ok())
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
            .with_context(|| format!("{path}: no Ed25519 public key for version {version}"))?;
        Ok((version, public_key))
    }

    /// The Ed25519 signature of the key's version `version` over `data`.
    pub fn sign(&self, version: u64, data: &[u8]) -> Result<[u8; 64]> {
        let path = format!("{}/sign/{}", self.mount, self.key);
        let body = json!({ "input": STANDARD.encode(data), "key_version": version });
        let answer = self.openbao.post(&path, &body)?;
        answer["signature"]
            .as_str()
            .and_then(|s| s.strip_prefix(&format!("vault:v{version}:")))
            .and_then(|s| STANDARD.decode(s).ok())
            .and_then(|s| <[u8; 64]>::try_from(s).ok())
            .with_context(|| format!("{path}: an unexpected signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_only_travel_over_tls_or_to_this_machine() {
        assert!(check_address("https://vault.example").is_ok());
        assert!(check_address("http://127.0.0.1:8200").is_ok());
        assert!(check_address("http://vault.example").is_err());
        assert!(check_address("https://").is_err());
        assert!(check_address("vault.example").is_err());
    }
}
