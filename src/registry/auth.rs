//! Registry credentials and the challenges registries answer with.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn basic_header(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.username, self.password))
        )
    }
}

/// Credentials by registry, read from a Docker `config.json`.
#[derive(Debug, Default)]
pub struct Credentials(HashMap<String, Credential>);

#[derive(Deserialize)]
struct DockerConfig {
    #[serde(default)]
    auths: HashMap<String, DockerAuth>,
}

#[derive(Deserialize)]
struct DockerAuth {
    auth: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

/// The registry a Docker `config.json` key means: `https://index.docker.io/v1/`
/// and plain `ghcr.io` both appear in the wild.
fn registry_of_key(key: &str) -> String {
    let host = key
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default();
    match host {
        "index.docker.io" | "registry-1.docker.io" => "docker.io".into(),
        h => h.into(),
    }
}

impl Credentials {
    pub fn parse(json: &str) -> Result<Credentials> {
        let config: DockerConfig = serde_json::from_str(json)?;
        let mut creds = HashMap::new();
        for (key, auth) in config.auths {
            let cred = match (auth.auth, auth.username, auth.password) {
                (_, Some(username), Some(password)) => Credential { username, password },
                (Some(encoded), _, _) => {
                    let decoded = STANDARD
                        .decode(encoded.trim())
                        .with_context(|| format!("auths.{key:?}.auth is not base64"))?;
                    let decoded = String::from_utf8(decoded)
                        .with_context(|| format!("auths.{key:?}.auth is not UTF-8"))?;
                    let (username, password) = decoded
                        .split_once(':')
                        .with_context(|| format!("auths.{key:?}.auth is not user:password"))?;
                    Credential {
                        username: username.into(),
                        password: password.into(),
                    }
                }
                _ => continue,
            };
            creds.insert(registry_of_key(&key), cred);
        }
        Ok(Credentials(creds))
    }

    /// The file's credentials, or none if there is no file.
    pub fn load(path: &Path) -> Result<Credentials> {
        match std::fs::read_to_string(path) {
            Ok(text) => Credentials::parse(&text).with_context(|| format!("{}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Credentials::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn get(&self, registry: &str) -> Option<&Credential> {
        self.0.get(registry)
    }

    pub fn set(&mut self, registry: &str, cred: Credential) {
        self.0.insert(registry_of_key(registry), cred);
    }

    pub fn to_docker_config(&self) -> String {
        let mut keys: Vec<_> = self.0.keys().collect();
        keys.sort();
        let auths: serde_json::Map<_, _> = keys
            .into_iter()
            .map(|k| {
                let c = &self.0[k];
                let auth = STANDARD.encode(format!("{}:{}", c.username, c.password));
                (k.clone(), serde_json::json!({ "auth": auth }))
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({ "auths": auths })).expect("plain JSON")
            + "\n"
    }
}

/// A `WWW-Authenticate` header: the scheme and its parameters.
#[derive(Debug, PartialEq, Eq)]
pub struct Challenge {
    pub scheme: String,
    pub params: HashMap<String, String>,
}

impl Challenge {
    pub fn parse(header: &str) -> Result<Challenge> {
        let header = header.trim();
        let (scheme, rest) = header.split_once(' ').unwrap_or((header, ""));
        let mut params = HashMap::new();
        let mut chars = rest.chars().peekable();
        loop {
            while chars.peek().is_some_and(|c| *c == ',' || c.is_whitespace()) {
                chars.next();
            }
            let key: String = chars.by_ref().take_while(|c| *c != '=').collect();
            if key.is_empty() {
                break;
            }
            let mut value = String::new();
            if chars.peek() == Some(&'"') {
                chars.next();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => value.extend(chars.next()),
                        '"' => break,
                        c => value.push(c),
                    }
                }
            } else {
                while let Some(c) = chars.next_if(|c| *c != ',') {
                    value.push(c);
                }
            }
            params.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
        if scheme.is_empty() {
            bail!("empty WWW-Authenticate header");
        }
        Ok(Challenge {
            scheme: scheme.to_ascii_lowercase(),
            params,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_challenges_keep_commas_inside_quotes() {
        let c = Challenge::parse(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull,push""#,
        )
        .unwrap();
        assert_eq!(c.scheme, "bearer");
        assert_eq!(c.params["realm"], "https://ghcr.io/token");
        assert_eq!(c.params["service"], "ghcr.io");
        assert_eq!(c.params["scope"], "repository:a/b:pull,push");
        let basic = Challenge::parse(r#"Basic realm=Registry"#).unwrap();
        assert_eq!(
            (basic.scheme.as_str(), basic.params["realm"].as_str()),
            ("basic", "Registry")
        );
    }

    #[test]
    fn docker_config_credentials_are_found_by_registry() {
        let creds = Credentials::parse(
            r#"{"auths": {
                "ghcr.io": {"auth": "dXNlcjpwYTpzcw=="},
                "https://index.docker.io/v1/": {"username": "hub", "password": "secret"},
                "quay.io": {"identitytoken": "x"}
            }}"#,
        )
        .unwrap();
        assert_eq!(
            creds.get("ghcr.io"),
            Some(&Credential {
                username: "user".into(),
                password: "pa:ss".into()
            })
        );
        assert_eq!(creds.get("docker.io").unwrap().username, "hub");
        assert!(creds.get("quay.io").is_none());
        let again = Credentials::parse(&creds.to_docker_config()).unwrap();
        assert_eq!(again.get("ghcr.io"), creds.get("ghcr.io"));
    }
}
