//! Just enough of the OCI distribution API to pull an image: resolve a tag
//! to a platform's manifest, and fetch blobs, checking every digest.

mod auth;
mod reference;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ureq::Body;
use ureq::http::Response;

pub use auth::{Challenge, Credential, Credentials};
pub use reference::{Reference, valid_digest};

/// The only platform arsonist boots.
pub const OS: &str = "linux";
pub const ARCHITECTURE: &str = "amd64";

const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

const MAX_MANIFEST_BYTES: u64 = 4 << 20;
const MAX_CONFIG_BYTES: u64 = 16 << 20;

#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Index {
    manifests: Vec<IndexEntry>,
}

#[derive(Deserialize)]
struct IndexEntry {
    digest: String,
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

/// The parts of an image's config file arsonist uses.
#[derive(Debug, Default, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub config: ContainerConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct ContainerConfig {
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
}

/// An image resolved to the manifest for [`OS`]/[`ARCHITECTURE`].
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The platform manifest's digest, which names this exact image.
    pub digest: String,
    pub manifest: Manifest,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn check_digest(what: &str, expected: &str, actual_hex: &str) -> Result<()> {
    if !valid_digest(expected) {
        bail!("{what}: unsupported digest {expected:?}");
    }
    if expected[7..] != *actual_hex {
        bail!("{what}: content is sha256:{actual_hex}, expected {expected}");
    }
    Ok(())
}

pub struct Client {
    agent: ureq::Agent,
    creds: Credentials,
    /// `Authorization` values by `host/repository`.
    authorizations: HashMap<String, String>,
}

impl Client {
    pub fn new(creds: Credentials) -> Client {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(concat!("arsonist/", env!("CARGO_PKG_VERSION")))
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_recv_response(Some(Duration::from_secs(120)))
            .timeout_per_read(Some(Duration::from_secs(120)))
            .build();
        Client {
            agent: ureq::Agent::new_with_config(config),
            creds,
            authorizations: HashMap::new(),
        }
    }

    /// GET a registry URL, answering one authentication challenge.
    fn get(&mut self, r: &Reference, url: &str, accept: Option<&str>) -> Result<Response<Body>> {
        let key = format!("{}/{}", r.api_host(), r.repository);
        let mut challenged = false;
        loop {
            let mut req = self.agent.get(url);
            if let Some(accept) = accept {
                req = req.header("Accept", accept);
            }
            if let Some(authorization) = self.authorizations.get(&key) {
                req = req.header("Authorization", authorization);
            }
            let mut resp = req.call().with_context(|| format!("GET {url}"))?;
            let status = resp.status();
            if status == 401 && !challenged {
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .with_context(|| format!("GET {url}: 401 without a WWW-Authenticate header"))?;
                let challenge = Challenge::parse(challenge)?;
                let authorization = self.authorize(r, &challenge)?;
                self.authorizations.insert(key.clone(), authorization);
                challenged = true;
                continue;
            }
            if !status.is_success() {
                let body = resp
                    .body_mut()
                    .with_config()
                    .limit(4096)
                    .lossy_utf8(true)
                    .read_to_string()
                    .unwrap_or_default();
                let hint = if status == 401 || status == 403 {
                    format!(
                        " (credentials for {}: `arsonist auth login {}`)",
                        r.registry, r.registry
                    )
                } else {
                    String::new()
                };
                bail!("GET {url}: HTTP {status}{hint}: {}", body.trim());
            }
            return Ok(resp);
        }
    }

    fn authorize(&self, r: &Reference, challenge: &Challenge) -> Result<String> {
        let cred = self.creds.get(&r.registry);
        match challenge.scheme.as_str() {
            "basic" => cred.map(Credential::basic_header).with_context(|| {
                format!(
                    "{} wants a password; `arsonist auth login {}`",
                    r.registry, r.registry
                )
            }),
            "bearer" => {
                let realm = challenge
                    .params
                    .get("realm")
                    .context("Bearer challenge without a realm")?;
                let scope = challenge
                    .params
                    .get("scope")
                    .cloned()
                    .unwrap_or_else(|| format!("repository:{}:pull", r.repository));
                let mut req = self.agent.get(realm).query("scope", &scope);
                if let Some(service) = challenge.params.get("service") {
                    req = req.query("service", service);
                }
                if let Some(cred) = cred {
                    req = req.header("Authorization", cred.basic_header());
                }
                let mut resp = req.call().with_context(|| format!("GET {realm}"))?;
                if !resp.status().is_success() {
                    bail!(
                        "{realm}: HTTP {} getting a token for {scope}",
                        resp.status()
                    );
                }
                #[derive(Deserialize)]
                struct Token {
                    token: Option<String>,
                    access_token: Option<String>,
                }
                let token: Token = serde_json::from_slice(
                    &resp.body_mut().with_config().limit(1 << 20).read_to_vec()?,
                )
                .with_context(|| format!("{realm}: unreadable token response"))?;
                let token = token
                    .token
                    .or(token.access_token)
                    .with_context(|| format!("{realm}: no token in the response"))?;
                Ok(format!("Bearer {token}"))
            }
            other => bail!(
                "{}: unsupported authentication scheme {other:?}",
                r.registry
            ),
        }
    }

    fn manifest_bytes(&mut self, r: &Reference, reference: &str) -> Result<(Vec<u8>, String)> {
        let url = format!(
            "https://{}/v2/{}/manifests/{reference}",
            r.api_host(),
            r.repository
        );
        let mut resp = self.get(r, &url, Some(MANIFEST_TYPES))?;
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(MAX_MANIFEST_BYTES)
            .read_to_vec()
            .with_context(|| format!("reading {url}"))?;
        let actual = sha256_hex(&bytes);
        if reference.starts_with("sha256:") {
            check_digest(&url, reference, &actual)?;
        }
        Ok((bytes, format!("sha256:{actual}")))
    }

    /// Resolve `r` to its manifest for [`OS`]/[`ARCHITECTURE`].
    pub fn resolve(&mut self, r: &Reference) -> Result<Resolved> {
        let (bytes, digest) = self.manifest_bytes(r, r.manifest_reference())?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).with_context(|| format!("{r}: manifest is not JSON"))?;
        if value.get("manifests").is_some() {
            let index: Index =
                serde_json::from_value(value).with_context(|| format!("{r}: unreadable index"))?;
            let entry = index
                .manifests
                .iter()
                .find(|m| {
                    m.platform
                        .as_ref()
                        .is_some_and(|p| p.os == OS && p.architecture == ARCHITECTURE)
                })
                .with_context(|| format!("{r} has no {OS}/{ARCHITECTURE} image"))?;
            let entry_digest = entry.digest.clone();
            let (bytes, digest) = self.manifest_bytes(r, &entry_digest)?;
            let manifest: Manifest = serde_json::from_slice(&bytes)
                .with_context(|| format!("{r}: unreadable manifest {digest}"))?;
            return Ok(Resolved { digest, manifest });
        }
        let manifest: Manifest =
            serde_json::from_value(value).with_context(|| format!("{r}: unreadable manifest"))?;
        Ok(Resolved { digest, manifest })
    }

    fn blob_url(r: &Reference, digest: &str) -> String {
        format!(
            "https://{}/v2/{}/blobs/{digest}",
            r.api_host(),
            r.repository
        )
    }

    pub fn image_config(&mut self, r: &Reference, manifest: &Manifest) -> Result<ImageConfig> {
        let url = Self::blob_url(r, &manifest.config.digest);
        let mut resp = self.get(r, &url, None)?;
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(MAX_CONFIG_BYTES)
            .read_to_vec()
            .with_context(|| format!("reading {url}"))?;
        check_digest(&url, &manifest.config.digest, &sha256_hex(&bytes))?;
        serde_json::from_slice(&bytes).with_context(|| format!("{url}: unreadable image config"))
    }

    /// Download a blob to `path`, checking its size and digest.
    pub fn blob_to_file(&mut self, r: &Reference, blob: &Descriptor, path: &Path) -> Result<()> {
        let url = Self::blob_url(r, &blob.digest);
        let resp = self.get(r, &url, None)?;
        let mut reader = resp.into_body().into_reader();
        let mut out =
            BufWriter::new(File::create(path).with_context(|| format!("{}", path.display()))?);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            let n = reader
                .read(&mut buf)
                .with_context(|| format!("reading {url}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])
                .with_context(|| format!("{}", path.display()))?;
            total += n as u64;
            if total > blob.size {
                bail!("{url}: more than the {} bytes the manifest says", blob.size);
            }
        }
        out.flush()?;
        if total != blob.size {
            bail!("{url}: {total} bytes, the manifest says {}", blob.size);
        }
        check_digest(&url, &blob.digest, &hex(&hasher.finalize()))
    }
}
