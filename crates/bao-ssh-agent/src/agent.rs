//! The agent: ssh-agent-lib's server, offering one key and having its key
//! store sign with it.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::async_trait;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_agent_lib::ssh_key::{Algorithm, PublicKey, Signature};
#[cfg(unix)]
use tokio::task::JoinHandle;
use tokio::task::spawn_blocking;

use crate::openbao::Transit;

/// Where the key is, which signs for the agent: OpenBao's transit engine,
/// or in tests, memory. Called from a blocking thread.
pub trait KeyStore: Send + Sync + 'static {
    /// The key's latest version, and that version's Ed25519 public key.
    fn latest(&self) -> Result<(u64, [u8; 32])>;
    /// Version `version`'s Ed25519 signature over `data`.
    fn sign(&self, version: u64, data: &[u8]) -> Result<[u8; 64]>;
    /// The key's name, for `ssh-add -l` and the log.
    fn name(&self) -> String;
}

impl KeyStore for Transit {
    fn latest(&self) -> Result<(u64, [u8; 32])> {
        Transit::latest(self)
    }

    fn sign(&self, version: u64, data: &[u8]) -> Result<[u8; 64]> {
        Transit::sign(self, version, data)
    }

    fn name(&self) -> String {
        Transit::name(self)
    }
}

/// The key as an `authorized_keys` line, to register with a git host.
pub fn public_key(store: &dyn KeyStore) -> Result<String> {
    let (version, public_key) = store.latest()?;
    let key = KeyData::Ed25519(Ed25519PublicKey(public_key));
    let comment = format!("{} v{version}", store.name());
    Ok(PublicKey::new(key, comment).to_openssh()?)
}

/// A version of the key, and its Ed25519 public key.
type Version = (u64, [u8; 32]);

/// The agent, cloned for each connection. The clones share the key's
/// version, looked up once: a rotation while the agent runs cannot have ssh
/// offer one version and sign with another.
#[derive(Clone)]
pub struct Agent {
    store: Arc<dyn KeyStore>,
    latest: Arc<Mutex<Option<Version>>>,
    /// Whom the agent serves, to log its signatures under.
    label: Arc<str>,
}

fn failed(label: &str, e: impl std::fmt::Display) -> AgentError {
    log::error!("{label}: {e:#}");
    AgentError::Failure
}

impl Agent {
    pub fn new(store: Arc<dyn KeyStore>, label: &str) -> Agent {
        Agent {
            store,
            latest: Arc::default(),
            label: label.into(),
        }
    }

    async fn latest(&self) -> Result<(u64, KeyData), AgentError> {
        let cached = *self.latest.lock().unwrap_or_else(|e| e.into_inner());
        let (version, public_key) = match cached {
            Some(latest) => latest,
            None => {
                let store = self.store.clone();
                let found = spawn_blocking(move || store.latest())
                    .await
                    .map_err(|e| failed(&self.label, e))?
                    .map_err(|e| failed(&self.label, e))?;
                *self.latest.lock().unwrap_or_else(|e| e.into_inner()) = Some(found);
                found
            }
        };
        Ok((version, KeyData::Ed25519(Ed25519PublicKey(public_key))))
    }
}

#[async_trait]
impl Session for Agent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let (version, key) = self.latest().await?;
        Ok(vec![Identity {
            credential: PublicCredential::Key(key),
            comment: format!("{} v{version}", self.store.name()),
        }])
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let (version, key) = self.latest().await?;
        if request.credential.key_data() != &key {
            return Err(failed(
                &self.label,
                "asked to sign with a key it does not have",
            ));
        }
        let store = self.store.clone();
        let signature = spawn_blocking(move || store.sign(version, &request.data))
            .await
            .map_err(|e| failed(&self.label, e))?
            .map_err(|e| failed(&self.label, e))?;
        log::info!(
            "{}: signed with {} v{version}",
            self.label,
            self.store.name()
        );
        Signature::new(Algorithm::Ed25519, signature.to_vec()).map_err(AgentError::other)
    }
}

/// Serve on a unix socket only its owner may use, until dropped.
#[cfg(unix)]
pub async fn serve_unix(path: &std::path::Path, agent: Agent) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listen(listener, agent).await?;
    Ok(())
}

/// Serve on a named pipe, such as `\\.\pipe\openssh-ssh-agent`, Windows
/// OpenSSH's own, until dropped.
#[cfg(windows)]
pub async fn serve_pipe(name: &str, agent: Agent) -> Result<()> {
    let listener = ssh_agent_lib::agent::NamedPipeListener::bind(name)?;
    listen(listener, agent).await?;
    Ok(())
}

/// Agents served from a runtime of their own, for callers that have none.
#[cfg(unix)]
pub struct Background {
    runtime: tokio::runtime::Runtime,
}

/// One agent being served; dropping it stops the listening. Connections
/// already made are answered until their clients hang up.
#[cfg(unix)]
pub struct Serving(JoinHandle<()>);

#[cfg(unix)]
impl Drop for Serving {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(unix)]
impl Background {
    pub fn new() -> Result<Background> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("bao-ssh-agent")
            .enable_all()
            .build()?;
        Ok(Background { runtime })
    }

    /// Serve `agent` on `listener`, which the caller has bound and given
    /// the permissions it wants.
    pub fn serve(
        &self,
        listener: std::os::unix::net::UnixListener,
        agent: Agent,
    ) -> Result<Serving> {
        listener.set_nonblocking(true)?;
        let listener = {
            let _runtime = self.runtime.enter();
            tokio::net::UnixListener::from_std(listener)?
        };
        let label = agent.label.clone();
        Ok(Serving(self.runtime.spawn(async move {
            if let Err(e) = listen(listener, agent).await {
                log::error!("{label}: the agent stopped: {e}");
            }
        })))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use anyhow::bail;
    use signature::{Signer as _, Verifier as _};
    use ssh_agent_lib::blocking::Client;
    use ssh_agent_lib::ssh_key::private::Ed25519Keypair;

    use super::*;

    /// Transit's part, played by keys in memory: version n is seeded with n.
    struct Memory {
        latest: AtomicU64,
    }

    impl Memory {
        fn at(version: u64) -> Arc<Memory> {
            Arc::new(Memory {
                latest: AtomicU64::new(version),
            })
        }

        fn keypair(version: u64) -> Ed25519Keypair {
            Ed25519Keypair::from_seed(&[version as u8; 32])
        }

        fn key(version: u64) -> KeyData {
            KeyData::Ed25519(Memory::keypair(version).public)
        }
    }

    impl KeyStore for Memory {
        fn latest(&self) -> Result<(u64, [u8; 32])> {
            let version = self.latest.load(Ordering::SeqCst);
            Ok((version, Memory::keypair(version).public.0))
        }

        fn sign(&self, version: u64, data: &[u8]) -> Result<[u8; 64]> {
            let signature: Signature = Memory::keypair(version).try_sign(data)?;
            Ok(signature.as_bytes().try_into()?)
        }

        fn name(&self) -> String {
            "transit/test".into()
        }
    }

    /// OpenBao out of reach.
    struct Unreachable;

    impl KeyStore for Unreachable {
        fn latest(&self) -> Result<(u64, [u8; 32])> {
            bail!("could not reach OpenBao")
        }

        fn sign(&self, _: u64, _: &[u8]) -> Result<[u8; 64]> {
            bail!("could not reach OpenBao")
        }

        fn name(&self) -> String {
            "transit/test".into()
        }
    }

    struct Served {
        _background: Background,
        serving: Option<Serving>,
        path: PathBuf,
    }

    impl Served {
        fn client(&self) -> Client<UnixStream> {
            Client::new(UnixStream::connect(&self.path).unwrap())
        }
    }

    impl Drop for Served {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn serve(store: Arc<dyn KeyStore>) -> Served {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bao-ssh-agent-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&path);
        let background = Background::new().unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        let serving = background
            .serve(listener, Agent::new(store, "test"))
            .unwrap();
        Served {
            _background: background,
            serving: Some(serving),
            path,
        }
    }

    fn sign_request(key: KeyData, data: &[u8]) -> SignRequest {
        SignRequest {
            credential: PublicCredential::Key(key),
            data: data.to_vec(),
            flags: 0,
        }
    }

    #[test]
    fn it_offers_the_one_key_and_signs_with_it() {
        let served = serve(Memory::at(1));
        let mut client = served.client();

        let identities = client.request_identities().unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].credential.key_data(), &Memory::key(1));
        assert_eq!(identities[0].comment, "transit/test v1");

        let data = b"a session's exchange hash, as ssh would send it";
        let signature = client.sign(sign_request(Memory::key(1), data)).unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        Memory::key(1).verify(data, &signature).unwrap();
    }

    #[test]
    fn a_rotation_while_it_runs_changes_nothing_it_offers() {
        let store = Memory::at(1);
        let served = serve(store.clone());
        assert_eq!(
            served.client().request_identities().unwrap()[0].comment,
            "transit/test v1"
        );
        store.latest.store(2, Ordering::SeqCst);

        let mut client = served.client();
        assert_eq!(
            client.request_identities().unwrap()[0].comment,
            "transit/test v1"
        );
        let signature = client.sign(sign_request(Memory::key(1), b"data")).unwrap();
        Memory::key(1).verify(b"data", &signature).unwrap();
        assert!(client.sign(sign_request(Memory::key(2), b"data")).is_err());
    }

    #[test]
    fn it_signs_with_no_other_key() {
        let served = serve(Memory::at(1));
        let mut client = served.client();
        assert!(client.sign(sign_request(Memory::key(7), b"data")).is_err());
    }

    #[test]
    fn it_refuses_what_it_does_not_do_and_keeps_answering() {
        let served = serve(Memory::at(1));
        let mut client = served.client();
        assert!(client.remove_all_identities().is_err());
        assert!(client.lock("a passphrase".into()).is_err());
        assert_eq!(client.request_identities().unwrap().len(), 1);
    }

    #[test]
    fn openbao_out_of_reach_is_a_refusal_not_a_hang() {
        let served = serve(Arc::new(Unreachable));
        let mut client = served.client();
        assert!(client.request_identities().is_err());
        assert!(client.sign(sign_request(Memory::key(1), b"data")).is_err());
    }

    #[test]
    fn it_stops_listening_when_dropped() {
        let mut served = serve(Memory::at(1));
        let mut kept = served.client();
        assert_eq!(kept.request_identities().unwrap().len(), 1);

        drop(served.serving.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while UnixStream::connect(&served.path).is_ok() {
            assert!(Instant::now() < deadline, "still listening");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            kept.request_identities().unwrap().len(),
            1,
            "a connection made before goes on being answered"
        );
    }

    #[test]
    fn the_public_key_is_an_authorized_keys_line() {
        let line = public_key(&*Memory::at(3)).unwrap();
        assert!(line.starts_with("ssh-ed25519 AAAA"), "{line}");
        assert!(line.ends_with(" transit/test v3"), "{line}");
    }
}
