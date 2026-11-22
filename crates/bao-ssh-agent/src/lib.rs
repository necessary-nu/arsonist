//! An ssh agent whose one key is an Ed25519 key in OpenBao's transit engine.
//! The agent never holds the key: it asks OpenBao for each signature, so
//! whoever can reach the agent can use the key while it runs, and nobody
//! can take it away.

pub mod agent;
pub mod openbao;

pub use agent::{Agent, KeyStore, public_key};
#[cfg(unix)]
pub use agent::{Background, Serving};
pub use openbao::{Login, OpenBao, Transit};
