
use std::sync::atomic::AtomicUsize;

use iroh::{EndpointAddr, KeyParsingError, SecretKey, PublicKey, endpoint::BindError};
use log::*;
use serde::{Serialize, Deserialize};
use figment::{Figment, providers::{Format, Toml, Env, Serialized}};
use clap::Parser;
use tokio::net::TcpListener;
use thiserror::Error;
use std::sync::Arc;
use core::str::FromStr;
use core::convert::From;
use std::path::Path;

use crate::{BridgeSettings, client_proxy::core::ClientProxy, utils::{self, LoadSecretKeyError}};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub max_connections: usize,
    pub max_streams: usize,
    pub remote_id: String,
    pub secret_key_file: Option<String>
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".into(),
            max_connections: 1000,
            max_streams: 10,
            remote_id: "".into(),
            secret_key_file: None
        }
    }
}


#[derive(Parser, Debug)]
#[command(author, version, about = "Nostr-Iroh client proxy")]
struct CliArgs {
    #[arg(short, long)]
    bind_addr: Option<String>,

    #[arg(short, long)]
    max_connections: Option<usize>,

    #[arg(short, long)]
    max_streams: Option<usize>,

    #[arg(short, long)]
    remote_id: Option<String>,

    #[arg(short, long)]
    secure_key_file: Option<String>,

    #[arg(short, long, default_value = "config.toml")]
    config: String
}

#[derive(Error, Debug)]
pub enum CreateError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Key parsing error: {0}")]
    KeyParsingError(#[from] KeyParsingError),
    #[error("Bind error: {0}")]
    BindError(#[from] BindError),
    #[error("Loading secret key error: {0}")]
    LoadSecretKeyError(#[from] LoadSecretKeyError)
}

impl ClientProxy {
    pub async fn from_config(config: &Config) -> Result<Self, CreateError> {
        let listener = TcpListener::bind(&config.bind_addr).await.inspect_err(|e|{
            error!("Error while binding TCP listener to address {}: {}", &config.bind_addr, e);
        } )?;

        let bridge_settings = Arc::new(BridgeSettings {
            max_streams: AtomicUsize::new(config.max_streams)
        });

        let addr = EndpointAddr::from(PublicKey::from_str(&config.remote_id)?);

        let sec: SecretKey = if let Some(s) = &config.secret_key_file {
            let path = Path::new(&s);
            utils::load_or_create_sec(&path, true)?
        } else { SecretKey::generate() };

        let ep = utils::create_endpoint(sec).await?;

        Ok(ClientProxy::new(ep, listener, None, addr, bridge_settings, config.max_connections))
    }
}
