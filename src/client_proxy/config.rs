
use std::sync::atomic::AtomicUsize;

use iroh::{EndpointAddr, KeyParsingError, SecretKey, PublicKey, endpoint::BindError};
use log::*;
use serde::{Serialize, Deserialize};
use clap::Parser;
use tokio::net::TcpListener;
use thiserror::Error;
use std::sync::Arc;
use core::str::FromStr;
use core::convert::From;
use std::path::{PathBuf};

use crate::{BridgeSettings, client_proxy::core::ClientProxy,
    utils::{self, LoadSecretKeyError, starts_with_existing_dir, Directories}};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub max_connections: usize,
    pub max_streams: usize,
    pub remote_id: String,
    pub secret_key_file: Option<String>
}

impl Config {
    pub fn dump(&self) {
        println!("bind_addr: {}", self.bind_addr);
        println!("max_connections: {}", self.max_connections);
        println!("max_streams: {}", self.max_streams);
        println!("remote_id: {}", self.remote_id);
        println!("secret_key_file: {:?}", self.secret_key_file);
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".into(),
            max_connections: 1000,
            max_streams: 10,
            remote_id: "".into(),
            secret_key_file: Some("secret.prv".to_string())
        }
    }
}


#[derive(Parser, Debug, serde::Serialize, Clone)]
#[command(author, version, about = "Nostr-Iroh client proxy")]
pub struct CliArgs {
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,

    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<usize>,

    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,

    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key_file: Option<String>,

    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>
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
    pub async fn from_config(config: &Config, dirs: &Directories) -> Result<Self, CreateError> {
        let listener = TcpListener::bind(&config.bind_addr).await.inspect_err(|e|{
            error!("Error while binding TCP listener to address {}: {}", &config.bind_addr, e);
        } )?;

        let bridge_settings = Arc::new(BridgeSettings {
            max_streams: AtomicUsize::new(config.max_streams)
        });

        let sec: SecretKey = if let Some(s) = &config.secret_key_file {
            let mut path = PathBuf::from(&s);
            if !starts_with_existing_dir(&path) {
                if !dirs.user_config.is_empty() {
                    path = dirs.user_config.clone().join(path);
                }
            }
            utils::load_or_create_sec(&path, true)?
        } else { SecretKey::generate() };

        let ep = utils::create_endpoint(sec).await?;

        let addr = EndpointAddr::from(PublicKey::from_str(&config.remote_id)?);

        Ok(ClientProxy::new(ep, listener, None, addr, bridge_settings, config.max_connections))
    }
}
