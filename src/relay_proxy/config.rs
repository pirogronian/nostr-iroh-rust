
use std::sync::atomic::AtomicUsize;

use http::{Uri, uri::InvalidUri};
use iroh::{KeyParsingError, SecretKey, endpoint::BindError};
use log::*;
use serde::{Serialize, Deserialize};
use clap::Parser;
use thiserror::Error;
use tokio_websockets::Connector;
use std::sync::Arc;
use core::str::FromStr;
use core::convert::From;
use std::path::{PathBuf};

use crate::{BridgeSettings, relay_proxy::core::RelayProxy,
    utils::{self, LoadSecretKeyError, starts_with_existing_dir, Directories,
    create_tls_connector}};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub max_connections: usize,
    pub max_streams: usize,
    pub relay_addr: String,
    pub secret_key_file: Option<String>,
    pub print_iroh_messages: bool,
    pub print_websocket_messages: bool
}

impl Config {
    pub fn dump(&self) {
        println!("max_connections: {}", self.max_connections);
        println!("max_streams: {}", self.max_streams);
        println!("relay_addr: {}", self.relay_addr);
        println!("secret_key_file: {:?}", self.secret_key_file);
        println!("print_iroh_messages: {:?}", self.print_iroh_messages);
        println!("print_websocket_messages: {:?}", self.print_websocket_messages);
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_streams: 10,
            relay_addr: "ws://127.0.0.1:8080".into(),
            secret_key_file: Some("secret.prv".to_string()),
            print_iroh_messages: false,
            print_websocket_messages: false
        }
    }
}

#[derive(Parser, Debug, serde::Serialize, Clone)]
#[command(author, version, about = "Nostr-Iroh relay proxy")]
pub struct CliArgs {
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,

    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<usize>,

    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_addr: Option<String>,

    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key_file: Option<String>,

    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub print_iroh_messages: Option<bool>,

    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub print_websocket_messages: Option<bool>,

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
    LoadSecretKeyError(#[from] LoadSecretKeyError),
    #[error("Invalid URI: {0}")]
    InvalidUri(#[from] InvalidUri)
}

impl RelayProxy {
    pub async fn from_config(config: &Config, dirs: &Directories) -> Result<Self, CreateError> {
        let uri = Uri::from_str(&config.relay_addr)?;

        let connector = match uri.scheme_str() {
            Some(scheme) => {
                if scheme == "wss" {
                    Connector::Rustls(create_tls_connector())
                }
                else { Connector::Plain }
            }
            None => Connector::Plain
        };

        let bridge_settings = Arc::new(BridgeSettings {
            max_streams: AtomicUsize::new(config.max_streams),
            print_iroh_messages: config.print_iroh_messages.into(),
            print_websocket_messages: config.print_websocket_messages.into()
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

        Ok(RelayProxy::new(ep, uri, Some(connector), bridge_settings, config.max_connections))
    }
}
