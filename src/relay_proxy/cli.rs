
use env_logger;
use log::{debug, info, warn, error};
use figment::{Figment, providers::{Serialized, Toml, Format}};
use tokio;
use clap::Parser;
use std::{path::{Path, PathBuf}, sync::Arc};

use nostr_iroh::relay_proxy::{core::RelayProxy, config::{Config, CliArgs}};
use nostr_iroh::utils::{create_dir_all, Directories, publish};

const QUALIFIER: &str = "pub";
const ORGANIZATION: &str = "NostrIroh";
const APPLICATION: &str = "NostrIrohRelayProxy";

const CONFIG_FILE: &str = "config.toml";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    debug!("Welcome to relay-proxy!");

    let args = CliArgs::parse();

    let app_dirs = Directories::new(QUALIFIER, ORGANIZATION, APPLICATION);
    app_dirs.create_all();

    let mut figm = Figment::new();
    figm = figm.merge(Serialized::defaults(Config::default()));
    figm = figm.merge(Toml::file(&app_dirs.system_config.clone().join(CONFIG_FILE)));
    let config_file = if let Some(file) = &args.config {
        PathBuf::from(&file)
    } else {
        println!("User config dir: {}", app_dirs.user_config.display());
        app_dirs.user_config.clone().join(CONFIG_FILE)
    };
    debug!("Loading user config from {}", config_file.display());
    figm = figm.merge(Toml::file(&config_file));
    figm = figm.merge(Serialized::defaults(args));
    let config: Config = figm.extract()?;
    debug!("Configuration completed.");
    config.dump();

    let proxy = RelayProxy::from_config(&config, &app_dirs).await?;
    debug!("Relay proxy created.");
    publish(&proxy.endpoint.id(), &app_dirs, "relay-proxy.pub");

    let shared_proxy = Arc::new(proxy);

    shared_proxy.start().await;

    Ok(())
}
