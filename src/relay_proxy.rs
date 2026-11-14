
use nostr_iroh::test::test_client_iroh_packet_sender;
use nostr_iroh::test::test_relay_handler;
use log::{error, warn, info, debug};
use nostr_iroh::utils;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;
use std::fmt::Display;
use std::os::unix::fs::PermissionsExt;
use thiserror::Error;
use directories::ProjectDirs;
use iroh::{SecretKey, PublicKey};
use iroh::endpoint;
use tokio;
use anyhow::Result;

use crate::utils::{load_or_create_sec};

const DOMAIN: &'static str = "pirogronian";
const ORGANIZATION: &'static str = "nostr-iroh";
const APPNAME: &'static str = "relay-proxy";
const SECFILENAME: &'static str = "sec.prv";
const PUBFILENAME: &'static str = "pubid.txt";

fn get_config_dir() -> Option<PathBuf> {
    if let Some(project_path) = ProjectDirs::from(DOMAIN, ORGANIZATION, APPNAME) {
        return Some(project_path.config_dir().to_path_buf());
    }
    None
}

fn publish_pub_key(pub_key: PublicKey) -> Result<(), std::io::Error> {
    let pub_key_str = pub_key.to_string();
    info!("Node public key: {}",pub_key_str);
    if let Some(mut path) = get_config_dir() {
        path = path.join(PUBFILENAME);
        debug!("Writing pub id to file: {:?}", path);
        let mut file = File::create(path)?;
        file.write_all(&pub_key_str.as_bytes())?;
    }
    Ok(())
}

async fn init_endpoint(sec: SecretKey) -> Result<endpoint::Endpoint, endpoint::BindError> {
    let ep = iroh::endpoint::Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(nostr_iroh::ALPNs.to_vec())
        .secret_key(sec)
        .bind()
        .await;
    ep
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let proj_path_o = get_config_dir();
    if proj_path_o.is_none() {
        error!("No project directory avaliable!");
        return
    }
    let proj_path = proj_path_o.unwrap();
    let sec_key_file_path = proj_path.join(SECFILENAME);
    let sec_ret = load_or_create_sec(&sec_key_file_path, true);
    if let Err(msg) = sec_ret {
        error!("Cannot initiate secret key: {}", msg);
        return
    }
    let sec = sec_ret.unwrap();
    if let Err(e) = publish_pub_key(sec.public()) { error!("{}", e); }
    let ep_ret = init_endpoint(sec).await;
    if let Err(msg) = ep_ret {
        error!("Cannot init the endpoint: {}", msg);
        return
    }
    let ep = ep_ret.unwrap();
    let addr = ep.addr();
    debug!("Spawning test relay with addr: {:?}", addr);
    tokio::spawn(test_relay_handler(ep.clone()));
    test_client_iroh_packet_sender(addr).await;
    if let Err(e) = tokio::signal::ctrl_c().await { error!("{}", e) }
    ep.close().await;
    ()
}
