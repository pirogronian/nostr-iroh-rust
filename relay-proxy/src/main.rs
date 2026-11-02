
use log::{error, warn, info, debug};
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

#[derive(Error, Debug)]
pub enum LoadSecKeyError {
    #[error("Parsing secret error: {0}")]
    KeyParsingError(#[from] iroh::KeyParsingError),
    #[error("IO error while reading secret's file: {0}")]
    IoError(#[from] std::io::Error)
}

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

fn init_sec_key() -> Result<SecretKey, LoadSecKeyError> {
    let mut config_dir = PathBuf::new();
    if let Some(path) = get_config_dir() { config_dir = path }
    let file_path = config_dir.join(SECFILENAME);
    debug!("Secret's file path: {:?}", file_path);
    let mut ret = SecretKey::generate();
    if let Ok(mut file) = File::open(&file_path) {
        let mut s = String::new();
        file.read_to_string(&mut s)?;
        ret = SecretKey::from_str(&s)?;
    } else {
        let s = hex::encode(ret.to_bytes());
        if let Err(msg) = std::fs::create_dir_all(&config_dir) {
            error!("Error while creating secret's file path: {}", msg);
        }
        let cfret = File::create(file_path);
        match cfret {
            Ok(mut file) => {
                if let Ok(meta) = file.metadata() {
                    let mut perm = meta.permissions();
                    perm.set_mode(0600);
                    if let Err(msg) = file.set_permissions(perm) {
                        error!("Error while setting permissions to the secret's file: {}", msg);
                    }
                }
                if let Err(msg) = file.write_all(&s.as_bytes()) {
                    error!("Error while writing secret to a file: {}", msg);
                }
                if let Err(msg) = file.sync_all() {
                    error!("Error while syncing file with a secret: {}", msg);
                }
            },
            Err(msg) => {
                error!("Error while creating secret's file: {}", msg)
            }
        }
    }
    Ok(ret)
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
        .alpns(lib::ALPNs.to_vec())
        .secret_key(sec)
        .bind()
        .await;
    ep
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let sec_ret = init_sec_key();
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
    ep.close().await;
    ()
}
