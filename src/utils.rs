
use env_logger;
use log::{debug, info, warn, error};
use core::fmt;
use std::{path::{Path, PathBuf, Component}, str::FromStr};
use std::fs::{File};
use std::io::{Read, Write};
use std::clone::Clone;
use thiserror::Error;
use iroh::{SecretKey, PublicKey, EndpointId};
use iroh::endpoint::{Endpoint, BindError};
use std::env;
use std::sync::Arc;
use directories::ProjectDirs;
use tokio_rustls::{client::TlsConnector, rustls::crypto::CryptoProvider};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{ALPNs};

pub fn sec_to_string(sec: &SecretKey) -> String {
    return hex::encode(sec.to_bytes());
}

pub fn pub_to_string(id: &EndpointId) -> String {
    return hex::encode(id.as_bytes());
}

#[derive(Error, Debug)]
pub enum LoadSecretKeyError {
    #[error("Parsing secret error: {0}")]
    KeyParsingError(#[from] iroh::KeyParsingError),
    #[error("IO error while reading secret's file: {0}")]
    IoError(#[from] std::io::Error)
}

pub fn load_or_create_sec(path: &Path, break_on_error: bool) -> Result<SecretKey, LoadSecretKeyError> {
    let mut sec = SecretKey::generate();
    if path.exists() {
        match File::open(&path) {
            Err(e) => {
                error!("Error while opening secret key file {}: {}", path.display(), e);
                if break_on_error { return Err(LoadSecretKeyError::IoError(e)) }
            }
            Ok(mut file) => {
                let mut s = String::new();
                match file.read_to_string(&mut s) {
                    Err(e) => {
                        error!("Error while reading secret key from {}: {}", path.display(), e);
                        if break_on_error { return Err(LoadSecretKeyError::IoError(e)) }
                    }
                    Ok (_) => {
                        match SecretKey::from_str(&s) {
                            Err(e) => {
                                error!("Error while parsing secret key: {}", e);
                                if break_on_error { return Err(LoadSecretKeyError::KeyParsingError(e)) }
                            }
                            Ok(v) => { sec = v }
                        }
                    }
                }
            }
        }
    } else {
        let dirs_o = path.parent();
        if let Some(dirs) = dirs_o && !dirs.is_empty() {
            if let Err(e) = std::fs::create_dir_all(dirs) {
                error!("Error while creating path to secret key file {}: {}", dirs.display(), e);
                if break_on_error { return Err(LoadSecretKeyError::IoError(e)) }
                return Ok(sec)
            }
        }
        match File::create(path) {
            Err(e) => {
                error!("Error while creating secret key file {}: {}", path.display(), e);
                if break_on_error { return Err(LoadSecretKeyError::IoError(e)) }
            }
            Ok(mut file) => {
                let s = sec_to_string(&sec);
                if let Err(e) = file.write_all(&s.as_bytes()) {
                    error!("Error while writing secret key to file {}: {}", path.display(), e);

                }
            }
        }
    }
    return Ok(sec)
}

pub async fn create_endpoint(sec: SecretKey) -> Result<Endpoint, BindError> {
    return iroh::endpoint::Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(ALPNs.to_vec())
        .secret_key(sec).bind().await;
}

#[derive(Debug, PartialEq)]
pub enum EnvironmentType {
    Manual,
    SystemService,
    UserService,
}

pub fn detect_environment() -> EnvironmentType {
    if env::var("INVOCATION_ID").is_err() {
        return EnvironmentType::Manual;
    }

    if env::var("XDG_RUNTIME_DIR").is_ok() {
        EnvironmentType::UserService
    } else {
        EnvironmentType::SystemService
    }
}

#[derive(Debug)]
pub struct PathError {
    path: PathBuf,
    error: std::io::Error
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error on path \"{}\": {}", self.path.display(), self.error)
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub fn create_dir_all(path: &Path) -> Result<(), PathError> {
    let ret = std::fs::create_dir_all(path);
    if let Err(err) = ret {
        return Err(PathError { path: path.to_path_buf(), error: err })
    }
    Ok(())
}

pub struct Directories {
    pub system_config: PathBuf,
    pub user_config: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf
}

impl Directories {
    pub fn new(qualifier: &str, organization: &str, app: &str) -> Directories {
        let systemd_config_var = "CONFIGURATION_DIRECTORY";
        let systemd_state_var = "STATE_DIRECTORY";
        let systemd_runtime_var = "RUNTIME_DIRECTORY";
        let exec_env = detect_environment();

        let mut system_config = Path::new("/etc/").join(app);
        if exec_env == EnvironmentType::UserService ||
            exec_env == EnvironmentType::SystemService {
            if let Ok(dir) = env::var(systemd_config_var) {
                system_config = PathBuf::from(dir);
            }
        }

        let proj_dir_o = ProjectDirs::from(qualifier, organization, app);
        let user_config = match &proj_dir_o {
            Some(proj_dir) => {
                proj_dir.config_dir().to_path_buf()
            }
            None => PathBuf::new()
        };
        //println!("User config dir: {}", user_config.display());

        let state_dir: PathBuf = match exec_env {
            EnvironmentType::Manual | EnvironmentType::UserService => {
                if let Ok(dir) = env::var(systemd_state_var) {
                    PathBuf::from(dir)
                } else {
                    match &proj_dir_o {
                        Some(proj_dir) => {
                            match proj_dir.state_dir() {
                                Some(state_dir) => state_dir.to_path_buf(),
                                None => proj_dir.data_dir().to_path_buf()
                            }
                        }
                        None => PathBuf::new()
                    }
                }
            }
            EnvironmentType::SystemService => {
                if let Ok(dir) = env::var(systemd_state_var) {
                    PathBuf::from(dir)
                } else { Path::new("/var/lib/").join(app) }
            }
        };

        let fallback_runtime_dir = env::temp_dir().join(app);
        let runtime_dir: PathBuf = match exec_env {
            EnvironmentType::Manual | EnvironmentType::UserService => {
                if let Ok(dir) = env::var(systemd_runtime_var) {
                    PathBuf::from(dir)
                } else {
                    match &proj_dir_o {
                        Some(proj_dir) => {
                            match proj_dir.runtime_dir() {
                                Some(runtime_dir) => runtime_dir.to_path_buf(),
                                None => fallback_runtime_dir
                            }
                        }
                        None => fallback_runtime_dir
                    }
                }
            }
            EnvironmentType::SystemService => {
                if let Ok(dir) = env::var(systemd_runtime_var) {
                    PathBuf::from(dir)
                } else { fallback_runtime_dir }
            }
        };

        Self { system_config: system_config,
            user_config: user_config,
            state: state_dir,
            runtime: runtime_dir }
    }

    pub fn create_all(&self) -> Result<(), PathError> {
        create_dir_all(&self.user_config)?;
        create_dir_all(&self.state)?;
        create_dir_all(&self.runtime)?;
        Ok(())
    }
}

pub fn starts_with_existing_dir(path: &Path) -> bool {
    match path.components().next() {
        Some(Component::Normal(first)) => Path::new(first).is_dir(),
        Some(Component::RootDir) => Path::new("/").is_dir(),
        _ => false,
    }
}

pub fn publish(ep_id: &PublicKey, dirs: &Directories, name: &str) -> Result<(), std::io::Error> {
    let path = dirs.state.clone().join(name);
    let mut file = File::create(&path)?;
    file.write_all(pub_to_string(ep_id).as_bytes())?;
    Ok(())
}

pub fn create_tls_connector() -> tokio_rustls::client::TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}
