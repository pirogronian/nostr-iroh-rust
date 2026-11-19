
use std::{path::{Path, PathBuf}, str::FromStr};
use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use log::{error};
use thiserror::Error;
use iroh::{SecretKey};
use iroh::endpoint::{Endpoint, BindError};
use std::env;
use directories::ProjectDirs;

use crate::{ALPNs};

pub fn sec_to_string(sec: &SecretKey) -> String {
    return hex::encode(sec.to_bytes());
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
            if let Err(e) = create_dir_all(dirs) {
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
/*
#[derive(Debug, Clone)]
struct PathError {
    path: PathBuf,
    error: std::io::Error
}

*/

pub struct Directories {
    system_config: PathBuf,
    user_config: PathBuf,
    state: PathBuf,
    runtime: PathBuf
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
/*
    pub fn create_all(&self) {
        create_dir_all(path)
    }*/
}
