
use std::{path::Path, str::FromStr};
use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use log::{error};
use thiserror::Error;
use iroh::{SecretKey};
use iroh::endpoint::{Endpoint, BindError};

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
