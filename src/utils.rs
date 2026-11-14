
use iroh::{SecretKey};

pub fn sec_to_string(sec: &SecretKey) -> String {
    return hex::encode(sec.to_bytes());
}
