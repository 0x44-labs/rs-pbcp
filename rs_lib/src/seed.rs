use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const T0: u64 = 0;

pub fn derive_seed(sid: &[u8], answer: Vec<Vec<u8>>, x: u64) -> [u8; 32] {
    let step = time_step(x);

    let mut hasher = Sha256::new();
    hasher.update(sid);
    hasher.update(&answer.concat());
    hasher.update(&step.to_le_bytes());

    hasher.finalize().into()
}

pub fn time_step(x: u64) -> u64 {
    let current_unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs();

    (current_unix_time - T0) / x
}
