use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use wasm_bindgen::prelude::*;

use crate::session::Grid;

const T0: u64 = 0;

#[wasm_bindgen]
pub fn derive_seed(sid: &[u8], answer: &Grid, step: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(sid);
    hasher.update(answer.data());
    hasher.update(&step.to_le_bytes());

    hasher.finalize().to_vec()
}

#[wasm_bindgen]
pub fn time_step(x: u64) -> u64 {
    let current_unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs();

    (current_unix_time - T0) / x
}
