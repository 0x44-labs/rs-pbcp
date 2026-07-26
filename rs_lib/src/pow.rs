use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn pow_mine(seed: &[u8], n: u8) -> u128 {
    let mut nonce = 0u128;

    loop {
        let candidate = nonce_hmac(seed, nonce);
        let satisfied = check_candidate(&candidate, n);

        // Break the mining loop when the constraint is satisfied
        if bool::from(satisfied) {
            return nonce;
        }

        nonce += 1
    }
}

#[wasm_bindgen]
pub fn pow_verify(seed: &[u8], nonce: u128, n: u8) -> bool {
    let candidate = nonce_hmac(seed, nonce);
    let satisfied = check_candidate(&candidate, n);

    bool::from(satisfied)
}

fn nonce_hmac(seed: &[u8], nonce: u128) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(&seed)
        .expect("HMAC can take key of any size");
    mac.update(&nonce.to_le_bytes());

    mac.finalize().into_bytes().into()
}

fn check_candidate(candidate: &[u8; 32], n: u8) -> Choice {
    let bytes = n / 8;
    let bits = n % 8;

    // Verify first N bytes are zero, following N bits are zero
    let mut satisfied = Choice::from(1u8);
    for i in 0..bytes {
        satisfied &= candidate[i as usize].ct_eq(&0u8);
    }
    if bits > 0 {
        let mask = (0xFF << (8 - bits)) as u8;
        satisfied &= (candidate[bytes as usize] & mask).ct_eq(&0u8);
    }

    satisfied
}
