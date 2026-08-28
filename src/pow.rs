use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::session::{Grid, time_step};

pub fn mine(session_id: &[u8], solution: &Grid, x: u64, n: u8) -> u128 {
    let mut nonce = 0u128;

    let step = time_step(x);
    let seed = derive_seed(session_id, solution, step);

    loop {
        let candidate = authenticate(&seed, nonce);
        let satisfied = check(&candidate, n);

        // Break loop when the constraint is satisfied
        if bool::from(satisfied) {
            return nonce;
        }

        nonce += 1
    }
}

/*
pub fn verify(seed: &[u8; 32], nonce: u128, n: u8) -> bool {
    let candidate = authenticate(seed, nonce);
    let satisfied = check(&candidate, n);

    bool::from(satisfied)
}
*/

fn derive_seed(session_id: &[u8], solution: &Grid, step: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(solution.data());
    hasher.update(&step.to_le_bytes());

    hasher.finalize().into()
}

fn authenticate(seed: &[u8; 32], nonce: u128) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed)
        .expect("HMAC can take key of any size");
    mac.update(&nonce.to_le_bytes());

    mac.finalize().into_bytes().into()
}

fn check(candidate: &[u8; 32], n: u8) -> Choice {
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
