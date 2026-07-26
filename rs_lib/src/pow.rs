use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

fn mine(seed: &[u8], constraint: usize) -> u128 {
    let mut nonce = 0u128;

    loop {
        let mut mac = Hmac::<Sha256>::new_from_slice(&seed)
            .expect("HMAC can take key of any size");
        mac.update(&nonce.to_le_bytes());
        let mut digest: [u8; 32] = mac.finalize().into_bytes().into();

        let bytes = constraint / 8;
        let bits = constraint % 8;

        // Verify first N bytes are zero, following N bits are zero
        let mut satisfied = Choice::from(1u8);
        for i in 0..bytes {
            satisfied &= digest[i].ct_eq(&0u8);
        }
        if bits > 0 {
            let mask = (0xFF << (8 - bits)) as u8;
            satisfied &= (digest[bytes] & mask).ct_eq(&0u8);
        }

        // Break the mining loop when the constraint is satisfied
        if bool::from(satisfied) {
            digest.zeroize();
            return nonce;
        }

        nonce += 1
    }
}
