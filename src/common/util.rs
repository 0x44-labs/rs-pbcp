use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("")
        .as_secs()
}

pub(crate) fn derive_secret(id: &Ulid, nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();

    hasher.update(&id.to_bytes());
    hasher.update(nonce);

    let mut hash = hasher.finalize();
    let secret: [u8; 32] = hash.into();

    #[cfg(feature = "zeroize")]
    {
        hasher.zeroize();
        hash.zeroize();
    }

    secret
}
