use std::time::{SystemTime, UNIX_EPOCH};

pub struct Nonce(u128);

impl Nonce {
    pub fn new(counter: u64) -> Self {
        let time = Self::now();

        Self(Self::pack(time, counter))
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("")
            .as_secs()
    }

    fn pack(time: u64, counter: u64) -> u128 {
        (time as u128) << 64 | (counter as u128)
    }

    fn unpack(&self) -> (u64, u64) {
        let time = (self.0 >> 64) as u64;
        let counter = self.0 as u64;

        (time, counter)
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Self::new(0u64)
    }
}
