use num_traits::ToBytes;
use std::{
    ops::AddAssign,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy)]
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

impl core::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (time, counter) = self.unpack();

        f.debug_struct("Nonce")
            .field("time", &time)
            .field("counter", &counter)
            .finish()
    }
}

impl ToBytes for Nonce {
    type Bytes = [u8; 16];

    fn to_be_bytes(&self) -> Self::Bytes {
        self.0.to_be_bytes()
    }

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn to_ne_bytes(&self) -> Self::Bytes {
        self.0.to_ne_bytes()
    }
}

impl AddAssign<u64> for Nonce {
    /// Performs the `+=` operation on the counter. If the addition would
    /// overflow, the counter restarts at zero under a fresh timestamp instead
    /// of wrapping.
    fn add_assign(&mut self, rhs: u64) {
        let (time, mut counter) = self.unpack();

        if counter <= u64::MAX - rhs {
            counter += rhs;
            self.0 = Self::pack(time, counter);
        } else {
            let time = Self::now();
            let counter = 0u64;
            self.0 = Self::pack(time, counter);
        }
    }
}

impl From<u128> for Nonce {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<Nonce> for u128 {
    fn from(value: Nonce) -> Self {
        value.0
    }
}
