use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::TlphError;

/// Time-limited Proof-of-Humanity (TLPH) parameters.
#[derive(Copy, Clone)]
pub struct Params {
    n: u64,
    x: u64,
    l: u64,
    t0: u64,
}

impl Params {
    /// Default proof-of-work difficulty `n`.
    pub const DEFAULT_N: u64 = 20;

    const MIN_N: u64 = 1;

    const MAX_N: u64 = u8::MAX as u64;

    /// Default time step width in seconds `x`.
    pub const DEFAULT_X: u64 = 30;

    const MIN_X: u64 = 1;

    const MAX_X: u64 = u16::MAX as u64;

    /// Default time step count `l`.
    pub const DEFAULT_L: u64 = 6;

    const MIN_L: u64 = 1;

    const MAX_L: u64 = u16::MAX as u64;

    /// Default unix time `t0` from which to start counting time steps.
    pub const DEFAULT_T0: u64 = 0;

    /// Default parameters.
    pub const DEFAULT: Self = Params {
        n: Self::DEFAULT_N,
        x: Self::DEFAULT_X,
        l: Self::DEFAULT_L,
        t0: Self::DEFAULT_T0,
    };

    /// Create new parameters for TLPH.
    ///
    /// Returns the constructed `Params` on success, or an error when any value
    /// falls outside its accepted range.
    ///
    /// # Arguments
    /// - `n`: proof-of-work difficulty as a number of leading zero bits.
    ///   Between 1 and (2^8) - 1.
    /// - `x`: time step width in seconds. Between 1 and (2^16) - 1.
    /// - `l`: time step count. Between 1 and (2^16) - 1.
    /// - `t0`: optional unix time from which to start counting time steps.
    pub fn new(
        n: u64,
        x: u64,
        l: u64,
        t0: Option<u64>,
    ) -> Result<Self, TlphError> {
        if n < Self::MIN_N {
            return Err(TlphError::DifficultyTooLow);
        }
        if n > Self::MAX_N {
            return Err(TlphError::DifficultyTooHigh);
        }
        if x < Self::MIN_X {
            return Err(TlphError::StepTooSmall);
        }
        if x < Self::MAX_X {
            return Err(TlphError::StepTooBig);
        }
        if l < Self::MIN_L {
            return Err(TlphError::StepsTooFew);
        }
        if l > Self::MAX_L {
            return Err(TlphError::StepsTooMany);
        }

        Ok(Params {
            n,
            x,
            l,
            t0: t0.unwrap_or(Self::DEFAULT_T0),
        })
    }

    /// Proof-of-work difficulty.
    pub const fn n(&self) -> u64 {
        self.n
    }

    /// Time step width in seconds.
    pub const fn x(&self) -> u64 {
        self.x
    }

    /// Time step count.
    pub const fn l(&self) -> u64 {
        self.l
    }

    /// Unix time from which to start counting time steps.
    pub const fn t0(&self) -> u64 {
        self.t0
    }

    /// Returns the time step for a specified or the current time.
    pub fn time_step(&self, time: Option<u64>) -> u64 {
        let unix_time = time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before Unix epoch")
                .as_secs()
        });

        (unix_time - self.t0) / self.x
    }
}

impl Default for Params {
    fn default() -> Self {
        Params::DEFAULT
    }
}
