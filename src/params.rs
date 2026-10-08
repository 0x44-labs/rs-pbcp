use std::time::{SystemTime, UNIX_EPOCH};
use traversev;

use crate::errors::TlphError;

/// Alias for TraverseV proof-of-work parameters.
pub type TvParams = traversev::Params;

/// Time-limited Proof-of-Humanity (TLPH) parameters.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Params {
    tv: TvParams,
    x: u64,
    l: u64,
    t0: u64,
}

impl Params {
    /// Default TraverseV parameters.
    pub const DEFAULT_TV: TvParams = TvParams::DEFAULT;

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
        tv: Self::DEFAULT_TV,
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
    /// - `tv`: TraverseV [parameters](traversev::Params).
    /// - `x`: time step width in seconds. Between 1 and (2^16) - 1.
    /// - `l`: time step count. Between 1 and (2^16) - 1.
    /// - `t0`: optional unix time from which to start counting time steps.
    pub fn new(
        tv: TvParams,
        x: u64,
        l: u64,
        t0: Option<u64>,
    ) -> Result<Self, TlphError> {
        if x < Self::MIN_X {
            return Err(TlphError::StepTooSmall);
        }
        if x > Self::MAX_X {
            return Err(TlphError::StepTooBig);
        }
        if l < Self::MIN_L {
            return Err(TlphError::StepsTooFew);
        }
        if l > Self::MAX_L {
            return Err(TlphError::StepsTooMany);
        }

        Ok(Params {
            tv,
            x,
            l,
            t0: t0.unwrap_or(Self::DEFAULT_T0),
        })
    }

    /// TraverseV parameters.
    pub const fn tv(&self) -> TvParams {
        self.tv
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
