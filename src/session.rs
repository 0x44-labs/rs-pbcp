use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

pub struct Session {
    id: Ulid,
    challenge: Vec<u8>,
    start_step: u64,
    params: Params,
}

impl Session {
    pub fn new(challenge: Vec<u8>, params: Params) -> Self {
        let id = Ulid::generate();
        let start_step = params.time_step(None);

        Self {
            id,
            challenge,
            params,
            start_step,
        }
    }

    pub fn new_from(id: Ulid, challenge: Vec<u8>, params: Params) -> Self {
        let start_step = params.time_step(None);

        Self {
            id,
            challenge,
            params,
            start_step,
        }
    }

    pub fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }

    pub const fn start_step(&self) -> u64 {
        self.start_step
    }
}

#[derive(Clone)]
pub struct Params {
    /// PoW Constraint
    n: u8,

    /// Time Step Width
    x: u64,

    /// Time Step Count
    l: u64,

    /// Unix time from which to start counting time steps.
    t0: u64,
}

impl Params {
    pub const DEFAULT_T0: u64 = 0;

    pub fn new(n: u8, x: u64, l: u64, t0: Option<u64>) -> Params {
        Params {
            n,
            x,
            l,
            t0: t0.unwrap_or(Self::DEFAULT_T0),
        }
    }

    pub const fn n(&self) -> u8 {
        self.n
    }

    pub const fn x(&self) -> u64 {
        self.x
    }

    pub const fn l(&self) -> u64 {
        self.l
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
