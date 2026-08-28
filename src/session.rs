use std::time::{SystemTime, UNIX_EPOCH};

const T0: u64 = 0;

pub struct Session {
    session_id: Vec<u8>,
    challenge_id: Vec<u8>,
    params: Params,
    start_step: u64,
}

impl Session {
    pub fn new(
        session_id: Vec<u8>,
        challenge_id: Vec<u8>,
        params: Params,
        start_step: u64,
    ) -> Session {
        Session {
            session_id,
            challenge_id,
            params,
            start_step,
        }
    }

    pub fn session_id(&self) -> Vec<u8> {
        self.session_id.clone()
    }

    pub fn challenge_id(&self) -> Vec<u8> {
        self.challenge_id.clone()
    }

    pub fn params(&self) -> Params {
        self.params.clone()
    }

    pub fn start_step(&self) -> u64 {
        self.start_step
    }
}

#[derive(Clone)]
pub struct Params {
    /// PoW Constraint
    pub n: u8,
    /// Similarity Threshold
    pub s: f64,
    /// Time Step Width
    pub x: u64,
    /// Time Step Count
    pub l: u64,
}

impl Params {
    pub fn new(n: u8, s: f64, x: u64, l: u64) -> Params {
        Params { n, s, x, l }
    }
}

pub fn time_step(x: u64) -> u64 {
    let current_unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs();

    (current_unix_time - T0) / x
}
