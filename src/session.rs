use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

const T0: u64 = 0;

pub struct Session {
    session_id: Ulid,
    challenge_id: Vec<u8>,
    start_step: u64,
    params: Params,
}

impl Session {
    pub fn new(challenge_id: Vec<u8>, params: Params) -> Session {
        let session_id = Ulid::generate();
        let start_step = time_step(params.x);

        Session {
            session_id,
            challenge_id,
            params,
            start_step,
        }
    }

    /*
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
    */
}

#[derive(Clone)]
pub struct Params {
    /// PoW Constraint
    n: u8,

    /// Time Step Width
    x: u64,

    /// Time Step Count
    l: u64,
}

impl Params {
    pub fn new(n: u8, x: u64, l: u64) -> Params {
        Params { n, x, l }
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
}

pub fn time_step(x: u64) -> u64 {
    let current_unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs();

    (current_unix_time - T0) / x
}
