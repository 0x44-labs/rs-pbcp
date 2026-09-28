mod errors;
mod params;
mod proof;

use ulid::Ulid;

use crate::params::Params;
use crate::proof::{Grid, Proof, Solution};

pub struct Tlph {
    id: Ulid,
    challenge: Vec<u8>,
    start_step: u64,
    params: Params,
}

impl Tlph {
    pub fn new(challenge: Vec<u8>, params: &Params) -> Self {
        let id = Ulid::generate();
        let start_step = params.time_step(None);

        Self {
            id,
            challenge,
            params: *params,
            start_step,
        }
    }

    pub fn new_from(id: Ulid, challenge: Vec<u8>, params: &Params) -> Self {
        let start_step = params.time_step(None);

        Self {
            id,
            challenge,
            params: *params,
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

pub fn start_session(
    sid: Vec<u8>,
    n: u8,
    s: f64,
    x: u64,
    l: u64,
    cid: Vec<u8>,
) -> Session {
    let params = Params::new(n, s, x, l);
    let start_step = time_step(x);

    Session::new(sid, cid, params, start_step)
}

pub fn load_session(
    sid: Vec<u8>,
    n: u8,
    s: f64,
    x: u64,
    l: u64,
    cid: Vec<u8>,
    start_step: u64,
) -> Session {
    let params = Params::new(n, s, x, l);
    Session::new(sid, cid, params, start_step)
}

pub fn build_proof(session: &Session, answer: Grid) -> Proof {
    let step = time_step(session.params().x);

    let seed = derive_seed(&session.sid(), &answer, step);
    let nonce = mine(&seed, session.params().n);

    Proof::new(session.sid(), answer, nonce)
}

pub fn valid_step_range(session: &Session) -> Vec<u64> {
    let current = time_step(session.params().x);
    let max_step = session.start_step() + session.params().l - 1;
    let upper = current.min(max_step);
    (session.start_step()..=upper).collect()
}

pub fn verify_proof(session: &Session, proof: &Proof) -> bool {
    if proof.sid() != session.sid() {
        return false;
    }

    valid_step_range(session).into_iter().any(|step| {
        let seed = derive_seed(&session.sid(), &proof.answer(), step);
        verify(&seed, proof.nonce(), session.params().n)
    })
}
