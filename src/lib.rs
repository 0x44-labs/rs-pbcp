mod errors;
mod pow;
mod seed;
mod session;

use crate::pow::{pow_mine, pow_verify};
use crate::seed::{derive_seed, time_step};
use crate::session::{Grid, Params, Proof, Session};

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
    let nonce = pow_mine(&seed, session.params().n);

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
        pow_verify(&seed, proof.nonce(), session.params().n)
    })
}
