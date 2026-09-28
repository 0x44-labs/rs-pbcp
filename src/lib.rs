mod errors;
mod params;
mod proof;

use num_traits::{FromBytes, ToBytes};
use std::marker::PhantomData;
use traversev::TraverseV;
use ulid::Ulid;

use crate::params::Params;
use crate::proof::{Grid, Proof};

pub struct Tlph<T> {
    id: Ulid,
    tv: TraverseV,
    challenge: Vec<u8>,
    start_step: u64,
    params: Params,
    _marker: PhantomData<T>,
}

impl<T> Tlph<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    const CONTEXT: &str = "TIME_LIMITED_PROOF_OF_HUMANITY";

    pub fn new(challenge: Vec<u8>, params: &Params) -> Self {
        let id = Ulid::generate();
        let start_step = params.time_step(None);

        let permissioned = TraverseV::new_permissioned(
            &id.to_bytes(),
            Self::CONTEXT,
            params.tv(),
        );

        Self {
            id,
            tv: permissioned,
            challenge,
            params: *params,
            start_step,
            _marker: PhantomData,
        }
    }

    pub fn new_from(id: Ulid, challenge: Vec<u8>, params: &Params) -> Self {
        let start_step = params.time_step(None);

        let permissioned = TraverseV::new_permissioned(
            &id.to_bytes(),
            Self::CONTEXT,
            params.tv(),
        );

        Self {
            id,
            tv: permissioned,
            challenge,
            params: *params,
            start_step,
            _marker: PhantomData,
        }
    }

    pub fn prove(&self, grid: Grid<T>) -> Proof<T> {
        let step = self.params.time_step(None);

        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(&step.to_le_bytes());

        let grid_bytes = Vec::<u8>::from(grid.clone());
        input.extend_from_slice(&grid_bytes);

        let proof = self.tv.mine(&input);
        Proof::new(proof, step, grid)
    }

    pub fn verify(&self, proof: Proof<T>) -> bool {
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(&proof.step().to_le_bytes());

        let grid_bytes = Vec::<u8>::from(proof.grid());
        input.extend_from_slice(&grid_bytes);

        self.tv.verify(&input, proof.proof())
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
