mod errors;
mod params;
mod solution;

use blake3::Hasher;
use num_traits::{FromBytes, ToBytes};
use std::marker::PhantomData;
use traversev::TraverseV;
use ulid::Ulid;

pub use crate::errors::TlphError;
pub use crate::params::Params;
pub use crate::solution::{Grid, Solution};

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

        let secret = Self::derive_secret(&id, &challenge, params);
        let traversev_params = params.tv();
        let permissioned = TraverseV::new_permissioned(
            &secret,
            Self::CONTEXT,
            traversev_params,
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

    /*
    pub fn new_from(id: Ulid, challenge: Vec<u8>, params: &Params) -> Self {
        let start_step = params.time_step(None);

        let secret = Self::derive_secret(&id, &challenge, params);
        let traversev_params = params.tv();
        let permissioned = TraverseV::new_permissioned(
            &secret,
            Self::CONTEXT,
            traversev_params,
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
    */

    pub fn prove(&self, solution: &Solution<T>) -> Result<u128, TlphError> {
        let input = solution.to_bytes()?;
        Ok(self.tv.mine(&input))
    }

    pub fn verify(
        &self,
        solution: &Solution<T>,
        proof: u128,
    ) -> Result<bool, TlphError> {
        let current = self.params.time_step(None);
        self.verify_at(solution, proof, current)
    }

    pub fn verify_at(
        &self,
        solution: &Solution<T>,
        proof: u128,
        step: u64,
    ) -> Result<bool, TlphError> {
        let max_step = self.start_step + self.params.l() - 1;
        let upper = step.min(max_step);
        let valid_range = self.start_step..=upper;

        if !valid_range.contains(&solution.step()) {
            return Err(TlphError::OutOfRange);
        }

        let input = solution.to_bytes()?;
        Ok(self.tv.verify(&input, proof))
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

    fn derive_secret(
        id: &Ulid,
        challenge: &Vec<u8>,
        params: &Params,
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();

        hasher.update(&id.to_bytes());
        hasher.update(&params.x().to_le_bytes());
        hasher.update(&params.l().to_le_bytes());
        hasher.update(&params.t0().to_le_bytes());
        hasher.update(&challenge);

        hasher.finalize().into()
    }
}
