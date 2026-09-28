mod errors;
mod params;
mod proof;
mod solution;

use blake3::Hasher;
use num_traits::{FromBytes, ToBytes};
use std::marker::PhantomData;
use traversev::TraverseV;
use ulid::Ulid;

use crate::errors::TlphError;
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

    pub fn prove(&self, grid: Grid<T>) -> Proof<T> {
        let step = self.params.time_step(None);

        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(&step.to_le_bytes());

        let grid_bytes = Vec::<u8>::from(grid.clone());
        input.extend_from_slice(&grid_bytes);

        let proof = self.tv.mine(&input);
        Proof::new(proof, step, grid)
    }

    pub fn verify(&self, proof: Proof<T>) -> Result<bool, TlphError> {
        let current = self.params.time_step(None);
        self.verify_at(proof, current)
    }

    pub fn verify_at(
        &self,
        proof: Proof<T>,
        step: u64,
    ) -> Result<bool, TlphError> {
        let max_step = self.start_step + self.params.l() - 1;
        let upper = step.min(max_step);
        let valid_range = self.start_step..=upper;

        if !valid_range.contains(&proof.step()) {
            return Err(TlphError::OutOfRange);
        }

        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(&proof.step().to_le_bytes());

        let grid_bytes = Vec::<u8>::from(proof.grid());
        input.extend_from_slice(&grid_bytes);

        Ok(self.tv.verify(&input, proof.proof()))
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
