mod errors;
mod params;
mod solution;
mod uri;

use blake3::Hasher;
use http::Uri;
use num_traits::{FromBytes, ToBytes};
use std::marker::PhantomData;
use traversev::TraverseV;
use ulid::Ulid;

pub use crate::errors::TlphError;
pub use crate::params::Params;
pub use crate::solution::{Grid, Solution};
use crate::uri::{Challenge, Proof};

pub struct Tlph<T> {
    id: Ulid,
    tv: TraverseV,
    nonce: Vec<u8>,
    start: u64,
    params: Params,
    _marker: PhantomData<T>,
}

impl<T> Tlph<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    const CONTEXT: &str = "TIME_LIMITED_PROOF_OF_HUMANITY";

    pub fn new(nonce: Vec<u8>, params: &Params) -> Self {
        let id = Ulid::generate();
        let start = params.time_step(None);

        let secret = Self::derive_secret(&id, &nonce, params);
        let traversev_params = params.tv();
        let permissioned = TraverseV::new_permissioned(
            &secret,
            Self::CONTEXT,
            traversev_params,
        );

        Self {
            id,
            tv: permissioned,
            nonce,
            params: *params,
            start,
            _marker: PhantomData,
        }
    }

    pub fn new_from_uri(uri: &Uri) -> Result<Self, TlphError> {
        let challenge = Challenge::from_uri(uri)?;
        let id = challenge.id();
        let nonce = challenge.nonce();
        let params = challenge.params();

        let secret = Self::derive_secret(&id, &nonce, &params);
        let traversev_params = params.tv();
        let permissioned = TraverseV::new_permissioned(
            &secret,
            Self::CONTEXT,
            traversev_params,
        );

        Ok(Self {
            id,
            tv: permissioned,
            nonce,
            params,
            start: challenge.start(),
            _marker: PhantomData,
        })
    }

    pub fn session(&self) -> Result<Uri, TlphError> {
        let challenge = Challenge::build_uri(
            self.id,
            &self.nonce,
            self.start,
            &self.params,
        )?;

        Ok(challenge)
    }

    pub fn prove(&self, solution: &Solution<T>) -> Result<Uri, TlphError> {
        let input = solution.to_bytes()?;
        let nonce = self.tv.mine(&input);

        let proof = Proof::build_uri(self.id, nonce, solution)?;
        Ok(proof)
    }

    pub fn verify(&self, uri: &Uri) -> Result<bool, TlphError> {
        let current = self.params.time_step(None);
        self.verify_at(uri, current)
    }

    pub fn verify_at(&self, uri: &Uri, step: u64) -> Result<bool, TlphError> {
        let proof: Proof<T> = Proof::from_uri(uri)?;
        if proof.id() != self.id {
            return Err(TlphError::WrongSession);
        }

        let max_step = self.start + self.params.l() - 1;
        let upper = step.min(max_step);
        let valid_range = self.start..=upper;

        if !valid_range.contains(&proof.solution().step()) {
            return Err(TlphError::OutOfRange);
        }

        let input = &proof.solution().to_bytes()?;
        Ok(self.tv.verify(&input, proof.nonce()))
    }

    pub fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub fn params(&self) -> Params {
        self.params.clone()
    }

    fn derive_secret(id: &Ulid, nonce: &Vec<u8>, params: &Params) -> [u8; 32] {
        let mut hasher = Hasher::new();

        hasher.update(&id.to_bytes());
        hasher.update(&params.x().to_le_bytes());
        hasher.update(&params.l().to_le_bytes());
        hasher.update(&params.t0().to_le_bytes());
        hasher.update(&nonce);

        hasher.finalize().into()
    }
}
