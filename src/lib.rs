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
use crate::uri::{Session, Submission};

pub struct Tlph<T> {
    id: Ulid,
    tv: TraverseV,
    challenge: Vec<u8>,
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

    pub fn new(challenge: Vec<u8>, params: &Params) -> Self {
        let id = Ulid::generate();
        let start = params.time_step(None);

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
            start,
            _marker: PhantomData,
        }
    }

    pub fn new_from_uri(uri: &Uri) -> Result<Self, TlphError> {
        let session = Session::from_uri(uri)?;
        let id = session.id();
        let challenge = session.challenge();
        let params = session.params();

        let secret = Self::derive_secret(&id, &challenge, &params);
        let traversev_params = params.tv();
        let permissioned = TraverseV::new_permissioned(
            &secret,
            Self::CONTEXT,
            traversev_params,
        );

        Ok(Self {
            id,
            tv: permissioned,
            challenge,
            params,
            start: session.start(),
            _marker: PhantomData,
        })
    }

    pub fn session(&self) -> Result<Uri, TlphError> {
        let uri = Session::build_uri(
            self.id,
            &self.challenge,
            self.start,
            &self.params,
        )?;

        Ok(uri)
    }

    pub fn prove(&self, solution: &Solution<T>) -> Result<Uri, TlphError> {
        let input = solution.to_bytes()?;
        let proof = self.tv.mine(&input);

        let uri = Submission::build_uri(self.id, proof, solution)?;
        Ok(uri)
    }

    pub fn verify(&self, uri: &Uri) -> Result<bool, TlphError> {
        let current = self.params.time_step(None);
        self.verify_at(uri, current)
    }

    pub fn verify_at(&self, uri: &Uri, step: u64) -> Result<bool, TlphError> {
        let submission: Submission<T> = Submission::from_uri(uri)?;

        let max_step = self.start + self.params.l() - 1;
        let upper = step.min(max_step);
        let valid_range = self.start..=upper;

        if !valid_range.contains(&submission.solution().step()) {
            return Err(TlphError::OutOfRange);
        }

        let input = &submission.solution().to_bytes()?;
        Ok(self.tv.verify(&input, submission.proof()))
    }

    pub fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub fn params(&self) -> Params {
        self.params.clone()
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
