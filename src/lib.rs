mod errors;
mod nonce;
mod params;
mod solution;
mod uri;

use blake3::Hasher;
use http::Uri;
use traversev::TraverseV;
use ulid::Ulid;

pub use crate::errors::TlphError;
pub use crate::nonce::Nonce;
pub use crate::params::{Params, TvParams};
pub use crate::solution::Solution;
use crate::uri::{Challenge, Proof};

pub struct Tlph {
    id: Ulid,
    start: u64,
    nonce: Vec<u8>,
    tv: TraverseV,
    params: Params,
}

impl Tlph {
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
            start,
            nonce,
            tv: permissioned,
            params: *params,
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
            start: challenge.start(),
            nonce,
            tv: permissioned,
            params,
        })
    }

    pub fn challenge(&self) -> Result<Uri, TlphError> {
        let challenge = Challenge::build_uri(
            self.id,
            self.start,
            &self.nonce,
            &self.params,
        )?;

        Ok(challenge)
    }

    pub fn prove(&self, solution: &Solution) -> Result<Uri, TlphError> {
        let input = solution.to_bytes()?;
        let nonce: Nonce = self.tv.mine(&input, Nonce::default(), 1);

        let proof = Proof::build_uri(self.id, solution, nonce)?;
        Ok(proof)
    }

    pub fn verify(&self, uri: &Uri) -> Result<bool, TlphError> {
        let current = self.params.time_step(None);
        self.verify_at(uri, current)
    }

    pub fn verify_at(&self, uri: &Uri, step: u64) -> Result<bool, TlphError> {
        let proof = Proof::from_uri(uri)?;
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
