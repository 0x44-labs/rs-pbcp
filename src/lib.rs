mod errors;
mod model;
mod params;

use blake3::Hasher;
use traversev::TraverseV;
use ulid::Ulid;

pub use crate::errors::TlphError;
pub use crate::model::{Challenge, Counter, Proof, Solution};
pub use crate::params::{Params, TvParams};

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

    pub fn to_challenge(&self) -> Challenge {
        Challenge::new(self.id, self.start, &self.nonce, self.params)
    }

    pub fn from_challenge(challenge: &Challenge) -> Result<Self, TlphError> {
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

    pub fn prove(&self, solution: &Solution) -> Result<Proof, TlphError> {
        let input = solution.to_bytes()?;
        let nonce: u128 = self.tv.mine(&input, Counter::default(), 1);

        let proof = Proof::new(self.id, solution, nonce);
        Ok(proof)
    }

    pub fn verify(
        &self,
        proof: &Proof,
        step: Option<u64>,
    ) -> Result<bool, TlphError> {
        if proof.id() != self.id {
            return Err(TlphError::WrongSession);
        }

        let current = step.unwrap_or(self.params.time_step(None));
        let max_step = self.start + self.params.l() - 1;
        let upper = current.min(max_step);
        let valid_range = self.start..=upper;

        if !valid_range.contains(&proof.solution().step()) {
            return Err(TlphError::OutOfRange);
        }

        let input = &proof.solution().to_bytes()?;
        Ok(self.tv.verify(&input, proof.nonce()))
    }

    pub const fn id(&self) -> Ulid {
        self.id
    }

    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn params(&self) -> Params {
        self.params
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
