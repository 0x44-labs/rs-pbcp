//! ## Example
//! ```
//! use tlph::{Params, Solution, Tlph, TvParams};
//!
//! fn main() {
//!     let nonce = b"This is a challenge nonce".to_vec();
//!     let tv = TvParams::new(12 * 1024, 3, 8, 12).unwrap();
//!     let params = Params::new(tv, 30, 6, None).unwrap();
//!
//!     // Construct a new verifier peer for a TLPH session
//!     let verifier = Tlph::new(nonce, &params);
//!
//!     // Create a challenge from the verifier peer
//!     let challenge = verifier.to_challenge();
//!
//!     // Build a solution with a payload and JWT-style claims
//!     let step = params.time_step(None);
//!     let payload = b"This is a payload".to_vec();
//!     let solution = Solution::builder(step, payload)
//!         .claim("iss", "https://humanity.example")
//!         .claim("sub", "Homo sapiens")
//!         .claim("aud", "https://humans-only.example")
//!         .claim("iat", "1786554930")
//!         .claim("exp", "1786561137")
//!         .build();
//!
//!     // Create a prover peer from the challenge
//!     let prover = Tlph::from_challenge(&challenge);
//!
//!     // Mine a proof of the solution
//!     let proof = prover.prove(&solution).unwrap();
//!
//!     // Check that the proof is valid for the verifier's session
//!     let result = verifier.verify(&proof, None);
//!     assert!(result.is_ok());
//! }
//! ```
mod errors;
mod model;
mod params;

use blake3::Hasher;
use traversev::TraverseV;
use ulid::Ulid;

pub use crate::errors::TlphError;
pub use crate::model::{Challenge, Counter, Proof, Solution};
pub use crate::params::{Params, TvParams};

/// Time-limited Proof of Humanity (TLPH) instance.
///
/// Construction derives a secret from the session identifier, nonce and
/// parameters, and uses it to build a permissioned [TraverseV] instance. A
/// session is shared as a [Challenge], from which any party can reconstruct
/// an equivalent instance.
///
/// Proving mines a [Proof] of a [Solution] bound to a time step. Verification
/// checks that the proof belongs to this session, that the time step of its
/// solution lies within the session's valid range, and that its nonce
/// satisfies the difficulty. The valid range spans a limited number of time
/// steps from the starting time step.
pub struct Tlph {
    id: Ulid,
    start: u64,
    nonce: Vec<u8>,
    tv: TraverseV,
    params: Params,
}

impl Tlph {
    const CONTEXT: &str = "TIME_LIMITED_PROOF_OF_HUMANITY";

    /// Create a new [Tlph] instance with a fresh session identifier, the
    /// current time step as its start, and the given nonce and parameters.
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

    /// Create a [Challenge] from the session of this [Tlph] instance.
    pub fn to_challenge(&self) -> Challenge {
        Challenge::new(self.id, self.start, &self.nonce, self.params)
    }

    /// Create a [Tlph] instance from the given [Challenge].
    pub fn from_challenge(challenge: &Challenge) -> Self {
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

        Self {
            id,
            start: challenge.start(),
            nonce,
            tv: permissioned,
            params,
        }
    }

    /// Mine a [Proof] of the given [Solution] for this session.
    pub fn prove(&self, solution: &Solution) -> Result<Proof, TlphError> {
        let input = solution.to_bytes()?;
        let nonce: u128 = self.tv.mine(&input, Counter::default(), 1);

        let proof = Proof::new(self.id, solution, nonce);
        Ok(proof)
    }

    /// Verify the given [Proof] against this session, returning whether its
    /// nonce is valid for its solution.
    ///
    /// The time step of the solution must lie between the start time step and
    /// the earlier of `step` (defaulting to the current time step) and the
    /// last step permitted by the parameters.
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

    /// Returns the session identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns a clone of the challenge nonce.
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    /// Returns the starting time step.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Return the parameters.
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

impl core::fmt::Debug for Tlph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tlph")
            .field("id", &self.id)
            .field("start", &self.start)
            .field("tv", &self.tv)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}
