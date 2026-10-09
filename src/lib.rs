#![cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
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
//!
//! ## Features
//!
//! The `zeroize` feature (disabled by default) implements `Zeroize` and
//! `ZeroizeOnDrop` for `Solution`, `SolutionBuilder`, and `Proof`, and
//! zeroises intermediate values on a best-effort basis.
mod errors;
mod model;
mod params;

use blake3::Hasher;
use traversev::TraverseV;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub use crate::errors::TlphError;
pub use crate::model::{Challenge, Counter, Proof, Solution, SolutionBuilder};
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
#[derive(Debug)]
pub struct Tlph {
    id: Ulid,
    start: u64,
    nonce: Vec<u8>,
    tv: TraverseV,
    params: Params,
}

impl Tlph {
    const CONTEXT: &str = "TLPH";

    /// Create a new [Tlph] instance with a fresh session identifier, the
    /// current time step as its start, and the given nonce and parameters.
    pub fn new(nonce: Vec<u8>, params: &Params) -> Self {
        let id = Ulid::generate();
        let start = params.time_step(None);

        let mut secret = Self::derive_secret(&id, &nonce, params);
        let traversev_params = params.tv();
        let permissioned = TraverseV::new_permissioned(
            &secret,
            Self::CONTEXT,
            traversev_params,
        );

        #[cfg(feature = "zeroize")]
        secret.zeroize();

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

        let mut secret = Self::derive_secret(&id, &nonce, &params);
        let traversev_params = params.tv();
        let permissioned = TraverseV::new_permissioned(
            &secret,
            Self::CONTEXT,
            traversev_params,
        );

        #[cfg(feature = "zeroize")]
        secret.zeroize();

        Self {
            id,
            start: challenge.start(),
            nonce: nonce.clone(),
            tv: permissioned,
            params,
        }
    }

    /// Mine a [Proof] of the given [Solution] for this session.
    pub fn prove(&self, solution: &Solution) -> Result<Proof, TlphError> {
        let mut input = solution.to_bytes()?;
        let mut nonce: u128 = self.tv.mine(&input, Counter::default(), 1);

        #[cfg(feature = "zeroize")]
        input.zeroize();

        let proof = Proof::new(self.id, solution, nonce);

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

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

        let mut input = match proof.solution().to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => return Err(e),
        };
        let mut nonce = proof.nonce();
        let valid = self.tv.verify(&input, nonce);

        #[cfg(feature = "zeroize")]
        {
            input.zeroize();
            nonce.zeroize();
        }

        Ok(valid)
    }

    /// Returns the session identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns a reference to the challenge nonce.
    pub const fn nonce(&self) -> &Vec<u8> {
        &self.nonce
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

        let mut hash = hasher.finalize();
        let secret: [u8; 32] = hash.into();

        #[cfg(feature = "zeroize")]
        {
            hasher.zeroize();
            hash.zeroize();
        }

        secret
    }
}
