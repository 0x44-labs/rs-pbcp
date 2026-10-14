#![cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
//! ## Example
//! ```
//! use ctpp::{Params, Claims, Ctpp, TvParams};
//!
//! fn main() {
//!     let nonce = b"This is a challenge nonce".to_vec();
//!     let tv = TvParams::new(12 * 1024, 3, 8, 12).unwrap();
//!     let params = Params::new(tv, 30, 6, None).unwrap();
//!
//!     // Construct a new verifier peer for a CTPP session
//!     let verifier = Ctpp::new(nonce, &params);
//!
//!     // Create a challenge from the verifier peer
//!     let challenge = verifier.to_challenge();
//!
//!     // Build JWT-style claims
//!     let claims = Claims::builder(step)
//!         .claim("iss", "https://humanity.example")
//!         .claim("sub", "Homo sapiens")
//!         .claim("aud", "https://humans-only.example")
//!         .claim("iat", 1786554930)
//!         .claim("exp", 1786561137)
//!         .build();
//!
//!     // Create a prover peer from the challenge
//!     let prover = Ctpp::from_challenge(&challenge);
//!
//!     // Mine a proof of the claims
//!     let proof = prover.prove(&claims).unwrap();
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
//! `ZeroizeOnDrop` for `Claims`, `ClaimsBuilder`, and `Proof`, and
//! zeroises intermediate values on a best-effort basis.
mod errors;
mod model;

use blake3::Hasher;
use std::time::{SystemTime, UNIX_EPOCH};
use traversev::TraverseV;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub use crate::errors::CtppError;
pub use crate::model::{Challenge, Claims, ClaimsBuilder, Counter, Proof};

/// Alias for TraverseV proof-of-work parameters.
pub type TvParams = traversev::Params;

/// Claim-Bound Time-Based Proof Protocol (CTPP) context.
#[derive(Debug)]
pub struct Ctpp {
    context: String,
    params: TvParams,
}

impl Ctpp {
    /// Create a new CTPP context.
    pub fn new(context: impl Into<String>, params: TvParams) -> Self {
        Self {
            context: context.into(),
            params,
        }
    }

    /// Create a new CTPP [Verifier] from this context.
    pub fn verifier(&self, nonce: &[u8], ttl: u64) -> Verifier {
        Verifier::new(&self.context, nonce, ttl, self.params)
    }

    /// Create a new CTPP [Prover] from this context.
    pub fn prover(&self, challenge: &Challenge) -> Result<Prover, CtppError> {
        let limit = self.params;
        let requested = challenge.params();

        if requested.m_cost() > limit.m_cost()
            || requested.t_cost() > limit.t_cost()
            || requested.e_cost() > limit.e_cost()
            || requested.n_cost() > limit.n_cost()
        {
            return Err(CtppError::TooCostly);
        }

        Ok(Prover::new(&self.context, challenge))
    }
}

/// A [Ctpp] Verifier.
#[derive(Debug)]
pub struct Verifier {
    id: Ulid,
    expires_at: u64,
    nonce: Vec<u8>,
    tv: TraverseV,
    params: TvParams,
}

impl Verifier {
    fn new(context: &str, nonce: &[u8], ttl: u64, params: TvParams) -> Self {
        let id = Ulid::generate();
        let expires_at = unix_now() + ttl;

        let mut secret = derive_secret(&id, nonce);
        let tv = TraverseV::new_permissioned(&secret, context, params);

        #[cfg(feature = "zeroize")]
        secret.zeroize();

        Self {
            id,
            expires_at,
            nonce: nonce.to_vec(),
            tv,
            params,
        }
    }

    /// Create a [Challenge] from this [Verifier].
    pub fn to_challenge(&self) -> Challenge {
        Challenge::new(self.id, self.expires_at, &self.nonce, self.params)
    }

    /// Verify the given [Proof] against this [Verifier]'s challenge, returning
    /// whether its nonce is a valid proof over its claims.
    pub fn verify(&self, proof: &Proof) -> Result<bool, CtppError> {
        if proof.id() != self.id {
            return Err(CtppError::WrongChallenge);
        }
        if proof.nonce().time() > self.expires_at
            || unix_now() > self.expires_at
        {
            return Err(CtppError::Expired);
        }

        let mut input = match proof.claims().to_bytes() {
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

    /// Returns the challenge identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns the time of challenge expiration.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns a reference to the challenge nonce.
    pub const fn nonce(&self) -> &Vec<u8> {
        &self.nonce
    }
}

/// A [Ctpp] Prover.
#[derive(Debug)]
pub struct Prover {
    id: Ulid,
    tv: TraverseV,
}

impl Prover {
    fn new(context: &str, challenge: &Challenge) -> Self {
        let id = challenge.id();
        let nonce = challenge.nonce();
        let params = challenge.params();

        let mut secret = derive_secret(&id, &nonce);
        let tv = TraverseV::new_permissioned(&secret, context, params);

        #[cfg(feature = "zeroize")]
        secret.zeroize();

        Self { id, tv }
    }

    /// Mine a [Proof] over the given [Claims] for the challenge this [Prover]
    /// was constructed from.
    pub fn prove(&self, claims: &Claims) -> Result<Proof, CtppError> {
        let mut input = claims.to_bytes()?;
        let mut nonce: Counter = self.tv.mine(&input, Counter::default(), 1);

        #[cfg(feature = "zeroize")]
        input.zeroize();

        let proof = Proof::new(self.id, claims, nonce);

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Ok(proof)
    }

    /// Returns the challenge identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("")
        .as_secs()
}

fn derive_secret(id: &Ulid, nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();

    hasher.update(&id.to_bytes());
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

/*
#[cfg(test)]
mod tests {
    use super::*;

    type Error = CtppError;

    const TIME: u64 = 1786558105;
    const NONCE: &[u8] = b"This is a challenge nonce";

    /// Parameters for testing.
    fn params() -> Params {
        let tv = TvParams::new(8, 2, 2, 12).expect("test parameters are valid");
        Params::new(tv, 30, 6, None).expect("test parameters are valid")
    }

    fn time_step() -> u64 {
        let params = Params::default();
        params.time_step(Some(TIME))
    }

    fn claims() -> Claims {
        Claims::builder()
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", 1786554930)
            .claim("exp", 1786561137)
            .build()
    }

    #[test]
    fn new_starts_at_current_time_step() {
        let params = params();

        let before = params.time_step(None);
        let ctpp = Ctpp::new(NONCE.to_vec(), params);
        let after = params.time_step(None);

        assert!((before..=after).contains(&ctpp.start()));
    }

    #[test]
    fn challenge_round_trip() {
        let params = params();

        let original = Ctpp::new(NONCE.to_vec(), params);
        let reconstructed = Ctpp::from_challenge(&original.to_challenge());

        assert_eq!(reconstructed.id(), original.id());
        assert_eq!(reconstructed.start(), original.start());
        assert_eq!(reconstructed.nonce(), original.nonce());
        assert_eq!(reconstructed.params(), original.params());
    }

    #[test]
    fn proof_verifies() {
        let params = params();
        let verifier = Ctpp::new(NONCE.to_vec(), params);

        let prover = Ctpp::from_challenge(&verifier.to_challenge());
        let proof = prover
            .prove(&claims())
            .expect("any valid Claims are provable");

        let result = verifier.verify(&proof, None);
        assert!(result.is_ok());

        let valid = result.unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn verify_rejects_wrong_session() {
        let params = params();
        let verifier = Ctpp::new(b"Verifier".to_vec(), params);

        let prover = Ctpp::new(b"Prover".to_vec(), params);
        let proof = prover
            .prove(&claims())
            .expect("any valid Claims is provable");

        let result = verifier.verify(&proof, None);
        assert!(matches!(result.err(), Some(Error::WrongSession)));
    }

    /*
    #[test]
    fn verify_rejects_out_of_range() {
        let params = params();
        let verifier = Ctpp::new(NONCE.to_vec(), params);

        let start = verifier.start();
        let l = verifier.params().l();

        // Before the window, after the last permitted step, and later than
        // the current step.
        for (_, current) in [
            (start - 1, start),
            (start + l, start + l + 1),
            (start + 1, start),
        ] {
            let id = verifier.id();
            let nonce = Counter::from(0u128);
            let proof = Proof::new(id, &claims(), nonce);

            let result = verifier.verify(&proof, Some(current));
            assert!(matches!(result.err(), Some(Error::OutOfRange)));
        }
    }
    */

    #[test]
    fn accessors_return_their_own_field() {
        let id = Ulid::generate();
        let params = params();
        let challenge = Challenge::new(id, time_step(), NONCE, params);
        let ctpp = Ctpp::from_challenge(&challenge);

        assert_eq!(ctpp.id(), id);
        assert_eq!(ctpp.start(), time_step());
        assert_eq!(ctpp.nonce(), &NONCE.to_vec());
        assert_eq!(ctpp.params(), params);
    }
}
*/
