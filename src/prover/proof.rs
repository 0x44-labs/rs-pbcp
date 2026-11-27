use num_traits::{FromBytes, ToBytes};
use serde::{Deserialize, Serialize};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::{Claims, Counter, Wire, b64url_vec};
use crate::errors::PbcpError;
use crate::verifier::Challenge;

/// Response to a [Challenge].
///
/// Holds some [Claims] and the mined nonce value proving them, with the
/// challenge they respond to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    challenge: Challenge,
    claims: Claims,
    nonce: Counter,
}

impl Proof {
    /// Create a new [Proof] for the given challenge, claims, and nonce.
    pub fn new(challenge: &Challenge, claims: &Claims, nonce: Counter) -> Self {
        Self {
            challenge: challenge.clone(),
            claims: claims.clone(),
            nonce,
        }
    }

    /// Serialise this [Proof] to CBOR bytes, omitting parameters that have
    /// their default values.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PbcpError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&ProofWire::try_from(self)?, &mut buf)?;
        Ok(buf)
    }

    /// Parse a [Proof] from CBOR bytes, using defaults for omitted parameters.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PbcpError> {
        let mut scratch_buffer = vec![0u8; bytes.len().max(1)];
        let result = ciborium::from_reader_with_buffer::<ProofWire, _>(
            bytes,
            &mut scratch_buffer,
        );

        #[cfg(feature = "zeroize")]
        scratch_buffer.zeroize();

        Proof::try_from(result?)
    }

    /// Returns a reference to the challenge.
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// Returns a reference to the claims.
    pub const fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Returns the nonce.
    pub const fn nonce(&self) -> Counter {
        self.nonce
    }
}

impl TryFrom<ProofWire> for Proof {
    type Error = PbcpError;

    fn try_from(value: ProofWire) -> Result<Self, Self::Error> {
        let challenge = Challenge::from_bytes(&value.challenge)?;
        let claims = Claims::from_bytes(&value.claims)?;

        let mut nonce: [u8; 16] = value
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| PbcpError::ProofNonce)?;
        let counter = Counter::from_le_bytes(&nonce);

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Ok(Self {
            challenge,
            claims,
            nonce: counter,
        })
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Proof {
    fn zeroize(&mut self) {
        self.claims.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Proof {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Proof {}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(deny_unknown_fields)]
pub(crate) struct ProofWire {
    #[serde(with = "b64url_vec")]
    pub(crate) challenge: Vec<u8>,
    #[serde(with = "b64url_vec")]
    pub(crate) claims: Vec<u8>,
    #[serde(with = "b64url_vec")]
    pub(crate) nonce: Vec<u8>,
}

impl Wire for ProofWire {}

impl TryFrom<&Proof> for ProofWire {
    type Error = PbcpError;

    fn try_from(value: &Proof) -> Result<Self, Self::Error> {
        let challenge = value.challenge.to_bytes()?;
        let claims = value.claims.to_bytes()?;

        let mut nonce_bytes = value.nonce.to_le_bytes();
        let nonce = nonce_bytes.to_vec();

        #[cfg(feature = "zeroize")]
        nonce_bytes.zeroize();

        Ok(Self {
            challenge,
            claims,
            nonce,
        })
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for ProofWire {
    fn zeroize(&mut self) {
        self.claims.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for ProofWire {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for ProofWire {}

#[cfg(test)]
mod tests {
    use traversev::Params;
    use ulid::Ulid;

    use crate::common::unix_now;

    use super::*;

    fn challenge() -> Challenge {
        Challenge::new(
            Ulid::generate(),
            unix_now() + 300,
            b"This is a challenge nonce",
            Params::new(8, 2, 2, 12).expect("valid parameters"),
        )
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

    fn proof(challenge: &Challenge) -> Proof {
        let claims = claims();
        let nonce = Counter::default();

        Proof::new(challenge, &claims, nonce)
    }

    #[test]
    fn cbor_bytes_round_trip() {
        let original = proof(&challenge());
        let bytes = original
            .to_bytes()
            .expect("valid Proof serialises to CBOR bytes");

        let reconstructed =
            Proof::from_bytes(&bytes).expect("valid CBOR bytes parse to Proof");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn accessors_return_their_own_field() {
        let challenge = challenge();
        let claims = claims();
        let nonce = Counter::default();
        let proof = Proof::new(&challenge, &claims, nonce);

        assert_eq!(proof.challenge(), &challenge);
        assert_eq!(proof.claims(), &claims);
        assert_eq!(proof.nonce(), nonce);
    }
}
