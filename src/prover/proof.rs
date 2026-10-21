use http::Uri;
use num_traits::{FromBytes, ToBytes};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::{
    Claims, Counter, URI_SCHEME, Wire, b64url_vec, host_query,
};
use crate::errors::PbcpError;
use crate::verifier::{Challenge, ChallengeWire};

/// A `Proof` represents some [Claims] and the mined nonce that proves them,
/// bound to the [Challenge] it responds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    challenge: Challenge,
    claims: Claims,
    nonce: Counter,
}

impl Proof {
    /// Create a new [Proof] for the given challenge, claims and nonce.
    pub fn new(challenge: &Challenge, claims: &Claims, nonce: Counter) -> Self {
        Self {
            challenge: challenge.clone(),
            claims: claims.clone(),
            nonce,
        }
    }

    /// Serialise this [Proof] to a `pbcp://proof` URI.
    pub fn to_uri(&self) -> Result<Uri, PbcpError> {
        let wire = ProofWire::try_from(self)?;

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme(URI_SCHEME)
            .authority("proof")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    /// Parse a [Proof] from a `pbcp://proof` URI.
    pub fn from_uri(uri: &Uri) -> Result<Self, PbcpError> {
        let query = host_query(uri, "proof")?;
        let wire: ProofWire = serde_qs::from_str(query)?;

        Proof::try_from(wire)
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
        let wire: ProofWire = ciborium::from_reader(bytes)?;
        Proof::try_from(wire)
    }

    /// Returns reference to the challenge.
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
        let challenge_wire = ChallengeWire {
            id: value.id,
            expires_at: value.expires_at,
            nonce: value.challenge.clone(),
            m_cost: value.m_cost,
            t_cost: value.t_cost,
            e_cost: value.e_cost,
            n_cost: value.n_cost,
            auth_tag: value.auth_tag.clone(),
        };
        let challenge = Challenge::try_from(challenge_wire)?;

        let nonce: [u8; 16] = value
            .nonce
            .clone()
            .try_into()
            .map_err(|_| PbcpError::NonceLen)?;

        Ok(Self {
            challenge,
            claims: Claims::from_bytes(&value.claims)?,
            nonce: Counter::from_le_bytes(&nonce),
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
    pub(crate) id: Ulid,
    pub(crate) expires_at: u64,
    #[serde(with = "b64url_vec")]
    pub(crate) claims: Vec<u8>,
    #[serde(with = "b64url_vec")]
    pub(crate) challenge: Vec<u8>,
    #[serde(with = "b64url_vec")]
    pub(crate) nonce: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) m_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) t_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) e_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) n_cost: Option<u32>,
    #[serde(with = "b64url_vec")]
    pub(crate) auth_tag: Vec<u8>,
}

impl Wire for ProofWire {}

impl TryFrom<&Proof> for ProofWire {
    type Error = PbcpError;

    fn try_from(value: &Proof) -> Result<Self, Self::Error> {
        let challenge_wire = ChallengeWire::from(&value.challenge);

        Ok(Self {
            id: challenge_wire.id,
            expires_at: challenge_wire.expires_at,
            challenge: challenge_wire.nonce.to_vec(),
            claims: value.claims.to_bytes()?,
            nonce: value.nonce.to_le_bytes().to_vec(),
            m_cost: challenge_wire.m_cost,
            t_cost: challenge_wire.t_cost,
            e_cost: challenge_wire.e_cost,
            n_cost: challenge_wire.n_cost,
            auth_tag: challenge_wire.auth_tag,
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

/*
#[cfg(test)]
mod tests {
    use super::*;

    type Error = PbcpError;

    fn claims() -> Claims {
        Claims::builder()
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", 1786554930)
            .claim("exp", 1786561137)
            .build()
    }

    fn proof() -> Proof {
        let id = Ulid::generate();
        let claims = claims();
        let nonce = Counter::default();

        Proof::new(id, &claims, nonce)
    }

    #[test]
    fn uri_round_trip() {
        let original = proof();
        let uri = original.to_uri().expect("valid Proof serialises to URI");

        let reconstructed =
            Proof::from_uri(&uri).expect("valid URI parses to Proof");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn string_round_trip() {
        let original = proof();
        let string = original
            .to_string()
            .expect("valid Proof serialises to string");

        let reconstructed =
            Proof::from_string(&string).expect("valid string parses to Proof");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn from_string_rejects_malformed() {
        let id = Ulid::generate();
        let claims = URL_SAFE_NO_PAD.encode(
            claims()
                .to_bytes()
                .expect("valid Claims serialise to canonical JSON bytes"),
        );
        let nonce = URL_SAFE_NO_PAD.encode(0u128.to_le_bytes());

        for string in [
            format!("{nonce}.{claims}.{id}"),
            format!("{claims}.{id}.{nonce}"),
            format!("{id}.{claims}"),
            format!("{claims}.{nonce}"),
        ] {
            let result = Proof::from_string(&string);
            assert!(matches!(result.err(), Some(Error::ProofFormat)));
        }
    }

    #[test]
    fn accessors_return_their_own_field() {
        let id = Ulid::generate();
        let claims = claims();
        let nonce = Counter::default();
        let proof = Proof::new(id, &claims, nonce);

        assert_eq!(proof.id(), id);
        assert_eq!(proof.claims(), &claims);
        assert_eq!(proof.nonce(), nonce);
    }

    #[test]
    fn path_and_query_layout() {
        let id = Ulid::generate();
        let claims = claims()
            .to_bytes()
            .expect("valid Claims serialise to canonical JSON bytes");
        let nonce = Counter::default().to_le_bytes();

        let expected = format!(
            "/?id={}&claims={}&nonce={}",
            id,
            URL_SAFE_NO_PAD.encode(&claims),
            URL_SAFE_NO_PAD.encode(&nonce)
        );

        let wire = ProofWire { id, claims, nonce };
        let p_and_q = wire
            .path_and_query()
            .expect("valid wire builds path and query");

        assert_eq!(p_and_q.as_str(), expected);
    }
}
*/
