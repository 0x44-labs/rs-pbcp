use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Uri;
use num_traits::{FromBytes, ToBytes};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::{
    Claims, Counter, URI_SCHEME, Wire, b64url_array, b64url_vec, host_query,
    with_decoded,
};
use crate::errors::PbcpError;

/// A `Proof` represents a [Claims] and the mined nonce that proves it,
/// bound to a challenge identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    id: Ulid,
    claims: Claims,
    nonce: Counter,
}

impl Proof {
    /// Create a new [Proof] for the given challenge identifier, claims and
    /// nonce.
    pub fn new(id: Ulid, claims: &Claims, nonce: Counter) -> Self {
        Self {
            id: id,
            claims: claims.clone(),
            nonce,
        }
    }

    /// Serialise this [Proof] to a `pbcp://proof` URI.
    pub fn to_uri(&self) -> Result<Uri, PbcpError> {
        let wire = ProofWire {
            id: self.id,
            nonce: self.nonce.to_le_bytes(),
            claims: self.claims.to_bytes()?,
        };

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

        Ok(Proof {
            id: wire.id,
            claims: Claims::from_bytes(&wire.claims)?,
            nonce: Counter::from_le_bytes(&wire.nonce),
        })
    }

    /// Serialise this [Proof] to a string of the form `id.claims.nonce`,
    /// with the claims and nonce encoded as unpadded URL-safe base64.
    pub fn to_string(&self) -> Result<String, PbcpError> {
        let id = self.id.to_string();

        let mut claims_bytes = self.claims.to_bytes()?;
        let mut nonce_bytes = self.nonce.to_le_bytes();

        let mut claims = URL_SAFE_NO_PAD.encode(&claims_bytes);
        let mut nonce = URL_SAFE_NO_PAD.encode(&nonce_bytes);

        let proof_str = format!("{id}.{claims}.{nonce}");

        #[cfg(feature = "zeroize")]
        {
            claims_bytes.zeroize();
            nonce_bytes.zeroize();
            claims.zeroize();
            nonce.zeroize();
        }

        Ok(proof_str)
    }

    /// Parse a [Proof] from a string of the form `id.claims.nonce`, with the
    /// claims and nonce encoded as unpadded URL-safe base64.
    pub fn from_string(s: &str) -> Result<Self, PbcpError> {
        let mut parts = s.split(".");
        let (Some(first), Some(second), Some(third), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PbcpError::ProofFormat);
        };

        let id =
            Ulid::from_string(first).map_err(|_| PbcpError::ProofFormat)?;
        let claims = with_decoded(second, Claims::from_bytes)??;
        let mut nonce = with_decoded(third, |v| {
            <&[u8; 16]>::try_from(v).map(|bytes| Counter::from_le_bytes(bytes))
        })?
        .map_err(|_| PbcpError::ProofFormat)?;

        let proof = Self { id, claims, nonce };

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Ok(proof)
    }

    /// Returns the challenge identifier.
    pub const fn id(&self) -> Ulid {
        self.id
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
    #[serde(with = "b64url_vec")]
    pub(crate) claims: Vec<u8>,
    #[serde(with = "b64url_array")]
    pub(crate) nonce: [u8; 16],
}

impl Wire for ProofWire {}

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
