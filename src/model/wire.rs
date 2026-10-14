use http::uri::PathAndQuery;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::CtppError;

pub(crate) trait Wire: Serialize {
    fn path_and_query(&self) -> Result<PathAndQuery, CtppError>
    where
        Self: Sized,
    {
        let mut querystring = serde_qs::to_string(self)?;
        let mut s = format!("/?{}", querystring);

        let p_and_q = PathAndQuery::from_str(&s);

        #[cfg(feature = "zeroize")]
        {
            querystring.zeroize();
            s.zeroize();
        }

        Ok(p_and_q?)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(deny_unknown_fields)]
pub(crate) struct ChallengeWire {
    pub(crate) id: Ulid,
    pub(crate) expires_at: u64,
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
}

impl Wire for ChallengeWire {}

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

mod b64url_vec {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};
    #[cfg(feature = "zeroize")]
    use zeroize::Zeroize;

    pub(super) fn serialize<S: Serializer>(
        v: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut encoded = URL_SAFE_NO_PAD.encode(v);
        let serialized = s.serialize_str(&encoded);

        #[cfg(feature = "zeroize")]
        encoded.zeroize();

        serialized
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<u8>, D::Error> {
        let mut input = String::deserialize(d)?;
        let deserialized = URL_SAFE_NO_PAD.decode(&input).map_err(|_| {
            <D::Error as serde::de::Error>::custom("invalid base64")
        });

        #[cfg(feature = "zeroize")]
        input.zeroize();

        deserialized
    }
}

mod b64url_array {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};
    #[cfg(feature = "zeroize")]
    use zeroize::Zeroize;

    pub(super) fn serialize<S: Serializer>(
        v: &[u8; 16],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut encoded = URL_SAFE_NO_PAD.encode(v);
        let serialized = s.serialize_str(&encoded);

        #[cfg(feature = "zeroize")]
        encoded.zeroize();

        serialized
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; 16], D::Error> {
        let mut input = String::deserialize(d)?;
        let decoded = URL_SAFE_NO_PAD.decode(&input);

        #[cfg(feature = "zeroize")]
        input.zeroize();

        let mut bytes = decoded.map_err(|_| {
            <D::Error as serde::de::Error>::custom("invalid base64")
        })?;
        let deserialized = <[u8; 16]>::try_from(bytes.as_slice());

        let deserialized = deserialized.map_err(|_| {
            <D::Error as serde::de::Error>::custom(
                "value must decode to 16 bytes",
            )
        })?;

        #[cfg(feature = "zeroize")]
        bytes.zeroize();

        Ok(deserialized)
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use num_traits::ToBytes;

    use crate::{Counter, model::Claims};

    use super::*;

    const TIME: u64 = 1786558105;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct B64UrlVec(#[serde(with = "b64url_vec")] Vec<u8>);

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct B64UrlArray(#[serde(with = "b64url_array")] [u8; 16]);

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
    fn challenge_path_and_query_layout() {
        let id = Ulid::generate();
        let expires_at = TIME + 300;
        let nonce = b"This is a challenge nonce".to_vec();

        let expected = format!(
            "/?id={}&expires_at={}&nonce={}",
            id,
            expires_at,
            URL_SAFE_NO_PAD.encode(&nonce)
        );

        let wire = ChallengeWire {
            id,
            expires_at,
            nonce,
            m_cost: None,
            t_cost: None,
            e_cost: None,
            n_cost: None,
        };
        let p_and_q = wire
            .path_and_query()
            .expect("valid wire builds path and query");

        assert_eq!(p_and_q.as_str(), expected);
    }

    #[test]
    fn proof_path_and_query_layout() {
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

    #[test]
    fn b64url_vec_round_trip() {
        let claims = claims();
        let original = B64UrlVec(claims.to_bytes().unwrap().to_vec());
        let json =
            serde_json::to_string(&original).expect("valid bytes serialise");

        let reconstructed: B64UrlVec = serde_json::from_str(&json)
            .expect("valid base64url string deserialises");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn b64url_vec_rejects_invalid() {
        let err = serde_json::from_str::<B64UrlVec>("\"!\"").unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn b64url_array_round_trip() {
        let nonce = Counter::default();
        let original = B64UrlArray(nonce.to_le_bytes());
        let json =
            serde_json::to_string(&original).expect("valid array serialises");

        let reconstructed: B64UrlArray = serde_json::from_str(&json)
            .expect("valid base64url string deserialises");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn b64url_array_rejects_invalid() {
        let err = serde_json::from_str::<B64UrlArray>("\"!\"").unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }
}
