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
    pub(crate) start: u64,
    #[serde(with = "base64url")]
    pub(crate) nonce: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) m_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) t_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) e_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) n_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) x: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) l: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) t0: Option<u64>,
}

impl Wire for ChallengeWire {}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(deny_unknown_fields)]
pub(crate) struct ProofWire {
    pub(crate) id: Ulid,
    #[serde(with = "base64url")]
    pub(crate) message: Vec<u8>,
    #[serde(with = "base64url_u128")]
    pub(crate) nonce: u128,
}

impl Wire for ProofWire {}

#[cfg(feature = "zeroize")]
impl Zeroize for ProofWire {
    fn zeroize(&mut self) {
        self.message.zeroize();
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

mod base64url {
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

mod base64url_u128 {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};
    #[cfg(feature = "zeroize")]
    use zeroize::Zeroize;

    pub(super) fn serialize<S: Serializer>(
        v: &u128,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut nonce_bytes = v.to_le_bytes();
        let mut encoded = URL_SAFE_NO_PAD.encode(&nonce_bytes);
        let serialized = s.serialize_str(&encoded);

        #[cfg(feature = "zeroize")]
        {
            nonce_bytes.zeroize();
            encoded.zeroize();
        }

        serialized
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<u128, D::Error> {
        let mut input = String::deserialize(d)?;
        let decoded = URL_SAFE_NO_PAD.decode(&input);

        #[cfg(feature = "zeroize")]
        input.zeroize();

        let mut bytes = decoded.map_err(|_| {
            <D::Error as serde::de::Error>::custom("invalid base64")
        })?;
        let array = <[u8; 16]>::try_from(bytes.as_slice());

        #[cfg(feature = "zeroize")]
        bytes.zeroize();

        let mut array = array.map_err(|_| {
            <D::Error as serde::de::Error>::custom(
                "u128 value must decode to 16 bytes",
            )
        })?;
        let deserialized = u128::from_le_bytes(array);

        #[cfg(feature = "zeroize")]
        array.zeroize();

        Ok(deserialized)
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use crate::{Params, model::Message};

    use super::*;

    const TIME: u64 = 1786558105;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Base64Url(#[serde(with = "base64url")] Vec<u8>);

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Base64UrlU128(#[serde(with = "base64url_u128")] u128);

    fn time_step() -> u64 {
        let params = Params::default();
        params.time_step(Some(TIME))
    }

    fn message() -> Message {
        let step = time_step();
        let message = Message::builder(step)
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", 1786554930)
            .claim("exp", 1786561137)
            .build();

        message
    }

    #[test]
    fn challenge_path_and_query_layout() {
        let id = Ulid::generate();
        let start = time_step();
        let nonce = b"This is a challenge nonce".to_vec();

        let expected = format!(
            "/?id={}&start={}&nonce={}",
            id,
            start,
            URL_SAFE_NO_PAD.encode(&nonce)
        );

        let wire = ChallengeWire {
            id,
            start,
            nonce,
            m_cost: None,
            t_cost: None,
            e_cost: None,
            n_cost: None,
            x: None,
            l: None,
            t0: None,
        };
        let p_and_q = wire
            .path_and_query()
            .expect("valid wire builds path and query");

        assert_eq!(p_and_q.as_str(), expected);
    }

    #[test]
    fn proof_path_and_query_layout() {
        let id = Ulid::generate();
        let message = message()
            .to_bytes()
            .expect("valid Message serialises to canonical JSON bytes");
        let nonce = 0u128;

        let expected = format!(
            "/?id={}&message={}&nonce={}",
            id,
            URL_SAFE_NO_PAD.encode(&message),
            URL_SAFE_NO_PAD.encode(&nonce.to_le_bytes())
        );

        let wire = ProofWire { id, message, nonce };
        let p_and_q = wire
            .path_and_query()
            .expect("valid wire builds path and query");

        assert_eq!(p_and_q.as_str(), expected);
    }

    #[test]
    fn base64url_round_trip() {
        let message = message();
        let original = Base64Url(message.to_bytes().unwrap().to_vec());
        let json =
            serde_json::to_string(&original).expect("valid bytes serialise");

        let reconstructed: Base64Url = serde_json::from_str(&json)
            .expect("valid base64url string deserialises");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn base64url_rejects_invalid() {
        let err = serde_json::from_str::<Base64Url>("\"!\"").unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn base64url_u128_round_trip() {
        for value in [0, 1, u128::MAX] {
            let original = Base64UrlU128(value);
            let json = serde_json::to_string(&original)
                .expect("valid u128 serialises");

            let reconstructed: Base64UrlU128 = serde_json::from_str(&json)
                .expect("valid base64url string deserialises");
            assert_eq!(original, reconstructed);
        }
    }

    #[test]
    fn base64url_u128_rejects_invalid() {
        let err = serde_json::from_str::<Base64UrlU128>("\"!\"").unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn base64url_u128_rejects_wrong_length() {
        for len in [15, 17] {
            let json = serde_json::to_string(&Base64Url(vec![0u8; len]))
                .expect("valid bytes serialise");

            let err = serde_json::from_str::<Base64UrlU128>(&json).unwrap_err();
            assert!(err.to_string().contains("16 bytes"));
        }
    }
}
