use http::uri::PathAndQuery;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::TlphError;

pub(crate) trait Wire: Serialize {
    fn path_and_query(&self) -> Result<PathAndQuery, TlphError>
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
#[serde(deny_unknown_fields)]
pub(crate) struct ProofWire {
    pub(crate) id: Ulid,
    #[serde(with = "base64url")]
    pub(crate) solution: Vec<u8>,
    #[serde(with = "base64url_u128")]
    pub(crate) nonce: u128,
}

impl Wire for ProofWire {}

#[cfg(feature = "zeroize")]
impl Zeroize for ProofWire {
    fn zeroize(&mut self) {
        self.solution.zeroize();
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
