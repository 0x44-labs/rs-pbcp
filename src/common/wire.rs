use http::uri::PathAndQuery;
use serde::Serialize;
use std::str::FromStr;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::errors::PbcpError;

pub(crate) trait Wire: Serialize {
    fn path_and_query(&self) -> Result<PathAndQuery, PbcpError>
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

pub(crate) mod b64url_vec {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};
    #[cfg(feature = "zeroize")]
    use zeroize::Zeroize;

    pub(crate) fn serialize<S: Serializer>(
        v: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut encoded = URL_SAFE_NO_PAD.encode(v);
        let serialized = s.serialize_str(&encoded);

        #[cfg(feature = "zeroize")]
        encoded.zeroize();

        serialized
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
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

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::common::Claims;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct B64UrlVec(#[serde(with = "b64url_vec")] Vec<u8>);

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
}
