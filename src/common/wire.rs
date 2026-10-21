use std::str::FromStr;

use http::uri::PathAndQuery;
use serde::Serialize;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::errors::PbcpError;

pub(crate) trait Wire: Serialize {
    /// Serialise this value into the path component of a URI.
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
    use serde::{Deserialize, Deserializer, Serializer, de::Visitor};
    #[cfg(feature = "zeroize")]
    use zeroize::Zeroize;

    pub(crate) fn serialize<S: Serializer>(
        v: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        if !s.is_human_readable() {
            return s.serialize_bytes(v);
        }

        let mut encoded = URL_SAFE_NO_PAD.encode(v);
        let serialized = s.serialize_str(&encoded);

        #[cfg(feature = "zeroize")]
        encoded.zeroize();

        serialized
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<u8>, D::Error> {
        if !d.is_human_readable() {
            return d.deserialize_byte_buf(BytesVisitor);
        }

        let mut input = String::deserialize(d)?;
        let deserialized = URL_SAFE_NO_PAD.decode(&input).map_err(|_| {
            <D::Error as serde::de::Error>::custom("invalid base64")
        });

        #[cfg(feature = "zeroize")]
        input.zeroize();

        deserialized
    }

    struct BytesVisitor;

    impl Visitor<'_> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("a byte string")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::common::Claims;

    use super::*;

    #[derive(Serialize)]
    struct Query {
        id: u8,
        name: &'static str,
    }

    impl Wire for Query {}

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
    fn path_and_query_serialises_fields() {
        let query = Query {
            id: 42,
            name: "Human",
        };

        let result = query.path_and_query();
        assert!(result.is_ok());

        let p_and_q = result.unwrap();
        assert_eq!(p_and_q.as_str(), "/?id=42&name=Human");
    }

    #[test]
    fn b64url_vec_round_trip() {
        let claims = claims();
        let original = B64UrlVec(claims.to_bytes().unwrap().to_vec());

        // Human-readable (JSON): serialised as a base64url string
        let json =
            serde_json::to_string(&original).expect("valid bytes serialise");

        let json_reconstructed: B64UrlVec = serde_json::from_str(&json)
            .expect("valid base64url string deserialises");
        assert_eq!(original, json_reconstructed);

        // Non-human-readable (CBOR): serialised as a raw byte string
        let mut cbor = Vec::new();

        ciborium::into_writer(&original, &mut cbor)
            .expect("valid bytes serialise");
        let cbor_value: ciborium::Value =
            ciborium::from_reader(cbor.as_slice()).expect("valid CBOR");
        assert_eq!(cbor_value, ciborium::Value::Bytes(original.0.clone()));

        let cbor_reconstructed: B64UrlVec =
            ciborium::from_reader(cbor.as_slice())
                .expect("valid CBOR byte string deserialises");
        assert_eq!(original, cbor_reconstructed);
    }

    #[test]
    fn b64url_vec_rejects_invalid() {
        // Human-readable (JSON): string that is not valid base64url
        let json_err = serde_json::from_str::<B64UrlVec>("\"!\"").unwrap_err();
        assert!(json_err.to_string().contains("invalid base64"));

        // Non-human-readable (CBOR): empty array instead of a byte string
        let cbor_err =
            ciborium::from_reader::<B64UrlVec, _>([0x80_u8].as_slice())
                .unwrap_err();
        assert!(cbor_err.to_string().contains("a byte string"));
    }
}
