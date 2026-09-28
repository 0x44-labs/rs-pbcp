use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeWire {
    id: Ulid,
    #[serde(with = "base64url")]
    challenge: Vec<u8>,
    start: u64,
    m_cost: Option<u32>,
    t_cost: Option<u32>,
    e_cost: Option<u32>,
    n_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    l: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t0: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmissionWire {
    id: Ulid,
    #[serde(with = "base64url_u128")]
    proof: u128,
    #[serde(with = "base64url")]
    solution: Vec<u8>,
}

mod base64url {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        v: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<u8>, D::Error> {
        let input = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(&input)
            .map_err(|e| <D::Error as serde::de::Error>::custom(e))
    }
}

mod base64url_u128 {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(v.to_le_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<u128, D::Error> {
        let input = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&input)
            .map_err(|e| <D::Error as serde::de::Error>::custom(e))?;
        let proof: [u8; 16] = bytes.try_into().map_err(|_| {
            <D::Error as serde::de::Error>::custom(
                "proof must decode to 16 bytes",
            )
        })?;
        Ok(u128::from_le_bytes(proof))
    }
}
