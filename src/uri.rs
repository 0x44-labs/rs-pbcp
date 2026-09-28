use http::{Uri, uri::PathAndQuery};
use num_traits::{FromBytes, ToBytes};
use serde::{Deserialize, Serialize};
use serde_qs;
use std::str::FromStr;
use ulid::Ulid;

use crate::errors::TlphError;
use crate::params::Params;
use crate::solution::Solution;

trait Wire: Serialize {
    fn path_and_query(&self) -> Result<PathAndQuery, TlphError>
    where
        Self: Sized,
    {
        Ok(PathAndQuery::from_str(&serde_qs::to_string(self)?)?)
    }
}

pub struct Challenge {
    id: Ulid,
    challenge: Vec<u8>,
    start: u64,
    params: Params,
}

impl Challenge {
    pub fn build_uri(
        id: Ulid,
        challenge: &[u8],
        start: u64,
        params: &Params,
    ) -> Result<Uri, TlphError> {
        let tv = params.tv();
        let wire = ChallengeWire {
            id,
            challenge: challenge.to_vec(),
            start,
            m_cost: Some(tv.m_cost()),
            t_cost: Some(tv.t_cost()),
            e_cost: Some(tv.e_cost()),
            n_cost: Some(tv.n_cost()),
            x: Some(params.x()),
            l: Some(params.l()),
            t0: Some(params.t0()),
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme("tlph")
            .authority("challenge")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }
}

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

impl Wire for ChallengeWire {}

pub struct Submission<T> {
    id: Ulid,
    proof: u128,
    sollution: Solution<T>,
}

impl<T> Submission<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    pub fn build_uri(
        id: Ulid,
        proof: u128,
        solution: &Solution<T>,
    ) -> Result<Uri, TlphError> {
        let wire = SubmissionWire {
            id,
            proof,
            solution: solution.to_bytes()?,
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme("tlph")
            .authority("submission")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }
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

impl Wire for SubmissionWire {}

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
