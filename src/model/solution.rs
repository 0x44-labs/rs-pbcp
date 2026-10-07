use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer;
use std::collections::BTreeMap;

use crate::errors::TlphError;

#[derive(Clone, Serialize, Deserialize)]
pub struct Solution {
    step: u64,
    data: Vec<u8>,
    claims: BTreeMap<String, Value>,
}

impl Solution {
    pub fn builder(step: u64, data: Vec<u8>) -> SolutionBuilder {
        SolutionBuilder::new(step, data)
    }

    pub fn from_json(json: &str) -> Result<Self, TlphError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn to_json(&self) -> Result<String, TlphError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TlphError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TlphError> {
        Ok(serde_json_canonicalizer::to_vec(self)?)
    }

    pub const fn step(&self) -> u64 {
        self.step
    }

    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }
}

pub struct SolutionBuilder {
    step: u64,
    data: Vec<u8>,
    claims: BTreeMap<String, Value>,
}

impl SolutionBuilder {
    fn new(step: u64, data: Vec<u8>) -> Self {
        Self {
            step,
            data,
            claims: BTreeMap::new(),
        }
    }

    pub fn claim(
        mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Self {
        self.claims.insert(name.into(), value.into());
        self
    }

    pub fn build(self) -> Solution {
        Solution {
            step: self.step,
            data: self.data,
            claims: self.claims,
        }
    }
}
