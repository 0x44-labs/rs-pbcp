use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, marker::PhantomData};

use crate::{errors::TlphError, proof::Grid};

#[derive(Clone, Serialize, Deserialize)]
pub struct Solution<T> {
    step: u64,
    grid: Vec<u8>,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> Solution<T> {}

pub struct SolutionBuilder<T> {
    step: u64,
    grid: Grid<T>,
    claims: BTreeMap<String, Value>,
}

impl<T> SolutionBuilder<T> {
    const RESERVED: [&str; 2] = ["step", "grid"];

    fn new(step: u64, grid: Grid<T>) -> Self {
        Self {
            step,
            grid,
            claims: BTreeMap::new(),
        }
    }

    pub fn claim(
        mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Result<Self, TlphError> {
        let name = name.into();
        if Self::RESERVED.contains(&name.as_str()) {
            return Err(TlphError::ReservedClaim);
        }

        self.claims.insert(name.into(), value.into());
        Ok(self)
    }
}
