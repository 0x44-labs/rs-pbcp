use ulid::Ulid;

use crate::errors::TlphError;

pub struct Proof {
    id: Ulid,
    nonce: u128,
    solution: Solution,
}

impl Proof {
    pub fn new(id: Ulid, nonce: u128, solution: Solution) -> Proof {
        Proof {
            id,
            nonce,
            solution,
        }
    }

    pub fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub const fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn solution(&self) -> Solution {
        self.solution.clone()
    }
}

#[derive(Clone)]
pub struct Solution {
    size: usize,
    inner: Vec<u8>,
}

impl Solution {
    pub fn new(size: usize, data: &[u8]) -> Option<Solution> {
        (data.len() == size * size).then_some(Self {
            size,
            inner: data.to_vec(),
        })
    }

    pub fn data(&self) -> Vec<u8> {
        self.inner.clone()
    }

    pub fn get(&self, row: usize, col: usize) -> u8 {
        self.inner[row * self.size + col]
    }

    pub fn row(&self, row: usize) -> Vec<u8> {
        let start = row * self.size;
        self.inner[start..start + self.size].to_vec()
    }

    pub fn col(&self, col: usize) -> Vec<u8> {
        (0..self.size)
            .map(|row| self.inner[row * self.size + col])
            .collect()
    }
}
