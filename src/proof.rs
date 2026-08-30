use ulid::Ulid;

use crate::errors::TlphError;

pub type Tile = [u8; 3];

pub struct Proof {
    id: Ulid,
    nonce: u128,
    solution: Grid,
}

impl Proof {
    pub fn new(id: Ulid, nonce: u128, solution: Grid) -> Proof {
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

    pub fn solution(&self) -> Grid {
        self.solution.clone()
    }
}

#[derive(Clone)]
pub struct Grid {
    size: usize,
    inner: Vec<Tile>,
}

impl Grid {
    pub fn new(size: usize, data: &[Tile]) -> Option<Grid> {
        (data.len() == size * size).then_some(Self {
            size,
            inner: data.to_vec(),
        })
    }

    pub fn data(&self) -> Vec<Tile> {
        self.inner.clone()
    }

    pub fn get(&self, row: usize, col: usize) -> Tile {
        self.inner[row * self.size + col]
    }

    pub fn row(&self, row: usize) -> Vec<Tile> {
        let start = row * self.size;
        self.inner[start..start + self.size].to_vec()
    }

    pub fn col(&self, col: usize) -> Vec<Tile> {
        (0..self.size)
            .map(|row| self.inner[row * self.size + col])
            .collect()
    }
}
