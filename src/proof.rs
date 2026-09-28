use num_traits::{FromBytes, ToBytes};

use crate::errors::TlphError;
use crate::solution::Grid;

pub struct Proof<T> {
    proof: u128,
    step: u64,
    grid: Grid<T>,
}

impl<T> Proof<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    pub fn new(proof: u128, step: u64, grid: Grid<T>) -> Self {
        Self { proof, step, grid }
    }

    pub const fn proof(&self) -> u128 {
        self.proof
    }

    pub const fn step(&self) -> u64 {
        self.step
    }

    pub fn grid(&self) -> Grid<T> {
        self.grid.clone()
    }
}

impl<T> TryFrom<&[u8]> for Proof<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    type Error = TlphError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // 16 proof + 8 step + 4 grid (min)
        const MIN_PROOF_BYTES: usize = 28;
        if value.len() < MIN_PROOF_BYTES {
            return Err(Self::Error::ProofTooSmall);
        }

        let mut proof_bytes = [0u8; 16];
        proof_bytes.copy_from_slice(&value[..16]);
        let proof = u128::from_le_bytes(proof_bytes);

        let mut step_bytes = [0u8; 8];
        step_bytes.copy_from_slice(&value[16..24]);
        let step = u64::from_le_bytes(step_bytes);

        let grid = Grid::<T>::try_from(&value[24..])?;

        Ok(Self { proof, step, grid })
    }
}

impl<T> From<Proof<T>> for Vec<u8>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    fn from(value: Proof<T>) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&value.proof.to_le_bytes());
        bytes.extend_from_slice(&value.step.to_le_bytes());
        bytes.extend(Vec::<u8>::from(value.grid));
        bytes
    }
}
