use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Grid {
    size: usize,
    inner: Vec<u8>,
}

#[wasm_bindgen]
impl Grid {
    #[wasm_bindgen(constructor)]
    pub fn new(size: usize, data: &[u8]) -> Option<Grid> {
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
