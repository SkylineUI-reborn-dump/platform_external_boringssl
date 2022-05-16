use std::{fs::File, io::Read};

use anyhow::Result;

use crate::drbg;

const SEED_FOR_CLIENT_LEN: usize = 496;
const NUM_REQUESTS_PER_RESEED: u32 = 256;

pub struct Conditioner {
    hwrng: File,
    rg: drbg::Drbg,
    requests_since_reseed: u32,
}

impl Conditioner {
    pub fn new(mut hwrng: File) -> Result<Conditioner> {
        let mut et: drbg::Entropy = [0; drbg::ENTROPY_LEN];
        hwrng.read_exact(&mut et)?;
        let rg = drbg::Drbg::new(&et)?;
        Ok(Conditioner {
            hwrng,
            rg,
            requests_since_reseed: 0,
        })
    }

    pub fn reseed_if_necessary(&mut self) -> Result<()> {
        if self.requests_since_reseed >= NUM_REQUESTS_PER_RESEED {
            let mut et: drbg::Entropy = [0; drbg::ENTROPY_LEN];
            self.hwrng.read_exact(&mut et)?;
            self.rg.reseed(&et)?;
            self.requests_since_reseed = 0;
        }
        Ok(())
    }

    pub fn request(&mut self) -> Result<[u8; SEED_FOR_CLIENT_LEN]> {
        self.reseed_if_necessary()?;
        let mut seed_for_client = [0u8; SEED_FOR_CLIENT_LEN];
        self.rg.generate(&mut seed_for_client)?;
        self.requests_since_reseed += 1;
        Ok(seed_for_client)
    }
}
