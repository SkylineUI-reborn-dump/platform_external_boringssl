use std::{fs::File, io::Read};

use anyhow::{ensure, Result};
use log::debug;
use tokio::io::AsyncReadExt;

use crate::drbg;

const SEED_FOR_CLIENT_LEN: usize = 496;
const NUM_REQUESTS_PER_RESEED: u32 = 256;

pub struct Conditioner {
    hwrng: tokio::fs::File,
    rg: drbg::Drbg,
    requests_since_reseed: u32,
}

impl Conditioner {
    pub fn new(mut hwrng: File) -> Result<Conditioner> {
        let mut et: drbg::Entropy = [0; drbg::ENTROPY_LEN];
        hwrng.read_exact(&mut et)?;
        let rg = drbg::Drbg::new(&et)?;
        Ok(Conditioner {
            hwrng: tokio::fs::File::from_std(hwrng),
            rg,
            requests_since_reseed: 0,
        })
    }

    pub async fn reseed_if_necessary(&mut self) -> Result<()> {
        if self.requests_since_reseed >= NUM_REQUESTS_PER_RESEED {
            debug!("Reseeding DRBG");
            let mut et: drbg::Entropy = [0; drbg::ENTROPY_LEN];
            self.hwrng.read_exact(&mut et).await?;
            self.rg.reseed(&et)?;
            self.requests_since_reseed = 0;
        }
        Ok(())
    }

    pub fn request(&mut self) -> Result<[u8; SEED_FOR_CLIENT_LEN]> {
        ensure!(
            self.requests_since_reseed < NUM_REQUESTS_PER_RESEED,
            "Not enough reseeds"
        );
        let mut seed_for_client = [0u8; SEED_FOR_CLIENT_LEN];
        self.rg.generate(&mut seed_for_client)?;
        self.requests_since_reseed += 1;
        Ok(seed_for_client)
    }
}
