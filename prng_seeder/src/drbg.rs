use anyhow::{anyhow, Result};
use bssl_sys_raw as bssl_sys;

pub const ENTROPY_LEN: usize = bssl_sys::CTR_DRBG_ENTROPY_LEN as usize;

pub type Entropy = [u8; ENTROPY_LEN];

pub struct Drbg(*mut bssl_sys::CTR_DRBG_STATE);

impl Drbg {
    pub fn new(entropy: &Entropy) -> Result<Drbg> {
        let p = unsafe { bssl_sys::CTR_DRBG_new(entropy.as_ptr(), std::ptr::null(), 0) };
        if p.is_null() {
            Err(anyhow!("CTR_DRBG_new failed"))
        } else {
            Ok(Drbg(p))
        }
    }

    pub fn reseed(&mut self, entropy: &Entropy) -> Result<()> {
        if unsafe { bssl_sys::CTR_DRBG_reseed(self.0, entropy.as_ptr(), std::ptr::null(), 0) } == 1
        {
            Ok(())
        } else {
            Err(anyhow!("CTR_DRBG_reseed failed"))
        }
    }

    pub fn generate(&mut self, buf: &mut [u8]) -> Result<()> {
        if unsafe {
            bssl_sys::CTR_DRBG_generate(self.0, buf.as_mut_ptr(), buf.len(), std::ptr::null(), 0)
        } == 1
        {
            Ok(())
        } else {
            Err(anyhow!("CTR_DRBG_generate failed"))
        }
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::CTR_DRBG_free(self.0);
        }
    }
}
