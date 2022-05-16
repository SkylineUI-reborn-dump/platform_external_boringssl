use std::ffi::CString;
use std::os::unix::prelude::RawFd;

use anyhow::{bail, Result};

pub fn android_get_control_socket(name: &str) -> Result<RawFd> {
    let name = CString::new(name)?;
    let res = unsafe { cutils_socket_bindgen::android_get_control_socket(name.as_ptr()) };
    if res < 0 {
        bail!("android_get_control_socket failed");
    }
    Ok(res)
}
