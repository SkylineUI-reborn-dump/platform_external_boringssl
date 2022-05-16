use std::ffi::CString;
use std::os::unix::{net::UnixListener, prelude::FromRawFd};

use anyhow::{ensure, Result};

pub fn android_get_control_socket(name: &str) -> Result<UnixListener> {
    let name = CString::new(name)?;
    let fd = unsafe { cutils_socket_bindgen::android_get_control_socket(name.as_ptr()) };
    ensure!(fd >= 0, "android_get_control_socket failed");
    Ok(unsafe { UnixListener::from_raw_fd(fd) })
}
