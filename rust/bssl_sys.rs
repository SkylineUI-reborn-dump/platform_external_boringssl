//! Low-level crate providing FFI access to BoringSSL functionality.
//!
//! This version is adapted from upstream's rust/src/lib.rs file at:
//! <https://boringssl.googlesource.com/boringssl/+/refs/heads/master/rust/src/lib.rs>
//!
//! Almost all the code in this crate is produced by bindgen running
//! over the BoringSSL headers. The only manually generated code is
//! - an `init()` function
//! - Rust equivalents to functional preprocessor macros defined in the
//!   BoringSSL headers (as bindgen doesn't cope with them).

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use libc::*;

include!(concat!(env!("OUT_DIR"), "/bssl_sys_bindings.rs"));

pub fn ERR_GET_LIB(packed_error: u32) -> i32 {
    unsafe { ERR_GET_LIB_RUST(packed_error) }
}

pub fn ERR_GET_REASON(packed_error: u32) -> i32 {
    unsafe { ERR_GET_REASON_RUST(packed_error) }
}

pub fn ERR_GET_FUNC(packed_error: u32) -> i32 {
    unsafe { ERR_GET_FUNC_RUST(packed_error) }
}

pub fn init() {
    unsafe {
        CRYPTO_library_init();
    }
}
