#[test]
fn test_sha256() {
    bssl_sys::init();

    // SHA-256 of a message.
    let msg = [0x00u8];
    let mut tag = [0; bssl_sys::SHA256_DIGEST_LENGTH as usize];
    let result = unsafe {
        // Safety: input pointer is of the specified length, and the output pointer
        // is large enough for the result.
        bssl_sys::SHA256(msg.as_ptr(), msg.len(), tag.as_mut_ptr())
    };
    assert_eq!(result, tag.as_mut_ptr());
    assert_eq!(
        tag,
        [
            0x6eu8, 0x34u8, 0x0bu8, 0x9cu8, 0xffu8, 0xb3u8, 0x7au8, 0x98u8, 0x9cu8, 0xa5u8, 0x44u8,
            0xe6u8, 0xbbu8, 0x78u8, 0x0au8, 0x2cu8, 0x78u8, 0x90u8, 0x1du8, 0x3fu8, 0xb3u8, 0x37u8,
            0x38u8, 0x76u8, 0x85u8, 0x11u8, 0xa3u8, 0x06u8, 0x17u8, 0xafu8, 0xa0u8, 0x1d
        ]
    );
}
