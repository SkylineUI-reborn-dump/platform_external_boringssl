perlasm(BCM_SOURCES aarch64 aesv8-armv8 aes/asm/aesv8-armx.pl)
perlasm(BCM_SOURCES aarch64 aesv8-gcm-armv8 modes/asm/aesv8-gcm-armv8.pl)
perlasm(BCM_SOURCES aarch64 armv8-mont bn/asm/armv8-mont.pl)
perlasm(BCM_SOURCES aarch64 bn-armv8 bn/asm/bn-armv8.pl)
perlasm(BCM_SOURCES aarch64 ghash-neon-armv8 modes/asm/ghash-neon-armv8.pl)
perlasm(BCM_SOURCES aarch64 ghashv8-armv8 modes/asm/ghashv8-armx.pl)
perlasm(BCM_SOURCES aarch64 p256_beeu-armv8-asm ec/asm/p256_beeu-armv8-asm.pl)
perlasm(BCM_SOURCES aarch64 p256-armv8-asm ec/asm/p256-armv8-asm.pl)
perlasm(BCM_SOURCES aarch64 sha1-armv8 sha/asm/sha1-armv8.pl)
perlasm(BCM_SOURCES aarch64 sha256-armv8 sha/asm/sha512-armv8.pl)
perlasm(BCM_SOURCES aarch64 sha512-armv8 sha/asm/sha512-armv8.pl)
perlasm(BCM_SOURCES aarch64 vpaes-armv8 aes/asm/vpaes-armv8.pl)
perlasm(BCM_SOURCES arm aesv8-armv7 aes/asm/aesv8-armx.pl)
perlasm(BCM_SOURCES arm armv4-mont bn/asm/armv4-mont.pl)
perlasm(BCM_SOURCES arm bsaes-armv7 aes/asm/bsaes-armv7.pl)
perlasm(BCM_SOURCES arm ghash-armv4 modes/asm/ghash-armv4.pl)
perlasm(BCM_SOURCES arm ghashv8-armv7 modes/asm/ghashv8-armx.pl)
perlasm(BCM_SOURCES arm sha1-armv4-large sha/asm/sha1-armv4-large.pl)
perlasm(BCM_SOURCES arm sha256-armv4 sha/asm/sha256-armv4.pl)
perlasm(BCM_SOURCES arm sha512-armv4 sha/asm/sha512-armv4.pl)
perlasm(BCM_SOURCES arm vpaes-armv7 aes/asm/vpaes-armv7.pl)
perlasm(BCM_SOURCES x86 aesni-x86 aes/asm/aesni-x86.pl)
perlasm(BCM_SOURCES x86 bn-586 bn/asm/bn-586.pl)
perlasm(BCM_SOURCES x86 co-586 bn/asm/co-586.pl)
perlasm(BCM_SOURCES x86 ghash-ssse3-x86 modes/asm/ghash-ssse3-x86.pl)
perlasm(BCM_SOURCES x86 ghash-x86 modes/asm/ghash-x86.pl)
perlasm(BCM_SOURCES x86 md5-586 md5/asm/md5-586.pl)
perlasm(BCM_SOURCES x86 sha1-586 sha/asm/sha1-586.pl)
perlasm(BCM_SOURCES x86 sha256-586 sha/asm/sha256-586.pl)
perlasm(BCM_SOURCES x86 sha512-586 sha/asm/sha512-586.pl)
perlasm(BCM_SOURCES x86 vpaes-x86 aes/asm/vpaes-x86.pl)
perlasm(BCM_SOURCES x86 x86-mont bn/asm/x86-mont.pl)
perlasm(BCM_SOURCES x86_64 aesni-gcm-x86_64 modes/asm/aesni-gcm-x86_64.pl)
perlasm(BCM_SOURCES x86_64 aesni-x86_64 aes/asm/aesni-x86_64.pl)
perlasm(BCM_SOURCES x86_64 ghash-ssse3-x86_64 modes/asm/ghash-ssse3-x86_64.pl)
perlasm(BCM_SOURCES x86_64 ghash-x86_64 modes/asm/ghash-x86_64.pl)
perlasm(BCM_SOURCES x86_64 md5-x86_64 md5/asm/md5-x86_64.pl)
perlasm(BCM_SOURCES x86_64 p256_beeu-x86_64-asm ec/asm/p256_beeu-x86_64-asm.pl)
perlasm(BCM_SOURCES x86_64 p256-x86_64-asm ec/asm/p256-x86_64-asm.pl)
perlasm(BCM_SOURCES x86_64 rdrand-x86_64 rand/asm/rdrand-x86_64.pl)
perlasm(BCM_SOURCES x86_64 rsaz-avx2 bn/asm/rsaz-avx2.pl)
perlasm(BCM_SOURCES x86_64 sha1-x86_64 sha/asm/sha1-x86_64.pl)
perlasm(BCM_SOURCES x86_64 sha256-x86_64 sha/asm/sha512-x86_64.pl)
perlasm(BCM_SOURCES x86_64 sha512-x86_64 sha/asm/sha512-x86_64.pl)
perlasm(BCM_SOURCES x86_64 vpaes-x86_64 aes/asm/vpaes-x86_64.pl)
perlasm(BCM_SOURCES x86_64 x86_64-mont bn/asm/x86_64-mont.pl)
perlasm(BCM_SOURCES x86_64 x86_64-mont5 bn/asm/x86_64-mont5.pl)

if(OPENSSL_ASM)
  list(APPEND BCM_SOURCES_ASM_USED ${BCM_SOURCES_ASM})
endif()
if(OPENSSL_NASM)
  list(APPEND BCM_SOURCES_ASM_USED ${BCM_SOURCES_NASM})
endif()

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
if(ARCH STREQUAL "arm")
  set(
    BCM_ASM_SOURCES

    aesv8-armx.${ASM_EXT}
    armv4-mont.${ASM_EXT}
    bsaes-armv7.${ASM_EXT}
    ghash-armv4.${ASM_EXT}
    ghashv8-armx.${ASM_EXT}
    sha1-armv4-large.${ASM_EXT}
    sha256-armv4.${ASM_EXT}
    sha512-armv4.${ASM_EXT}
    vpaes-armv7.${ASM_EXT}
  )
endif()

if(ARCH STREQUAL "aarch64")
  set(
    BCM_ASM_SOURCES

    aesv8-armx.${ASM_EXT}
    armv8-mont.${ASM_EXT}
    ghash-neon-armv8.${ASM_EXT}
    ghashv8-armx.${ASM_EXT}
    p256-armv8-asm.${ASM_EXT}
    p256_beeu-armv8-asm.${ASM_EXT}
    sha1-armv8.${ASM_EXT}
    sha256-armv8.${ASM_EXT}
    sha512-armv8.${ASM_EXT}
    vpaes-armv8.${ASM_EXT}
  )
endif()

if(ARCH STREQUAL "ppc64le")
  set(
    BCM_ASM_SOURCES

    aesp8-ppc.${ASM_EXT}
    ghashp8-ppc.${ASM_EXT}
  )
endif()

perlasm(aesni-gcm-x86_64.${ASM_EXT} modes/asm/aesni-gcm-x86_64.pl)
perlasm(aesni-x86_64.${ASM_EXT} aes/asm/aesni-x86_64.pl)
perlasm(aesni-x86.${ASM_EXT} aes/asm/aesni-x86.pl)
perlasm(aesp8-ppc.${ASM_EXT} aes/asm/aesp8-ppc.pl)
perlasm(aesv8-armx.${ASM_EXT} aes/asm/aesv8-armx.pl)
perlasm(armv4-mont.${ASM_EXT} bn/asm/armv4-mont.pl)
perlasm(armv8-mont.${ASM_EXT} bn/asm/armv8-mont.pl)
perlasm(bn-586.${ASM_EXT} bn/asm/bn-586.pl)
perlasm(bsaes-armv7.${ASM_EXT} aes/asm/bsaes-armv7.pl)
perlasm(co-586.${ASM_EXT} bn/asm/co-586.pl)
perlasm(ghash-armv4.${ASM_EXT} modes/asm/ghash-armv4.pl)
perlasm(ghashp8-ppc.${ASM_EXT} modes/asm/ghashp8-ppc.pl)
perlasm(ghashv8-armx.${ASM_EXT} modes/asm/ghashv8-armx.pl)
perlasm(ghash-neon-armv8.${ASM_EXT} modes/asm/ghash-neon-armv8.pl)
perlasm(ghash-ssse3-x86_64.${ASM_EXT} modes/asm/ghash-ssse3-x86_64.pl)
perlasm(ghash-ssse3-x86.${ASM_EXT} modes/asm/ghash-ssse3-x86.pl)
perlasm(ghash-x86_64.${ASM_EXT} modes/asm/ghash-x86_64.pl)
perlasm(ghash-x86.${ASM_EXT} modes/asm/ghash-x86.pl)
perlasm(md5-586.${ASM_EXT} md5/asm/md5-586.pl)
perlasm(md5-x86_64.${ASM_EXT} md5/asm/md5-x86_64.pl)
perlasm(p256-x86_64-asm.${ASM_EXT} ec/asm/p256-x86_64-asm.pl)
perlasm(p256_beeu-x86_64-asm.${ASM_EXT} ec/asm/p256_beeu-x86_64-asm.pl)
perlasm(p256-armv8-asm.${ASM_EXT} ec/asm/p256-armv8-asm.pl)
perlasm(p256_beeu-armv8-asm.${ASM_EXT} ec/asm/p256_beeu-armv8-asm.pl)
perlasm(rdrand-x86_64.${ASM_EXT} rand/asm/rdrand-x86_64.pl)
perlasm(rsaz-avx2.${ASM_EXT} bn/asm/rsaz-avx2.pl)
perlasm(sha1-586.${ASM_EXT} sha/asm/sha1-586.pl)
perlasm(sha1-armv4-large.${ASM_EXT} sha/asm/sha1-armv4-large.pl)
perlasm(sha1-armv8.${ASM_EXT} sha/asm/sha1-armv8.pl)
perlasm(sha1-x86_64.${ASM_EXT} sha/asm/sha1-x86_64.pl)
perlasm(sha256-586.${ASM_EXT} sha/asm/sha256-586.pl)
perlasm(sha256-armv4.${ASM_EXT} sha/asm/sha256-armv4.pl)
perlasm(sha256-armv8.${ASM_EXT} sha/asm/sha512-armv8.pl)
perlasm(sha256-x86_64.${ASM_EXT} sha/asm/sha512-x86_64.pl)
perlasm(sha512-586.${ASM_EXT} sha/asm/sha512-586.pl)
perlasm(sha512-armv4.${ASM_EXT} sha/asm/sha512-armv4.pl)
perlasm(sha512-armv8.${ASM_EXT} sha/asm/sha512-armv8.pl)
perlasm(sha512-x86_64.${ASM_EXT} sha/asm/sha512-x86_64.pl)
perlasm(vpaes-armv7.${ASM_EXT} aes/asm/vpaes-armv7.pl)
perlasm(vpaes-armv8.${ASM_EXT} aes/asm/vpaes-armv8.pl)
perlasm(vpaes-x86_64.${ASM_EXT} aes/asm/vpaes-x86_64.pl)
perlasm(vpaes-x86.${ASM_EXT} aes/asm/vpaes-x86.pl)
perlasm(x86_64-mont5.${ASM_EXT} bn/asm/x86_64-mont5.pl)
perlasm(x86_64-mont.${ASM_EXT} bn/asm/x86_64-mont.pl)
perlasm(x86-mont.${ASM_EXT} bn/asm/x86-mont.pl)

function(cpreprocess dest src)
  set(TARGET "")
  if(CMAKE_ASM_COMPILER_TARGET)
    set(TARGET "--target=${CMAKE_ASM_COMPILER_TARGET}")
  endif()

  add_custom_command(
    OUTPUT ${dest}
    COMMAND ${CMAKE_ASM_COMPILER} ${TARGET} $CMAKE_ASM_FLAGS -E ${src} -I${PROJECT_SOURCE_DIR}/include > ${dest}
    DEPENDS
    ${src}
    ${PROJECT_SOURCE_DIR}/include/openssl/arm_arch.h
    WORKING_DIRECTORY .
  )
endfunction()

=======
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
if(FIPS_DELOCATE)
  if(FIPS_SHARED)
    error("Can't set both delocate and shared mode for FIPS build")
  endif()

  add_library(
    bcm_c_generated_asm

    STATIC

    bcm.c
  )
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)

  if(ARCH STREQUAL "aarch64")
    # Perlasm output on Aarch64 needs to pass through the C preprocessor before
    # it can be parsed by delocate.
    foreach(asm ${BCM_ASM_SOURCES})
      cpreprocess(${asm}.s ${asm})
      list(APPEND BCM_ASM_PROCESSED_SOURCES "${asm}.s")
    endforeach()
  else()
    # No preprocessing is required on other platforms.
    set(BCM_ASM_PROCESSED_SOURCES ${BCM_ASM_SOURCES})
  endif()

  add_dependencies(bcm_c_generated_asm global_target)

=======
  add_dependencies(bcm_c_generated_asm boringssl_prefix_symbols)
  target_include_directories(bcm_c_generated_asm PRIVATE ../../include)
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
  set_target_properties(bcm_c_generated_asm PROPERTIES COMPILE_OPTIONS "-S")
  set_target_properties(bcm_c_generated_asm PROPERTIES POSITION_INDEPENDENT_CODE ON)

  go_executable(delocate boringssl.googlesource.com/boringssl/util/fipstools/delocate)
  add_custom_command(
    OUTPUT bcm-delocated.S
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    COMMAND ./delocate -a $<TARGET_FILE:bcm_c_generated_asm> -o bcm-delocated.S ${BCM_ASM_PROCESSED_SOURCES}
    DEPENDS bcm_c_generated_asm delocate ${BCM_ASM_PROCESSED_SOURCES}
=======
    COMMAND
    ./delocate
    -a $<TARGET_FILE:bcm_c_generated_asm>
    -o bcm-delocated.S
    -cc ${CMAKE_ASM_COMPILER}
    -cc-flags "${TARGET} $CMAKE_ASM_FLAGS"
    ${PROJECT_SOURCE_DIR}/include/openssl/arm_arch.h
    ${BCM_SOURCES_ASM_USED}
    DEPENDS
    bcm_c_generated_asm
    delocate
    ${BCM_SOURCES_ASM_USED}
    ${PROJECT_SOURCE_DIR}/include/openssl/arm_arch.h
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

  add_library(
    bcm_hashunset

    STATIC

    bcm-delocated.S
  )
  set_target_properties(bcm_hashunset PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(bcm_hashunset PROPERTIES LINKER_LANGUAGE C)

  set(MAYBE_INJECT_HASH_SHA256_FLAG "")
  # If building with OPENSSL_NO_ASM then ARCH will be "generic", but we still
  # need to use SHA-256. Since this only matters for FIPS, we only need to
  # worry about the Linux spelling of AArch64.
  if (ARCH STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(MAYBE_INJECT_HASH_SHA256_FLAG "-sha256")
  endif()

  go_executable(inject_hash
                boringssl.googlesource.com/boringssl/util/fipstools/inject_hash)
  add_custom_command(
    OUTPUT bcm.o
    COMMAND ./inject_hash -o bcm.o -in-archive $<TARGET_FILE:bcm_hashunset> ${MAYBE_INJECT_HASH_SHA256_FLAG}
    DEPENDS bcm_hashunset inject_hash
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

  # The outputs of add_custom_command cannot be referenced outside of the
  # CMakeLists.txt that defines it. Thus we have to wrap bcm.o in a custom target
  # so that crypto can depend on it.
  add_custom_target(bcm_o_target DEPENDS bcm.o)

  add_library(
    fipsmodule

    OBJECT

    fips_shared_support.c
  )
  add_dependencies(fipsmodule boringssl_prefix_symbols)
  target_include_directories(fipsmodule PRIVATE ../../include)
  set_target_properties(fipsmodule PROPERTIES LINKER_LANGUAGE C)
elseif(FIPS_SHARED)
  if(NOT BUILD_SHARED_LIBS)
    error("FIPS_SHARED set but not BUILD_SHARED_LIBS")
  endif()

  add_library(
    fipsmodule

    OBJECT

    fips_shared_support.c
  )
  add_dependencies(fipsmodule boringssl_prefix_symbols)
  target_include_directories(fipsmodule PRIVATE ../../include)

  add_library(
    bcm_library

    STATIC

    bcm.c
    ${BCM_SOURCES_ASM_USED}
  )
  add_dependencies(bcm_library boringssl_prefix_symbols)
  target_include_directories(bcm_library PRIVATE ../../include)

  add_custom_command(
    OUTPUT bcm.o
    COMMAND ${CMAKE_LINKER} -r -T ${CMAKE_CURRENT_SOURCE_DIR}/fips_shared.lds -o bcm.o --whole-archive $<TARGET_FILE:bcm_library>
    DEPENDS bcm_library fips_shared.lds
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

  add_custom_target(bcm_o_target DEPENDS bcm.o)
else()
  add_library(
    fipsmodule

    OBJECT

    bcm.c
    fips_shared_support.c
    ${BCM_SOURCES_ASM_USED}
  )
  add_dependencies(fipsmodule boringssl_prefix_symbols)
  target_include_directories(fipsmodule PRIVATE ../../include)
endif()
