FetchContent_Declare(
    wolfssl
    GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
    GIT_TAG        v5.8.2-stable  # July 2025 latest stable version
    GIT_SHALLOW    TRUE
)

# Force static linking
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries" FORCE)

set(WOLFSSL_TLS13 ON CACHE BOOL "Enable TLS 1.3 support" FORCE)
set(WOLFSSL_SNI ON CACHE BOOL "Enable Server Name Indication" FORCE)
set(WOLFSSL_SP ON CACHE BOOL "Enable single precision math" FORCE)
set(WOLFSSL_SP_MATH ON CACHE BOOL "Enable SP math implementation" FORCE)
set(WOLFSSL_AESNI ON CACHE BOOL "Enable AES-NI support" FORCE)
set(WOLFSSL_INTELASM ON CACHE BOOL "Enable Intel assembly optimizations" FORCE)
set(WOLFSSL_SP_ASM ON CACHE BOOL "Enable SP assembly optimizations" FORCE)
set(WOLFSSL_CHACHA ON CACHE BOOL "Enable ChaCha stream cipher" FORCE)
set(WOLFSSL_POLY1305 ON CACHE BOOL "Enable Poly1305 authenticator" FORCE)
set(WOLFSSL_CURVE25519 ON CACHE BOOL "Enable Curve25519 support" FORCE)

# Disable what we don't
set(WOLFSSL_PSK OFF CACHE BOOL "Disable PSK (Pre-Shared Key)" FORCE)
set(WOLFSSL_SRP OFF CACHE BOOL "Disable SRP (Secure Remote Password)" FORCE)
set(WOLFSSL_DTLS OFF CACHE BOOL "Disable DTLS (you're using TCP)" FORCE)
set(WOLFSSL_DTLS13 OFF CACHE BOOL "Disable DTLS 1.3 (requires DTLS)" FORCE)
set(WOLFSSL_OLD_TLS OFF CACHE BOOL "Disable old TLS versions" FORCE)
set(WOLFSSL_TLSV10 OFF CACHE BOOL "Disable TLS 1.0" FORCE)
set(WOLFSSL_TLSV11 OFF CACHE BOOL "Disable TLS 1.1" FORCE)
set(WOLFSSL_HARDEN OFF CACHE BOOL "Disable hardening for better performance" FORCE)
set(WOLFSSL_SECURE_RENEGOTIATION OFF CACHE BOOL "Disable secure renegotiation" FORCE)
set(WOLFSSL_ALPN OFF CACHE BOOL "Disable ALPN (not needed for basic HTTPS)" FORCE)
set(WOLFSSL_SESSION_TICKET OFF CACHE BOOL "Disable session tickets (simpler)" FORCE)
set(WOLFSSL_EXAMPLES OFF CACHE BOOL "Build wolfSSL examples" FORCE)
set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "Build wolfSSL crypt tests" FORCE)
set(WOLFSSL_OPENSSLEXTRA OFF CACHE BOOL "Disable OpenSSL compatibility (not needed)" FORCE)
set(WOLFSSL_OCSP OFF CACHE BOOL "Disable OCSP (certificate status)" FORCE)
set(WOLFSSL_CRL OFF CACHE BOOL "Disable CRL (certificate revocation)" FORCE)
set(WOLFSSL_DSA OFF CACHE BOOL "Disable DSA signatures" FORCE)
set(WOLFSSL_DH OFF CACHE BOOL "Disable Diffie-Hellman (use ECDH only)" FORCE)
set(WOLFSSL_RC4 OFF CACHE BOOL "Disable RC4 (insecure anyway)" FORCE)
set(WOLFSSL_MD4 OFF CACHE BOOL "Disable MD4 (obsolete)" FORCE)
set(WOLFSSL_MD5 OFF CACHE BOOL "Disable MD5 (weak hash)" FORCE)
set(WOLFSSL_DES3 OFF CACHE BOOL "Disable 3DES (slow and obsolete)" FORCE)

set(WOLFSSL_ERROR_STRINGS ON CACHE BOOL "Enable verbose error strings (disable for production)" FORCE)
set(WOLFSSL_DEBUG ON CACHE BOOL "Enable debug output (disable for production)" FORCE)

# Make wolfSSL available
FetchContent_MakeAvailable(wolfssl)
