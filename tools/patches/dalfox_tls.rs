//! XYRO's standalone CLI has no Android JVM. Use explicit Mozilla roots with
//! rustls/webpki instead of the JNI-backed platform verifier. Verification of
//! names, certificate signatures and expiry remains enabled.
pub(crate) fn builder() -> reqwest::ClientBuilder {
    crate::ensure_crypto_provider();
    let pem = match std::env::var_os("SSL_CERT_FILE") {
        Some(path) => std::fs::read(path).unwrap_or_default(),
        None => include_bytes!("xyro-ca.pem").to_vec(),
    };
    // An invalid/missing explicitly configured bundle yields no trusted roots:
    // fail closed at TLS verification, never fall back to JNI or insecure mode.
    let roots = reqwest::Certificate::from_pem_bundle(&pem).unwrap_or_default();
    reqwest::Client::builder().tls_certs_only(roots)
}
