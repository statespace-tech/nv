use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use std::path::Path;

use crate::error::{Error, Result};
use crate::proxy::config::{ca_cert_path, ca_key_path, global_ca_dir};

/// A loaded CA, ready for signing host certificates.
///
/// The `Issuer` owns all its data (`'static` lifetime).
pub(crate) struct CertificateAuthority {
    pub issuer: Issuer<'static, KeyPair>,
}

/// Generate a new CA key pair and self-signed certificate. Saves PEM files to env_dir.
pub(crate) fn generate_ca(env_dir: &Path) -> Result<()> {
    let key = KeyPair::generate()
        .map_err(|e| Error::cli(format!("Failed to generate CA key: {e}")))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "Statespace Local Proxy CA",
    );

    let cert = params
        .self_signed(&key)
        .map_err(|e| Error::cli(format!("Failed to self-sign CA certificate: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    let cert_path = ca_cert_path(env_dir);
    let key_path = ca_key_path(env_dir);

    std::fs::write(&cert_path, cert_pem)?;
    std::fs::write(&key_path, key_pem)?;

    // Restrict key permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Load an existing CA from the env_dir PEM files.
pub(crate) fn load_ca(env_dir: &Path) -> Result<CertificateAuthority> {
    let cert_pem = std::fs::read_to_string(ca_cert_path(env_dir))?;
    let key_pem = std::fs::read_to_string(ca_key_path(env_dir))?;

    let key = KeyPair::from_pem(&key_pem)
        .map_err(|e| Error::cli(format!("Failed to load CA key: {e}")))?;

    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
        .map_err(|e| Error::cli(format!("Failed to parse CA certificate: {e}")))?;

    Ok(CertificateAuthority { issuer })
}

/// Ensure the global CA exists (generating it if needed) and load it.
///
/// The global CA lives at `global_ca_dir()` (e.g. `~/Library/Application Support/statespace/proxy-ca/`).
/// This function only generates the CA; the caller is responsible for trusting it when it's
/// first created.
pub(crate) fn ensure_global_ca() -> Result<CertificateAuthority> {
    let ca_dir = global_ca_dir()
        .ok_or_else(|| Error::cli("Cannot determine system config directory"))?;

    if !ca_cert_path(&ca_dir).exists() {
        std::fs::create_dir_all(&ca_dir)
            .map_err(|e| Error::cli(format!("Failed to create CA directory: {e}")))?;
        generate_ca(&ca_dir)?;
    }

    load_ca(&ca_dir)
}

/// Generate a TLS certificate for `hostname`, signed by the given CA.
pub(crate) fn generate_host_cert(
    hostname: &str,
    ca: &CertificateAuthority,
) -> Result<(rcgen::Certificate, KeyPair)> {
    let host_key = KeyPair::generate()
        .map_err(|e| Error::cli(format!("Failed to generate host key: {e}")))?;

    let params = CertificateParams::new(vec![hostname.to_string()])
        .map_err(|e| Error::cli(format!("Failed to build host cert params: {e}")))?;

    let host_cert = params
        .signed_by(&host_key, &ca.issuer)
        .map_err(|e| Error::cli(format!("Failed to sign host certificate: {e}")))?;

    Ok((host_cert, host_key))
}

