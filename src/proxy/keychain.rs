use crate::error::{Error, Result};

const SERVICE: &str = "nv";

fn account(host: &str, field: &str) -> String {
    format!("{host}:{field}")
}

/// Store a secret in the OS keychain.
pub(crate) fn store(host: &str, field: &str, secret: &str) -> Result<()> {
    keyring::Entry::new(SERVICE, &account(host, field))
        .map_err(|e| Error::cli(format!("Keychain error: {e}")))?
        .set_password(secret)
        .map_err(|e| Error::cli(format!("Failed to store secret in keychain: {e}")))
}

/// Retrieve a secret from the OS keychain. Returns `None` if not found or unavailable.
pub(crate) fn get(host: &str, field: &str) -> Option<String> {
    keyring::Entry::new(SERVICE, &account(host, field))
        .ok()?
        .get_password()
        .ok()
}

/// Delete a secret from the OS keychain.
pub(crate) fn delete(host: &str, field: &str) {
    if let Ok(entry) = keyring::Entry::new(SERVICE, &account(host, field)) {
        let _ = entry.delete_credential();
    }
}
