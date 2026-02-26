use crate::error::Error;

/// Verify the current process is running as root.
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the effective UID is not 0.
pub fn require_root() -> Result<(), Error> {
    if !nix::unistd::geteuid().is_root() {
        return Err(Error::NotRoot);
    }
    Ok(())
}

/// Read `SUDO_USER` and resolve it to a UID.
///
/// # Errors
///
/// Returns [`Error::NoSudoUser`] if the variable is unset, or
/// [`Error::UserNotFound`] if the username cannot be resolved.
pub fn resolve_sudo_user() -> Result<u32, Error> {
    let username = std::env::var("SUDO_USER").map_err(|_| Error::NoSudoUser)?;
    let user = nix::unistd::User::from_name(&username)
        .map_err(|_| Error::UserNotFound(username.clone()))?
        .ok_or(Error::UserNotFound(username))?;
    Ok(user.uid.as_raw())
}

#[cfg(test)]
mod tests {
    use super::{require_root, resolve_sudo_user};

    #[test]
    fn require_root_fails_in_tests() {
        // Tests never run as root.
        let result = require_root();
        assert!(result.is_err());
        assert!(result.expect_err("not root").to_string().contains("root"));
    }

    #[test]
    fn resolve_sudo_user_without_env_returns_error() {
        // In the test environment, SUDO_USER is not set.
        let result = resolve_sudo_user();
        assert!(result.is_err());
        let msg = result.expect_err("no sudo").to_string();
        assert!(msg.contains("SUDO_USER"));
    }
}
