//! Process-wide ownership of the daemon's mutable runtime state.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

const LOCK_NAME: &str = "daemon.lock";

/// An advisory lock held for the complete daemon lifetime.
///
/// The lock file is intentionally never unlinked: keeping a stable inode
/// prevents two processes from locking different files during replacement.
pub struct DaemonLock {
    file: File,
}

impl DaemonLock {
    pub fn acquire(state_file: &Path) -> anyhow::Result<Self> {
        let run_dir = state_file
            .parent()
            .map(|parent| parent.join("run"))
            .unwrap_or_else(|| PathBuf::from("/tmp/causeway-run"));
        std::fs::create_dir_all(&run_dir)
            .with_context(|| format!("create daemon run dir {}", run_dir.display()))?;

        let run_dir_meta = std::fs::symlink_metadata(&run_dir)
            .with_context(|| format!("inspect daemon run dir {}", run_dir.display()))?;
        if !run_dir_meta.file_type().is_dir() || run_dir_meta.file_type().is_symlink() {
            bail!(
                "daemon run path {} must be a real directory, not a symlink or file",
                run_dir.display()
            );
        }
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("secure daemon run dir {}", run_dir.display()))?;

        let path = run_dir.join(LOCK_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("open daemon lock {}", path.display()))?;
        if !file
            .metadata()
            .with_context(|| format!("inspect daemon lock {}", path.display()))?
            .is_file()
        {
            bail!("daemon lock path {} is not a regular file", path.display());
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure daemon lock {}", path.display()))?;

        // SAFETY: flock only reads the valid descriptor owned by `file`.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!(
                    "another CAUSEWAY daemon already owns {}; stop that service or use its control socket",
                    path.display()
                );
            }
            return Err(error).with_context(|| format!("lock daemon state via {}", path.display()));
        }

        Ok(Self { file })
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid until the field is dropped.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_state_path(label: &str) -> PathBuf {
        let seq = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "causeway-lock-test-{}-{seq}-{label}",
                std::process::id()
            ))
            .join("state.json")
    }

    fn cleanup(state_path: &Path) {
        if let Some(root) = state_path.parent() {
            std::fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let state_path = test_state_path("exclusive");
        let first = DaemonLock::acquire(&state_path).unwrap();
        let error = DaemonLock::acquire(&state_path)
            .err()
            .expect("a second daemon must be rejected");
        assert!(error.to_string().contains("already owns"));

        drop(first);
        DaemonLock::acquire(&state_path).expect("dropping the owner must release the lock");
        cleanup(&state_path);
    }

    #[test]
    fn lock_paths_are_private() {
        let state_path = test_state_path("permissions");
        let _lock = DaemonLock::acquire(&state_path).unwrap();
        let run_dir = state_path.parent().unwrap().join("run");
        let lock_path = run_dir.join(LOCK_NAME);

        assert_eq!(
            std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        cleanup(&state_path);
    }

    #[test]
    fn symlink_lock_file_is_rejected() {
        let state_path = test_state_path("symlink");
        let run_dir = state_path.parent().unwrap().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let target = state_path.parent().unwrap().join("target.lock");
        File::create(&target).unwrap();
        symlink(&target, run_dir.join(LOCK_NAME)).unwrap();

        let error = DaemonLock::acquire(&state_path)
            .err()
            .expect("a symlink lock path must be rejected");
        assert!(error.to_string().contains("open daemon lock"));
        cleanup(&state_path);
    }
}
