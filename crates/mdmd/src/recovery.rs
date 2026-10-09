//! Filesystem-only validation and restoration for SQLite state.
//!
//! Restoring an MDM database must preserve the exact enrollment generations,
//! SCEP replay responses, device fingerprints, and durable notification state.
//! This module deliberately does not copy certificate or APNs key material. The
//! operator must restore those files separately and validate the CA/key pair
//! before starting the service.

use crate::identity::Identity;
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OpenFlags};
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

/// The schema and byte size observed after a backup has passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    pub bytes: u64,
    pub user_version: i64,
}

/// Metadata for the CA material that must accompany a restored database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaInfo {
    pub fingerprint: String,
    pub expires_at: String,
}

/// Validates a private, standalone SQLite backup without opening it for write.
///
/// Validation checks the file type and permissions, SQLite integrity, foreign
/// key references, schema version, and the tables required by this service.
pub fn validate_backup(path: &Path) -> Result<BackupInfo> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat SQLite backup {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("SQLite backup must be a regular file");
    }
    validate_private_mode(path, "SQLite backup")?;
    ensure!(metadata.len() > 0, "SQLite backup is empty");
    let wal_path = sqlite_wal_path(path);
    if let Ok(wal_metadata) = fs::symlink_metadata(&wal_path)
        && wal_metadata.len() > 0
    {
        bail!("SQLite backup has a non-empty WAL sidecar; use a standalone snapshot");
    }

    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open SQLite backup {}", path.display()))?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .context("set SQLite backup busy timeout")?;
    let mut integrity_statement = connection
        .prepare("PRAGMA integrity_check")
        .context("prepare SQLite integrity check")?;
    let mut integrity_rows = integrity_statement
        .query([])
        .context("check SQLite backup integrity")?;
    let integrity: String = integrity_rows
        .next()
        .context("read SQLite integrity check")?
        .context("SQLite integrity check returned no result")?
        .get(0)
        .context("read SQLite integrity result")?;
    ensure!(integrity == "ok", "SQLite backup integrity check failed");
    ensure!(
        integrity_rows
            .next()
            .context("read SQLite integrity check results")?
            .is_none(),
        "SQLite integrity check returned additional errors"
    );
    drop(integrity_rows);
    drop(integrity_statement);

    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .context("prepare SQLite foreign-key check")?;
    let mut rows = foreign_keys
        .query([])
        .context("run SQLite foreign-key check")?;
    ensure!(
        rows.next()
            .context("read SQLite foreign-key check")?
            .is_none(),
        "SQLite backup contains a foreign-key violation"
    );
    drop(rows);
    drop(foreign_keys);

    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .context("read SQLite backup schema version")?;
    let required_tables: &[&str] = match user_version {
        1 => &["enrollments", "commands", "outbox", "audit"],
        2 => &[
            "enrollments",
            "commands",
            "outbox",
            "audit",
            "declarations",
            "declaration_revisions",
            "declaration_targets",
            "ddm_state",
            "ddm_reports",
        ],
        3 => &[
            "enrollments",
            "commands",
            "outbox",
            "audit",
            "declarations",
            "declaration_revisions",
            "declaration_targets",
            "ddm_state",
            "ddm_reports",
            "device_observations",
            "erase_intents",
            "ade_devices",
            "apple_requests",
            "app_license_assignments",
            "ade_profiles",
            "ade_bootstrap",
        ],
        _ => bail!("unsupported SQLite backup schema version {user_version}"),
    };
    for table in required_tables {
        let present: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
                [table],
                |row| row.get(0),
            )
            .with_context(|| format!("check SQLite backup table {table}"))?;
        ensure!(present == 1, "SQLite backup is missing table {table}");
    }

    Ok(BackupInfo {
        bytes: metadata.len(),
        user_version,
    })
}

/// Validates that the CA certificate and private key form one usable identity.
///
/// The database contains certificate fingerprints, not the issuing CA
/// certificate itself, so this check verifies the material operators restore
/// alongside the database. It cannot prove that an arbitrary fingerprint was
/// issued by that CA unless the original device certificate is also available.
pub fn validate_ca_material(certificate_path: &Path, key_path: &Path) -> Result<CaInfo> {
    let identity = Identity::load(certificate_path, key_path)?;
    Ok(CaInfo {
        fingerprint: identity.ca_fingerprint()?,
        expires_at: identity.certificate_expiry()?,
    })
}

/// Restores a validated backup to a new destination without overwriting it.
///
/// The destination is created with private mode `0600` on Unix. A failed copy
/// or post-copy validation removes the partial destination so a retry cannot
/// accidentally treat it as a completed restore.
pub fn restore_database(backup: &Path, destination: &Path) -> Result<BackupInfo> {
    if backup == destination {
        bail!("restore source and destination must differ");
    }
    let source_info = validate_backup(backup)?;
    if destination.exists() {
        bail!("restore destination already exists");
    }
    ensure_parent_directory(destination)?;

    let mut destination_created = false;
    let result = (|| -> Result<BackupInfo> {
        let mut source = File::open(backup)
            .with_context(|| format!("open SQLite backup {}", backup.display()))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(destination)
            .with_context(|| format!("create restore destination {}", destination.display()))?;
        destination_created = true;
        io::copy(&mut source, &mut output).context("copy SQLite backup")?;
        output.sync_all().context("sync restored SQLite database")?;
        drop(output);

        let restored_info = validate_backup(destination)?;
        ensure!(
            restored_info == source_info,
            "restored SQLite database does not match validated backup"
        );
        Ok(restored_info)
    })();
    if destination_created && result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn sqlite_wal_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push("-wal");
    PathBuf::from(value)
}

fn validate_private_mode(path: &Path, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!("{label} must not be group- or world-readable");
        }
    }
    Ok(())
}

fn ensure_parent_directory(path: &Path) -> Result<()> {
    let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) else {
        return Ok(());
    };
    let mut missing = Vec::<PathBuf>::new();
    let mut current = parent;
    while !current.exists() {
        missing.push(current.to_owned());
        let Some(next) = current
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
        else {
            break;
        };
        if next == current {
            break;
        }
        current = next;
    }
    for directory in missing.into_iter().rev() {
        match fs::create_dir(&directory) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create restore directory {}", directory.display()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Store;
    use tempfile::tempdir;

    #[test]
    fn restore_validates_and_preserves_a_consistent_snapshot() -> Result<()> {
        let directory = tempdir()?;
        let source = directory.path().join("mdm.sqlite");
        let backup = directory.path().join("mdm-backup.sqlite");
        let restored = directory.path().join("restored/mdm.sqlite");
        let store = Store::open(&source)?;
        let enrollment_id = store.create_enrollment("restore-challenge", 1_800_000_000)?;
        store.backup(&backup)?;
        let expected = validate_backup(&backup)?;
        assert_eq!(restore_database(&backup, &restored)?, expected);
        assert_eq!(validate_backup(&restored)?, expected);
        let restored_store = Store::open(&restored)?;
        let restored_enrollments = restored_store.enrollments(None)?;
        assert_eq!(restored_enrollments.len(), 1);
        assert_eq!(restored_enrollments[0].id.as_str(), enrollment_id);
        assert!(restore_database(&backup, &restored).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_public_backup_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir()?;
        let source = directory.path().join("mdm.sqlite");
        let backup = directory.path().join("mdm-backup.sqlite");
        Store::open(&source)?.backup(&backup)?;
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o644))?;
        assert!(validate_backup(&backup).is_err());
        Ok(())
    }

    #[test]
    fn restore_rejects_damaged_and_future_schema_backups() -> Result<()> {
        let directory = tempdir()?;
        let source = directory.path().join("mdm.sqlite");
        let backup = directory.path().join("mdm-backup.sqlite");
        let damaged = directory.path().join("damaged.sqlite");
        let future = directory.path().join("future.sqlite");
        Store::open(&source)?.backup(&backup)?;

        fs::write(&damaged, b"not a sqlite database")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&damaged, fs::Permissions::from_mode(0o600))?;
        }
        assert!(validate_backup(&damaged).is_err());

        fs::copy(&backup, &future)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&future, fs::Permissions::from_mode(0o600))?;
        }
        let future_connection = Connection::open(&future)?;
        future_connection.execute_batch("PRAGMA user_version = 99;")?;
        drop(future_connection);
        assert!(validate_backup(&future).is_err());
        Ok(())
    }

    #[test]
    fn restore_rejects_nonempty_wal_sidecar() -> Result<()> {
        let directory = tempdir()?;
        let source = directory.path().join("mdm.sqlite");
        let backup = directory.path().join("mdm-backup.sqlite");
        Store::open(&source)?.backup(&backup)?;
        fs::write(sqlite_wal_path(&backup), b"uncommitted WAL")?;
        assert!(validate_backup(&backup).is_err());
        Ok(())
    }
}
