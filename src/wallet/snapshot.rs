//! Transport-independent wallet snapshots. A local archive is not an acknowledged backup.

use super::*;
use crate::wallet::core::RGB_LIB_DB_NAME;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 25_000;

/// An opaque content identity returned by [`RgbWalletOpsOffline::prepare_snapshot`].
///
/// It covers logical SQLite/BDK/RGB/operation state and all nontransient wallet files.
/// It does not contain a clock value, file modification time or cloud version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletSnapshotToken([u8; 32]);

/// A raw ZIP rooted at the wallet fingerprint and its acknowledgement token.
///
/// The archive includes private descriptors and proxy operation keys. Encrypt it before
/// sending it to a remote service; never log it. Creating it does not mark a backup complete.
pub struct WalletSnapshot {
    /// Bounded, unencrypted wallet archive. The caller owns transport and encryption.
    pub data: Vec<u8>,
    /// Pass this unchanged to conditional acknowledgement after confirmed remote commit.
    pub token: WalletSnapshotToken,
}

struct Entry {
    name: String,
    path: PathBuf,
    directory: bool,
}

fn open_file(path: &Path) -> Result<fs::File, Error> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::InvalidSnapshot);
    }
    Ok(file)
}

fn entries(wallet_dir: &Path) -> Result<Vec<Entry>, Error> {
    let root = fs::symlink_metadata(wallet_dir)?;
    if !root.is_dir() || root.file_type().is_symlink() {
        return Err(Error::InvalidSnapshot);
    }
    let parent = wallet_dir.parent().ok_or(Error::InvalidSnapshot)?;
    let mut result = Vec::new();
    let mut total = 0u64;
    let walker = WalkDir::new(wallet_dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            !entry.path().ends_with(RGB_RUNTIME_DELETING_DIR) || !entry.file_type().is_dir()
        });
    for entry in walker {
        let entry = entry.map_err(std::io::Error::from)?;
        let path = entry.path();
        let relative = path
            .strip_prefix(wallet_dir)
            .map_err(|_| Error::InvalidSnapshot)?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
            return Err(Error::InvalidSnapshot);
        }
        if relative == Path::new(LOG_FILE)
            || ["rgb_lib_db-wal", "rgb_lib_db-shm", "rgb_lib_db-journal"]
                .iter()
                .any(|name| relative == Path::new(name))
        {
            continue;
        }
        if relative == Path::new(RGB_LIB_DB_NAME) && !metadata.is_file() {
            return Err(Error::InvalidSnapshot);
        }
        let name = path
            .strip_prefix(parent)
            .map_err(|_| Error::InvalidSnapshot)?
            .to_str()
            .ok_or(Error::InvalidSnapshot)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if name.contains('\\')
            || name.contains('\0')
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(Error::InvalidSnapshot);
        }
        if metadata.is_file() {
            total = total
                .checked_add(metadata.len())
                .ok_or(Error::SnapshotLimitExceeded)?;
            if total > MAX_EXPANDED_BYTES {
                return Err(Error::SnapshotLimitExceeded);
            }
            // A second SQLite database has no coordinated snapshot protocol. Do not silently
            // copy a possibly live database and claim a consistent archive.
            if relative != Path::new(RGB_LIB_DB_NAME) {
                let mut prefix = [0u8; 16];
                let count = open_file(path)?.read(&mut prefix)?;
                if count == 16 && &prefix == b"SQLite format 3\0" {
                    return Err(Error::InvalidSnapshot);
                }
            }
        }
        result.push(Entry {
            name,
            path: path.to_path_buf(),
            directory: metadata.is_dir(),
        });
        if result.len() > MAX_ENTRIES {
            return Err(Error::SnapshotLimitExceeded);
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

fn framed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn content_hash() -> Sha256 {
    let mut hash = Sha256::new();
    framed(&mut hash, b"rgb-lib-wallet-snapshot-v1");
    hash
}

fn entry_header(hash: &mut Sha256, entry: &Entry) {
    framed(hash, entry.name.as_bytes());
    framed(
        hash,
        if entry.directory {
            b"directory"
        } else {
            b"file"
        },
    );
}

pub(super) fn content_digest<W: WalletCore + ?Sized>(
    wallet: &W,
    txn: &DbTxn,
) -> Result<[u8; 32], Error> {
    let mut hash = content_hash();
    txn.snapshot_digest(&mut hash)?;
    for entry in entries(wallet.wallet_dir())? {
        entry_header(&mut hash, &entry);
        if entry.directory || entry.path == wallet.wallet_dir().join(RGB_LIB_DB_NAME) {
            continue;
        }
        let mut file_hash = Sha256::new();
        let mut file = open_file(&entry.path)?;
        let mut buffer = [0u8; 8192];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            file_hash.update(&buffer[..count]);
        }
        framed(&mut hash, &file_hash.finalize());
    }
    Ok(hash.finalize().into())
}

fn current_token<W: WalletCore + ?Sized>(wallet: &W) -> Result<WalletSnapshotToken, Error> {
    let txn = wallet.database().begin_transaction()?;
    let token = WalletSnapshotToken(content_digest(wallet, &txn)?);
    txn.commit()?;
    Ok(token)
}

pub(super) fn prepare<W: WalletCore + ?Sized>(wallet: &mut W) -> Result<WalletSnapshot, Error> {
    let token = current_token(wallet)?;
    let parent = wallet.wallet_dir().parent().ok_or(Error::InvalidSnapshot)?;
    let temporary = tempfile::Builder::new()
        .prefix(".rgb-snapshot-")
        .tempdir_in(parent)?;
    let database = temporary.path().join(RGB_LIB_DB_NAME);
    wallet.database().snapshot_to(&database)?;
    let archive_path = temporary.path().join("snapshot.zip");
    let captured = capture_archive(wallet, &database, &archive_path)?;
    finish_snapshot(wallet, token, captured, &archive_path)
}

/// Digest the standalone database and the exact file bytes streamed into the ZIP.
/// Keeping this separate from final verification lets tests deterministically exercise
/// outside-writer A -> B -> A races without a production mutation callback.
fn capture_archive<W: WalletCore + ?Sized>(
    wallet: &W,
    database: &Path,
    archive_path: &Path,
) -> Result<WalletSnapshotToken, Error> {
    let mut hash = content_hash();
    RgbLibDatabase::snapshot_file_digest(database, &mut hash)?;
    let mut zip = ZipWriter::new(fs::File::create(archive_path)?);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Zstd)
        .unix_permissions(0o600);
    let mut expanded = 0u64;
    for entry in entries(wallet.wallet_dir())? {
        entry_header(&mut hash, &entry);
        if entry.directory {
            zip.add_directory(format!("{}/", entry.name), options.unix_permissions(0o700))
                .map_err(InternalError::from)?;
        } else {
            zip.start_file(&entry.name, options)
                .map_err(InternalError::from)?;
            let is_database = entry.path == wallet.wallet_dir().join(RGB_LIB_DB_NAME);
            let path = if is_database { database } else { &entry.path };
            let mut file = open_file(path)?;
            let mut file_hash = Sha256::new();
            let mut prefix = Vec::with_capacity(16);
            let mut buffer = [0u8; 8192];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                expanded = expanded
                    .checked_add(count as u64)
                    .ok_or(Error::SnapshotLimitExceeded)?;
                if expanded > MAX_EXPANDED_BYTES {
                    return Err(Error::SnapshotLimitExceeded);
                }
                if !is_database {
                    // Recheck the bytes actually captured, not only the earlier stat/open.
                    let remaining = 16 - prefix.len();
                    prefix.extend_from_slice(&buffer[..std::cmp::min(remaining, count)]);
                    if prefix == b"SQLite format 3\0" {
                        return Err(Error::InvalidSnapshot);
                    }
                    file_hash.update(&buffer[..count]);
                }
                zip.write_all(&buffer[..count])?;
            }
            if !is_database {
                framed(&mut hash, &file_hash.finalize());
            }
        }
    }
    let mut archive = zip.finish().map_err(InternalError::from)?;
    archive.flush()?;
    if archive.metadata()?.len() > MAX_ARCHIVE_BYTES {
        return Err(Error::SnapshotLimitExceeded);
    }
    Ok(WalletSnapshotToken(hash.finalize().into()))
}

fn finish_snapshot<W: WalletCore + ?Sized>(
    wallet: &W,
    token: WalletSnapshotToken,
    captured: WalletSnapshotToken,
    archive_path: &Path,
) -> Result<WalletSnapshot, Error> {
    let mut check = ZipArchive::new(fs::File::open(archive_path)?).map_err(InternalError::from)?;
    let mut expanded = 0u64;
    for index in 0..check.len() {
        let entry = check.by_index(index).map_err(InternalError::from)?;
        expanded = expanded
            .checked_add(entry.size())
            .ok_or(Error::SnapshotLimitExceeded)?;
        if expanded > MAX_EXPANDED_BYTES
            || entry.size() > std::cmp::max(entry.compressed_size(), 1).saturating_mul(2000)
        {
            return Err(Error::SnapshotLimitExceeded);
        }
    }
    // Comparing only the two live observations misses A -> B -> A: the archive
    // could contain B while both observations see A. Require the captured content too.
    if captured != token || current_token(wallet)? != token {
        return Err(Error::SnapshotStateChanged);
    }
    Ok(WalletSnapshot {
        data: fs::read(archive_path)?,
        token,
    })
}

pub(super) fn acknowledge<W: WalletBackup + ?Sized>(
    wallet: &mut W,
    token: &WalletSnapshotToken,
) -> Result<bool, Error> {
    let txn = wallet.database().begin_transaction()?;
    if content_digest(wallet, &txn)? != token.0 {
        txn.commit()?;
        return Ok(false);
    }
    wallet.update_backup_info(&txn, true)?;
    let mut info: DbBackupInfoActMod = txn.get_backup_info()?.ok_or(Error::InvalidSnapshot)?.into();
    info.snapshot_digest = ActiveValue::Set(Some(hex::encode(token.0)));
    txn.update_backup_info(&mut info)?;
    txn.commit()?;
    Ok(true)
}

#[cfg(test)]
mod migration_prerequisites {
    use super::*;
    use crate::wallet::test::PrivateDataDir;
    use sea_orm::ConnectionTrait;
    use serial_test::parallel;

    fn execute_sql(wallet: &Wallet, sql: &str) {
        let connection = block_on(Database::connect(format!(
            "sqlite:{}?mode=rw",
            wallet.get_wallet_dir().join(RGB_LIB_DB_NAME).display()
        )))
        .unwrap();
        block_on(connection.execute_unprepared(sql)).unwrap();
        block_on(connection.close()).unwrap();
    }

    #[test]
    #[parallel]
    fn snapshot_rejects_database_aba_even_when_live_before_and_after_match() {
        let directory = PrivateDataDir::new();
        let mut wallet = directory.wallet(false, None);
        wallet.get_address().unwrap();
        execute_sql(
            &wallet,
            "CREATE TABLE snapshot_aba (value TEXT NOT NULL); INSERT INTO snapshot_aba VALUES ('A')",
        );
        let before = current_token(&wallet).unwrap();
        let temporary = tempfile::tempdir_in(directory.path()).unwrap();
        let database = temporary.path().join(RGB_LIB_DB_NAME);
        let archive = temporary.path().join("snapshot.zip");

        // Orchestrate a prohibited second writer exactly across the real capture
        // steps, without thread timing, global state or a production test hook.
        execute_sql(&wallet, "UPDATE snapshot_aba SET value = 'B'");
        wallet.database().snapshot_to(&database).unwrap();
        execute_sql(&wallet, "UPDATE snapshot_aba SET value = 'A'");
        let captured = capture_archive(&wallet, &database, &archive).unwrap();
        assert_eq!(current_token(&wallet).unwrap(), before);
        assert_ne!(captured, before);
        assert!(matches!(
            finish_snapshot(&wallet, before, captured, &archive),
            Err(Error::SnapshotStateChanged)
        ));
        assert!(wallet.backup_info().unwrap());
    }

    #[test]
    #[parallel]
    fn snapshot_rejects_file_aba_and_hashes_the_bytes_actually_archived() {
        let directory = PrivateDataDir::new();
        let mut wallet = directory.wallet(false, None);
        wallet.get_address().unwrap();
        let source = wallet.get_wallet_dir().join("consignment.fixture");
        fs::write(&source, b"A").unwrap();
        let before = current_token(&wallet).unwrap();
        let temporary = tempfile::tempdir_in(directory.path()).unwrap();
        let database = temporary.path().join(RGB_LIB_DB_NAME);
        let archive = temporary.path().join("snapshot.zip");
        wallet.database().snapshot_to(&database).unwrap();

        fs::write(&source, b"B").unwrap();
        let captured = capture_archive(&wallet, &database, &archive).unwrap();
        fs::write(&source, b"A").unwrap();
        let mut zip = ZipArchive::new(fs::File::open(&archive).unwrap()).unwrap();
        let name = format!(
            "{}/consignment.fixture",
            wallet
                .get_wallet_dir()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        );
        let mut bytes = Vec::new();
        zip.by_name(&name).unwrap().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"B");
        assert_eq!(current_token(&wallet).unwrap(), before);
        assert_ne!(captured, before);
        assert!(matches!(
            finish_snapshot(&wallet, before, captured, &archive),
            Err(Error::SnapshotStateChanged)
        ));
        assert!(wallet.backup_info().unwrap());
    }
}
