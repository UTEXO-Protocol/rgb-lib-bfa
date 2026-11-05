use super::*;
use std::io::{Cursor, Read};

const DEV_ASSET: &str = "rgb:fbkO6B_i-qyLXa6d-x3sAOaX-cx~vZB9-rxNSUle-9lXBTf8";
const DEV_CONTRACT: &[u8] = include_bytes!("../../../tests/fixtures/dev-bridge-busdt-bfa5.rgb");
const LEGACY_DEV_CONTRACT: &[u8] = include_bytes!("../../../tests/fixtures/dev-bridge-usdt.rgb");

fn contract_path(directory: &PrivateDataDir) -> String {
    let path = directory.sub_path("public-contract.rgb");
    fs::write(&path, DEV_CONTRACT).unwrap();
    path.to_str().unwrap().to_owned()
}

fn execute_sql(wallet: &Wallet, sql: &str) {
    use sea_orm::ConnectionTrait;
    let connection = block_on(Database::connect(format!(
        "sqlite:{}?mode=rw",
        wallet.get_wallet_dir().join("rgb_lib_db").display()
    )))
    .unwrap();
    block_on(connection.execute_unprepared(sql)).unwrap();
    block_on(connection.close()).unwrap();
}

#[test]
#[parallel]
fn legacy_contract_encoding_is_rejected_without_wallet_mutation() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet_with_net(false, None, BitcoinNetwork::Signet);
    let path = directory.sub_path("legacy-contract.rgb");
    fs::write(&path, LEGACY_DEV_CONTRACT).unwrap();
    let pending = wallet.backup_info().unwrap();
    assert!(matches!(
        wallet.import_contract(path.to_string_lossy().into_owned(), None),
        Err(Error::InvalidConsignment)
    ));
    assert!(
        wallet
            .list_assets(vec![AssetSchema::Bfa])
            .unwrap()
            .bfa
            .unwrap()
            .is_empty()
    );
    assert_eq!(wallet.backup_info().unwrap(), pending);
}

#[test]
#[parallel]
fn supplied_contract_registers_without_balance_or_transfer_and_is_idempotent() {
    assert_eq!(
        hex::encode(Sha256::digest(DEV_CONTRACT)),
        "a678ebf73f3a0523b307cd2fe8019a321ac938eaf547c2c65a7ac079948332ce"
    );
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet_with_net(false, None, BitcoinNetwork::Signet);
    let path = contract_path(&directory);
    assert_eq!(
        wallet
            .import_contract(path.clone(), Some(DEV_ASSET.into()))
            .unwrap(),
        DEV_ASSET
    );
    let metadata = wallet.get_asset_metadata(DEV_ASSET.into()).unwrap();
    assert_eq!(metadata.name, "Bridged USDT");
    assert_eq!(metadata.ticker.as_deref(), Some("BUSDT"));
    assert_eq!(metadata.precision, 6);
    assert_eq!(metadata.asset_schema, AssetSchema::Bfa);
    let balance = wallet.get_asset_balance(DEV_ASSET.into()).unwrap();
    assert_eq!(
        (balance.settled, balance.future, balance.spendable),
        (0, 0, 0)
    );
    assert!(
        wallet
            .list_transfers(AssetFilter::AnyOrNone, None)
            .unwrap()
            .is_empty()
    );
    assert!(wallet.backup_info().unwrap());
    let snapshot = wallet.prepare_snapshot().unwrap();
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    assert!(!wallet.backup_info().unwrap());
    assert_eq!(
        wallet
            .import_contract(path, Some(DEV_ASSET.into()))
            .unwrap(),
        DEV_ASSET
    );
    assert!(!wallet.backup_info().unwrap());
    assert_eq!(
        wallet
            .list_assets(vec![AssetSchema::Bfa])
            .unwrap()
            .bfa
            .unwrap()
            .len(),
        1
    );
}

#[test]
#[parallel]
fn contract_rejection_does_not_register_or_change_backup_state() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet_with_net(false, None, BitcoinNetwork::Signet);
    let path = contract_path(&directory);
    assert!(matches!(
        wallet.import_contract(path.clone(), Some("rgb:wrong".into())),
        Err(Error::ContractIdMismatch { .. })
    ));
    assert!(
        wallet
            .list_assets(vec![AssetSchema::Bfa])
            .unwrap()
            .bfa
            .unwrap()
            .is_empty()
    );
    assert!(!wallet.backup_info().unwrap());
    fs::write(&path, &DEV_CONTRACT[..DEV_CONTRACT.len() / 2]).unwrap();
    assert!(wallet.import_contract(path, None).is_err());
    assert!(
        wallet
            .list_assets(vec![AssetSchema::Bfa])
            .unwrap()
            .bfa
            .unwrap()
            .is_empty()
    );
    assert!(!wallet.backup_info().unwrap());
}

#[test]
#[parallel]
fn contract_network_and_schema_are_checked_before_registration() {
    let directory = PrivateDataDir::new();
    let path = contract_path(&directory);
    let mut regtest = directory.wallet(false, None);
    assert!(regtest.import_contract(path.clone(), None).is_err());
    assert!(!regtest.backup_info().unwrap());
    let other = PrivateDataDir::new();
    let keys = generate_keys(BitcoinNetwork::Signet, WitnessVersion::Taproot);
    let mut data = other.wallet_data();
    data.bitcoin_network = BitcoinNetwork::Signet;
    data.supported_schemas = vec![AssetSchema::Nia];
    let mut unsupported =
        Wallet::new(data, SinglesigKeys::from_keys_no_mnemonic(&keys, None)).unwrap();
    assert!(matches!(
        unsupported.import_contract(path, None),
        Err(Error::UnsupportedSchema {
            asset_schema: AssetSchema::Bfa
        })
    ));
    assert!(!unsupported.backup_info().unwrap());
}

#[test]
#[parallel]
fn prepared_snapshot_remains_dirty_until_acknowledged_and_noop_ack_is_stable() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    wallet.get_address().unwrap();
    let snapshot = wallet.prepare_snapshot().unwrap();
    assert!(wallet.backup_info().unwrap());
    // A failed/cancelled transport simply omits acknowledgement; neither a metadata read
    // nor another local snapshot can turn that into a completed backup.
    let second = wallet.prepare_snapshot().unwrap();
    assert_eq!(snapshot.token, second.token);
    assert!(wallet.backup_info().unwrap());
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    assert!(!wallet.backup_info().unwrap());
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    assert!(!wallet.backup_info().unwrap());
    assert_eq!(wallet.prepare_snapshot().unwrap().token, snapshot.token);
}

#[test]
#[parallel]
fn snapshot_rejects_stale_bdk_and_consignment_state() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    let snapshot = wallet.prepare_snapshot().unwrap();
    wallet.get_address().unwrap();
    assert!(!wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    assert!(wallet.backup_info().unwrap());
    let snapshot = wallet.prepare_snapshot().unwrap();
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    let consignment = wallet.get_wallet_dir().join("consignment.fixture");
    fs::write(&consignment, b"public test consignment bytes").unwrap();
    assert!(wallet.backup_info().unwrap());
    assert!(!wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    let newest = wallet.prepare_snapshot().unwrap();
    assert!(wallet.acknowledge_snapshot(&newest.token).unwrap());
    fs::write(consignment, b"different consignment bytes").unwrap();
    assert!(wallet.backup_info().unwrap());
    assert!(!wallet.acknowledge_snapshot(&newest.token).unwrap());
}

#[test]
#[parallel]
fn snapshot_token_is_bound_to_the_wallet_and_tracks_binary_data() {
    let directory = PrivateDataDir::new();
    let other = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    let mut foreign = other.wallet(false, None);
    execute_sql(
        &wallet,
        "CREATE TABLE snapshot_binary_test (value BLOB NOT NULL); INSERT INTO snapshot_binary_test VALUES (X'610062')",
    );
    let snapshot = wallet.prepare_snapshot().unwrap();
    assert!(!foreign.acknowledge_snapshot(&snapshot.token).unwrap());
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    execute_sql(&wallet, "UPDATE snapshot_binary_test SET value = X'610063'");
    assert!(wallet.backup_info().unwrap());
    assert!(!wallet.acknowledge_snapshot(&snapshot.token).unwrap());
}

#[test]
#[parallel]
fn snapshot_rejects_unexpected_real_values_instead_of_rounding_a_generation() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    execute_sql(
        &wallet,
        "CREATE TABLE snapshot_real_test (value REAL NOT NULL); INSERT INTO snapshot_real_test VALUES (1.0000000000000002)",
    );
    assert!(matches!(
        wallet.prepare_snapshot(),
        Err(Error::InvalidSnapshot)
    ));
    execute_sql(
        &wallet,
        "UPDATE snapshot_real_test SET value = 1.0000000000000004",
    );
    assert!(matches!(
        wallet.prepare_snapshot(),
        Err(Error::InvalidSnapshot)
    ));
}

#[test]
#[parallel]
fn snapshot_token_ignores_sqlite_checkpoint_layout_but_contains_wal_state() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    execute_sql(&wallet, "PRAGMA journal_mode=WAL");
    wallet.get_address().unwrap();
    let snapshot = wallet.prepare_snapshot().unwrap();
    execute_sql(&wallet, "PRAGMA wal_checkpoint(TRUNCATE)");
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    assert_eq!(wallet.prepare_snapshot().unwrap().token, snapshot.token);
    assert!(!wallet.backup_info().unwrap());
}

#[test]
#[parallel]
fn snapshot_rejects_oversized_sources_before_reading_them() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    let file = fs::File::create(wallet.get_wallet_dir().join("oversized.fixture")).unwrap();
    file.set_len(512 * 1024 * 1024 + 1).unwrap();
    assert!(matches!(
        wallet.prepare_snapshot(),
        Err(Error::SnapshotLimitExceeded)
    ));
}

#[test]
#[parallel]
fn snapshot_survives_reopen_and_backup_clock_bookkeeping_cannot_hide_changes() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    let wallet_data = wallet.get_wallet_data();
    let keys = wallet.get_keys();
    wallet.get_address().unwrap();
    let snapshot = wallet.prepare_snapshot().unwrap();
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    let txn = wallet.database().begin_transaction().unwrap();
    let mut info: DbBackupInfoActMod = txn.get_backup_info().unwrap().unwrap().into();
    info.last_backup_timestamp = ActiveValue::Set(i128::MAX.to_string());
    info.last_operation_timestamp = ActiveValue::Set("1".into());
    txn.update_backup_info(&mut info).unwrap();
    txn.commit().unwrap();
    assert!(!wallet.backup_info().unwrap());
    drop(wallet);
    let mut reopened = Wallet::new(wallet_data, keys).unwrap();
    assert!(!reopened.backup_info().unwrap());
    assert!(reopened.acknowledge_snapshot(&snapshot.token).unwrap());
    reopened.get_address().unwrap();
    assert!(reopened.backup_info().unwrap());
    assert!(!reopened.acknowledge_snapshot(&snapshot.token).unwrap());
}

#[cfg(feature = "_online")]
#[test]
#[parallel]
fn snapshot_tracks_proxy_operation_secrets_without_dirty_timestamp_update() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    let txn = wallet.database().begin_transaction().unwrap();
    let operation = DbBatchTransferActMod {
        status: ActiveValue::Set(TransferStatus::WaitingCounterparty),
        created_at: ActiveValue::Set(1),
        updated_at: ActiveValue::Set(1),
        min_confirmations: ActiveValue::Set(1),
        incoming: ActiveValue::Set(false),
        operation_secret_key: ActiveValue::Set(Some(vec![1; 32])),
        ..Default::default()
    };
    let index = txn.set_batch_transfer(operation).unwrap();
    txn.commit().unwrap();
    let snapshot = wallet.prepare_snapshot().unwrap();
    assert!(wallet.acknowledge_snapshot(&snapshot.token).unwrap());
    let txn = wallet.database().begin_transaction().unwrap();
    let mut operation: DbBatchTransferActMod = txn
        .get_batch_transfer_or_fail(index, &txn.iter_batch_transfers().unwrap())
        .unwrap()
        .into();
    operation.operation_secret_key = ActiveValue::Set(Some(vec![2; 32]));
    txn.update_batch_transfer(&mut operation).unwrap();
    txn.commit().unwrap();
    assert!(wallet.backup_info().unwrap());
    assert!(!wallet.acknowledge_snapshot(&snapshot.token).unwrap());
}

#[test]
#[parallel]
fn raw_snapshot_is_a_standalone_fingerprint_rooted_database() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    let address = wallet.get_address().unwrap();
    let snapshot = wallet.prepare_snapshot().unwrap();
    let fingerprint = wallet
        .get_wallet_dir()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut zip = zip::ZipArchive::new(Cursor::new(&snapshot.data)).unwrap();
    for i in 0..zip.len() {
        let entry = zip.by_index(i).unwrap();
        let name = entry
            .name()
            .expect("snapshot entry has a valid canonical name");
        assert!(name.starts_with(&format!("{fingerprint}/")));
        assert!(!name.ends_with("-wal"));
        assert!(!name.ends_with("-shm"));
    }
    let mut database = Vec::new();
    zip.by_name(&format!("{fingerprint}/rgb_lib_db"))
        .unwrap()
        .read_to_end(&mut database)
        .unwrap();
    assert!(database.starts_with(b"SQLite format 3\0"));
    // Restore into a disposable directory through our test-only raw extractor, not the
    // public encrypted-file decoder. Production bounded staged admission remains in RLN.
    let restored = PrivateDataDir::new();
    zip.extract(restored.path()).unwrap();
    let mut data = wallet.get_wallet_data();
    data.data_dir = restored.string();
    let mut restored_wallet = Wallet::new(data, wallet.get_keys()).unwrap();
    assert_eq!(
        wallet.get_address().unwrap(),
        restored_wallet.get_address().unwrap()
    );
    assert_ne!(address, restored_wallet.get_address().unwrap());
}

#[cfg(unix)]
#[test]
#[parallel]
fn snapshot_rejects_symlinks_and_unknown_sqlite_sources() {
    let directory = PrivateDataDir::new();
    let mut wallet = directory.wallet(false, None);
    let target = directory.sub_path("outside");
    fs::write(&target, b"public test data").unwrap();
    let link = wallet.get_wallet_dir().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(matches!(
        wallet.prepare_snapshot(),
        Err(Error::InvalidSnapshot)
    ));
    fs::remove_file(link).unwrap();
    fs::write(
        wallet.get_wallet_dir().join("unknown.db"),
        b"SQLite format 3\0extra",
    )
    .unwrap();
    assert!(matches!(
        wallet.prepare_snapshot(),
        Err(Error::InvalidSnapshot)
    ));
}
