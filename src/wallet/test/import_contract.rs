use super::*;

use rgbstd::containers::Contract;
use sea_orm::ConnectionTrait;

fn issue_fixture(schema: AssetSchema, network: BitcoinNetwork) -> ValidContract {
    let seal = BlindSeal::new_random(RgbTxid::from_str(&"01".repeat(32)).unwrap(), 0);
    let terms = ContractTerms {
        text: RicardianContract::default(),
        media: None,
    };
    let builder = ContractBuilder::with(Identity::default(), schema.schema_rules(), network.into());
    let builder = match schema {
        AssetSchema::Bfa => builder
            .add_global_state("ticker", UnicodeTicker::from_str("TEST").unwrap())
            .unwrap()
            .add_global_state("name", Name::from_str("Import test asset").unwrap())
            .unwrap()
            .add_global_state("precision", Precision::try_from(6u8).unwrap())
            .unwrap()
            .add_global_state("terms", terms)
            .unwrap()
            .add_global_state(
                RGB_GLOBAL_BRIDGE_LOCATION,
                BridgeLocation::Evm(EvmContract {
                    chain_id: 31337,
                    address: EvmAddress::from_str("0x1111111111111111111111111111111111111111")
                        .unwrap(),
                }),
            )
            .unwrap()
            .add_rights(RGB_STATE_MINT_RIGHT, seal)
            .unwrap(),
        AssetSchema::Nia => builder
            .add_global_state(
                "spec",
                AssetSpec {
                    ticker: Ticker::from_str("TEST").unwrap(),
                    name: Name::from_str("Import test asset").unwrap(),
                    details: None,
                    precision: Precision::try_from(6u8).unwrap(),
                },
            )
            .unwrap()
            .add_global_state("terms", terms)
            .unwrap()
            .add_global_state(RGB_GLOBAL_ISSUED_SUPPLY, Amount::from(1000u64))
            .unwrap()
            .add_fungible_state(RGB_STATE_ASSET_OWNER, seal, 1000u64)
            .unwrap(),
        AssetSchema::Cfa => builder
            .add_global_state("name", Name::from_str("Import test asset").unwrap())
            .unwrap()
            .add_global_state("precision", Precision::try_from(6u8).unwrap())
            .unwrap()
            .add_global_state("terms", terms)
            .unwrap()
            .add_global_state(RGB_GLOBAL_ISSUED_SUPPLY, Amount::from(1000u64))
            .unwrap()
            .add_fungible_state(RGB_STATE_ASSET_OWNER, seal, 1000u64)
            .unwrap(),
        _ => unreachable!("this fixture only issues BFA, NIA and CFA"),
    };
    builder.issue_contract_raw(1_700_000_000).unwrap()
}

fn save_contract(data_dir: &PrivateDataDir, contract: &Contract) -> String {
    let path = data_dir.sub_path("contract.rgb");
    contract.save_file(&path).unwrap();
    path.to_str().unwrap().to_owned()
}

fn assert_unregistered(wallet: &Wallet, asset_id: &str) {
    assert_matches!(
        wallet.get_asset_metadata(asset_id.to_owned()),
        Err(Error::AssetNotFound { .. })
    );
    let txn = wallet.database().begin_transaction().unwrap();
    assert!(txn.iter_assets().unwrap().is_empty());
    assert!(txn.iter_transfers().unwrap().is_empty());
    assert!(txn.iter_colorings().unwrap().is_empty());
    assert!(txn.get_backup_info().unwrap().is_none());
    assert!(
        wallet
            .rgb_stock(&txn)
            .unwrap()
            .genesis(ContractId::from_str(asset_id).unwrap())
            .is_err()
    );
    txn.commit().unwrap();
}

#[test]
#[parallel]
fn registration_persists_without_creating_funds_or_transfers() {
    for schema in [AssetSchema::Bfa, AssetSchema::Nia, AssetSchema::Cfa] {
        let data_dir = PrivateDataDir::new();
        let mut wallet = data_dir.wallet(true, None);
        let contract = issue_fixture(schema, BitcoinNetwork::Regtest).into_consignment();
        let asset_id = contract.contract_id().to_string();
        let path = save_contract(&data_dir, &contract);
        assert_unregistered(&wallet, &asset_id);

        // The public ID accepts its standard unchunked representation as well.
        let imported = wallet
            .import_contract(path.clone(), Some(asset_id.replace('-', "")))
            .unwrap();
        assert_eq!(imported, asset_id);
        let metadata = wallet.get_asset_metadata(asset_id.clone()).unwrap();
        assert_eq!(metadata.asset_schema, schema);
        assert_eq!(metadata.name, "Import test asset");
        assert_eq!(metadata.precision, 6);
        assert_eq!(metadata.timestamp, 1_700_000_000);
        assert_eq!(
            metadata.initial_supply,
            if schema == AssetSchema::Bfa { 0 } else { 1000 }
        );
        assert_eq!(
            metadata.ticker,
            if schema == AssetSchema::Cfa {
                None
            } else {
                Some("TEST".to_owned())
            }
        );
        assert_eq!(
            wallet.get_asset_balance(asset_id.clone()).unwrap(),
            Balance {
                settled: 0,
                future: 0,
                spendable: 0
            }
        );
        assert!(
            wallet
                .list_transfers(AssetFilter::Id(asset_id.clone()), TransferScope::All)
                .unwrap()
                .is_empty()
        );
        assert!(wallet.backup_info().unwrap());

        let txn = wallet.database().begin_transaction().unwrap();
        let backup_info = txn.get_backup_info().unwrap();
        assert!(txn.iter_colorings().unwrap().is_empty());
        txn.commit().unwrap();
        let wallet_data = wallet.get_wallet_data();
        let keys = wallet.get_keys();
        drop(wallet);

        let mut wallet = Wallet::new(wallet_data, keys).unwrap();
        assert_eq!(
            wallet.get_asset_metadata(asset_id.clone()).unwrap(),
            metadata
        );
        assert_eq!(wallet.import_contract(path, None).unwrap(), asset_id);
        let txn = wallet.database().begin_transaction().unwrap();
        assert_eq!(txn.iter_assets().unwrap().len(), 1);
        assert_eq!(txn.get_backup_info().unwrap(), backup_info);
        assert_eq!(
            wallet
                .rgb_stock(&txn)
                .unwrap()
                .genesis(contract.contract_id())
                .unwrap(),
            contract.genesis
        );
        txn.commit().unwrap();
    }
}

#[test]
#[parallel]
fn issuance_export_is_revalidated_before_registration() {
    let data_dir = PrivateDataDir::new();
    let valid = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest);
    let asset_id = valid.contract_id().to_string();
    let path = data_dir.sub_path("issued.rgb");
    valid.save_file(&path).unwrap();

    // A serialized validation result from another chain cannot authorize this wallet.
    let mut signet = data_dir.wallet_with_net(true, None, BitcoinNetwork::Signet);
    assert_matches!(
        signet.import_contract(path.to_str().unwrap().to_owned(), None),
        Err(Error::ConsignmentValidationFailed { .. })
    );
    assert_unregistered(&signet, &asset_id);

    let mut wallet = data_dir.wallet(true, None);
    assert_eq!(
        wallet
            .import_contract(path.to_str().unwrap().to_owned(), None)
            .unwrap(),
        asset_id
    );
    assert_eq!(
        wallet.get_asset_metadata(asset_id).unwrap().asset_schema,
        AssetSchema::Bfa
    );
}

#[test]
#[parallel]
fn witness_invoice_can_reference_a_registered_contract_offline() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let contract = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest).into_consignment();
    let asset_id = contract.contract_id().to_string();
    wallet
        .import_contract(save_contract(&data_dir, &contract), None)
        .unwrap();

    let receive = wallet
        .witness_receive(
            None,
            Some(asset_id.clone()),
            Assignment::Fungible(1_000_000),
            (now().unix_timestamp() + 86_400) as u64,
            vec![],
            6,
            None,
        )
        .unwrap();
    let invoice = Invoice::new(receive.invoice).unwrap().invoice_data();
    assert_eq!(invoice.asset_id, Some(asset_id.clone()));
    assert_eq!(invoice.asset_schema, Some(AssetSchema::Bfa));
    assert_eq!(invoice.assignment, Assignment::Fungible(1_000_000));
    assert_eq!(invoice.network, BitcoinNetwork::Regtest);
    assert_eq!(wallet.get_asset_balance(asset_id).unwrap().spendable, 0);

    let txn = wallet.database().begin_transaction().unwrap();
    let transfers = txn.iter_transfers().unwrap();
    let backup_info = txn.get_backup_info().unwrap();
    txn.commit().unwrap();
    wallet
        .import_contract(save_contract(&data_dir, &contract), None)
        .unwrap();
    let txn = wallet.database().begin_transaction().unwrap();
    assert_eq!(txn.iter_transfers().unwrap(), transfers);
    assert_eq!(txn.get_backup_info().unwrap(), backup_info);
    txn.commit().unwrap();
}

#[test]
#[parallel]
fn invalid_files_and_asset_ids_leave_no_registration() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let contract = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest).into_consignment();
    let asset_id = contract.contract_id().to_string();
    let path = save_contract(&data_dir, &contract);
    assert_matches!(
        wallet.import_contract(path.clone(), Some("invalid asset ID".to_owned())),
        Err(Error::InvalidContractId { .. })
    );
    let other_id = issue_fixture(AssetSchema::Nia, BitcoinNetwork::Regtest)
        .contract_id()
        .to_string();
    assert_matches!(
        wallet.import_contract(path.clone(), Some(other_id.clone())),
        Err(Error::ContractIdMismatch { expected, actual }) if expected == other_id && actual == asset_id
    );
    assert_unregistered(&wallet, &asset_id);

    fs::write(&path, b"invalid contract").unwrap();
    assert_matches!(
        wallet.import_contract(path.clone(), None),
        Err(Error::InvalidConsignment)
    );
    fs::write(&path, b"RGB\0CON").unwrap();
    assert_matches!(
        wallet.import_contract(path.clone(), None),
        Err(Error::InvalidConsignment)
    );
    fs::remove_file(&path).unwrap();
    assert_matches!(
        wallet.import_contract(path.clone(), None),
        Err(Error::InvalidFilePath { .. })
    );
    assert_unregistered(&wallet, &asset_id);
}

#[test]
#[parallel]
fn wrong_network_and_disabled_schema_leave_no_registration() {
    let data_dir = PrivateDataDir::new();
    let contract = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest).into_consignment();
    let asset_id = contract.contract_id().to_string();
    let path = save_contract(&data_dir, &contract);
    let mut signet = data_dir.wallet_with_net(true, None, BitcoinNetwork::Signet);
    assert_matches!(
        signet.import_contract(path.clone(), None),
        Err(Error::ConsignmentValidationFailed { details }) if details.contains("chain-network")
    );
    assert_unregistered(&signet, &asset_id);

    let mut data = data_dir.wallet_data();
    data.supported_schemas = vec![AssetSchema::Nia];
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let mut wallet = Wallet::new(data, SinglesigKeys::from_keys(&keys, None)).unwrap();
    assert_matches!(
        wallet.import_contract(path.clone(), None),
        Err(Error::UnsupportedSchema {
            asset_schema: AssetSchema::Bfa
        })
    );
    assert_unregistered(&wallet, &asset_id);
}

#[test]
#[parallel]
fn transfer_files_and_contracts_with_history_are_rejected() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let mut contract = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest).into_consignment();
    let asset_id = contract.contract_id().to_string();
    let transfer = RgbTransfer {
        version: contract.version,
        transfer: true,
        genesis: contract.genesis.clone(),
        bundles: Default::default(),
    };
    let path = data_dir.sub_path("transfer.rgb");
    transfer.save_file(&path).unwrap();
    assert_matches!(
        wallet.import_contract(path.to_str().unwrap().to_owned(), None),
        Err(Error::InvalidConsignment)
    );

    contract.bundles.push(WitnessBundle::strict_dumb()).unwrap();
    assert!(
        wallet
            .import_contract(save_contract(&data_dir, &contract), None)
            .is_err()
    );
    assert_unregistered(&wallet, &asset_id);
}

#[test]
#[parallel]
fn known_asset_does_not_bypass_validation_or_trust_a_saved_validation_result() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let valid = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest);
    let mut contract = valid.clone().into_consignment();
    let asset_id = contract.contract_id().to_string();
    wallet
        .import_contract(save_contract(&data_dir, &contract), None)
        .unwrap();

    // The type flag is outside the genesis commitment, so this invalid file retains the ID.
    contract.transfer = true;
    assert_eq!(contract.contract_id(), valid.contract_id());
    let path = save_contract(&data_dir, &contract);
    assert!(
        wallet
            .import_contract(path.clone(), Some(asset_id.clone()))
            .is_err()
    );

    // Attach the original successful validation status to the tampered contract bytes.
    let mut forged = fs::read(&path).unwrap();
    forged[4..7].copy_from_slice(b"VCO");
    forged.extend(serde_json::to_vec(valid.validation_status()).unwrap());
    fs::write(&path, forged).unwrap();
    assert!(
        wallet
            .import_contract(path, Some(asset_id.clone()))
            .is_err()
    );
    assert_eq!(wallet.get_asset_balance(asset_id).unwrap().spendable, 0);
    let txn = wallet.database().begin_transaction().unwrap();
    assert_eq!(txn.iter_assets().unwrap().len(), 1);
    assert!(txn.iter_transfers().unwrap().is_empty());
    txn.commit().unwrap();
}

#[test]
#[parallel]
fn invalid_genesis_is_rejected_before_any_asset_is_registered() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let mut contract = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest).into_consignment();
    contract.genesis.globals = Default::default();
    let asset_id = contract.contract_id().to_string();
    assert_matches!(
        wallet.import_contract(save_contract(&data_dir, &contract), Some(asset_id.clone())),
        Err(Error::ConsignmentValidationFailed { .. })
    );
    assert_unregistered(&wallet, &asset_id);
}

#[test]
#[parallel]
fn failed_backup_update_rolls_back_stock_and_metadata_and_can_be_retried() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let contract = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest).into_consignment();
    let asset_id = contract.contract_id().to_string();
    let path = save_contract(&data_dir, &contract);
    let db_path = wallet.get_wallet_dir().join(RGB_LIB_DB_NAME);
    let connection = block_on(sea_orm::Database::connect(format!(
        "sqlite:{}",
        db_path.display()
    )))
    .unwrap();
    block_on(connection.execute_unprepared(
        "CREATE TRIGGER reject_import_backup BEFORE INSERT ON backup_info \
         BEGIN SELECT RAISE(ABORT, 'injected backup failure'); END",
    ))
    .unwrap();
    assert_matches!(
        wallet.import_contract(path.clone(), None),
        Err(Error::Database { .. })
    );
    assert_unregistered(&wallet, &asset_id);

    block_on(connection.execute_unprepared("DROP TRIGGER reject_import_backup")).unwrap();
    assert_eq!(wallet.import_contract(path, None).unwrap(), asset_id);
    assert!(wallet.backup_info().unwrap());
}

#[test]
#[parallel]
fn registration_completes_metadata_for_a_contract_already_in_stock() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);
    let valid = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest);
    let asset_id = valid.contract_id().to_string();
    let txn = wallet.database().begin_transaction().unwrap();
    wallet
        .rgb_stock(&txn)
        .unwrap()
        .import_contract(valid.clone(), &DumbResolver)
        .unwrap();
    assert!(txn.iter_assets().unwrap().is_empty());
    txn.commit().unwrap();

    let contract = valid.into_consignment();
    assert_eq!(
        wallet
            .import_contract(save_contract(&data_dir, &contract), None)
            .unwrap(),
        asset_id
    );
    assert_eq!(
        wallet
            .get_asset_metadata(asset_id.clone())
            .unwrap()
            .asset_schema,
        AssetSchema::Bfa
    );
    assert_eq!(wallet.get_asset_balance(asset_id).unwrap().spendable, 0);
    assert!(wallet.backup_info().unwrap());
}

#[test]
#[parallel]
fn registration_is_available_to_watch_only_and_multisig_wallets() {
    let data_dir = PrivateDataDir::new();
    let contract = issue_fixture(AssetSchema::Bfa, BitcoinNetwork::Regtest).into_consignment();
    let asset_id = contract.contract_id().to_string();
    let path = save_contract(&data_dir, &contract);
    let mut watch_only = data_dir.wallet(false, None);
    assert!(watch_only.get_keys().mnemonic.is_none());
    assert_eq!(
        watch_only.import_contract(path.clone(), None).unwrap(),
        asset_id
    );
    assert_eq!(
        watch_only
            .get_asset_metadata(asset_id.clone())
            .unwrap()
            .asset_schema,
        AssetSchema::Bfa
    );

    let cosigners = (0..2)
        .map(|_| {
            Cosigner::from_keys(
                &generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot),
                None,
            )
        })
        .collect();
    let mut multisig =
        MultisigWallet::new(data_dir.wallet_data(), MultisigKeys::new(cosigners, 2, 2)).unwrap();
    assert_eq!(multisig.import_contract(path, None).unwrap(), asset_id);
    assert_eq!(
        multisig
            .get_asset_metadata(asset_id.clone())
            .unwrap()
            .asset_schema,
        AssetSchema::Bfa
    );
    assert_eq!(multisig.get_asset_balance(asset_id).unwrap().spendable, 0);
}
