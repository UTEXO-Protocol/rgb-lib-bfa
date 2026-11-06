use super::*;

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let amount = 69;
    let expiration_secs = 60i64;
    let mut party = get_funded_party!();

    // only mandatory fields
    let bak_info_before = party.db_backup_info();
    let expiration_timestamp = default_rcv_expiration();
    let receive_data = party
        .wallet
        .witness_receive(
            Some(party.online),
            None,
            Assignment::Any,
            expiration_timestamp,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let bak_info_after = party.db_backup_info();
    assert!(bak_info_after.last_operation_timestamp > bak_info_before.last_operation_timestamp);
    assert_eq!(receive_data.expiration_timestamp, expiration_timestamp);
    let decoded_invoice = Invoice::new(receive_data.invoice).unwrap();
    assert_eq!(
        decoded_invoice.invoice_data.network,
        party.get_wallet_data().bitcoin_network
    );
    let transfer = party.get_test_transfer_recipient(&receive_data.recipient_id);
    let (_, batch_transfer) = party.get_test_transfer_related(&transfer);
    assert_eq!(batch_transfer.min_confirmations, MIN_CONFIRMATIONS);

    // asset ID + expiration + 0 min confirmations
    let asset = party.issue_asset_cfa(None, None);
    let asset_id = asset.asset_id;
    let expiration_timestamp = (now().unix_timestamp() + expiration_secs) as u64;
    let min_confirmations = 0;
    let receive_data = party
        .wallet
        .witness_receive(
            Some(party.online),
            Some(asset_id.clone()),
            Assignment::Fungible(amount),
            expiration_timestamp,
            TRANSPORT_ENDPOINTS.clone(),
            min_confirmations,
            None,
        )
        .unwrap();
    assert_eq!(receive_data.expiration_timestamp, expiration_timestamp);
    let transfer = party.get_test_transfer_recipient(&receive_data.recipient_id);
    let (_, batch_transfer) = party.get_test_transfer_related(&transfer);
    assert_eq!(batch_transfer.min_confirmations, min_confirmations);
    let invoice = Invoice::new(receive_data.invoice.clone()).unwrap();
    let invoice_data = invoice.invoice_data();
    assert_eq!(invoice_data.asset_schema, Some(AssetSchema::Cfa));

    // Invoice checks
    let invoice = Invoice::new(receive_data.invoice).unwrap();
    let invoice_data = invoice.invoice_data();
    assert_eq!(invoice_data.recipient_id, receive_data.recipient_id);
    assert_eq!(invoice_data.asset_schema, Some(AssetSchema::Cfa));
    assert_eq!(invoice_data.asset_id, Some(asset_id));
    assert_eq!(invoice_data.assignment, Assignment::Fungible(amount));
    assert_eq!(invoice_data.network, BitcoinNetwork::Regtest);
    assert_eq!(
        invoice_data.expiration_timestamp,
        Some(expiration_timestamp)
    );
    assert_eq!(
        invoice_data.transport_endpoints,
        TRANSPORT_ENDPOINTS.clone()
    );

    // check recipient ID
    let result = RecipientInfo::new(receive_data.recipient_id);
    assert!(result.is_ok());

    // transport endpoints: multiple endpoints
    let transport_endpoints = vec![
        format!("rpc://{}", "127.0.0.1:3000/json-rpc"),
        format!("rpc://{}", "127.0.0.1:3001/json-rpc"),
        format!("rpc://{}", "127.0.0.1:3002/json-rpc"),
    ];
    let result = party.wallet.witness_receive(
        Some(party.online),
        None,
        Assignment::Any,
        default_rcv_expiration(),
        transport_endpoints.clone(),
        MIN_CONFIRMATIONS,
        None,
    );
    assert!(result.is_ok());
    let transfer = party.get_test_transfer_recipient(&result.unwrap().recipient_id);
    let tte_data = party.db_transfer_transport_endpoints_data(transfer.idx);
    assert_eq!(tte_data.len(), transport_endpoints.len());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn schema_assignment_combinations() {
    initialize();

    let mut party = get_funded_party!();
    // more UTXOs to have free allocation slots for the issuances
    party.create_utxos_default();

    check_receive_schema_assignment_combinations(&mut party, Wallet::witness_receive);
}

#[test]
#[parallel]
fn fail() {
    let data_dir = PrivateDataDir::new();
    let mut wallet = data_dir.wallet(true, None);

    // online needed when transport endpoints are provided
    let result = wallet
        .witness_receive(
            None,
            None,
            Assignment::Any,
            (now().unix_timestamp() + 60) as u64,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap_err();
    #[cfg(feature = "_online")]
    assert_matches!(result, Error::OnlineNeeded);
    #[cfg(not(feature = "_online"))]
    assert_matches!(result, Error::Offline);

    // 0 expiration (out-of-band exchange, no online needed)
    let result = wallet
        .witness_receive(
            None,
            None,
            Assignment::Any,
            (now().unix_timestamp() - 1) as u64,
            vec![],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap_err();
    assert_matches!(result, Error::InvalidExpiration);

    // external script: not hex, not an address (OP_TRUE, OP_RETURN, empty, P2TR with an invalid
    // key), a vanilla script and a colored script of the wallet
    let bad_p2tr = format!("5120{}", "ff".repeat(32));
    let vanilla = BdkAddress::from_str(&wallet.get_address().unwrap())
        .unwrap()
        .assume_checked()
        .script_pubkey()
        .to_hex_string();
    let colored = wallet
        .bdk_wallet()
        .peek_address(KeychainKind::External, 0)
        .address
        .script_pubkey()
        .to_hex_string();
    for script in ["zz", "51", "6a", "", &bad_p2tr, &vanilla, &colored] {
        let result = wallet
            .witness_receive_external(
                None,
                script.to_string(),
                None,
                Assignment::Any,
                default_rcv_expiration(),
                vec![],
                MIN_CONFIRMATIONS,
                None,
            )
            .unwrap_err();
        assert_matches!(result, Error::InvalidScript { .. });
    }
}

/// A witness receive on a script the wallet does not own: the transfer settles with the
/// allocation in the stash only, no UTXO or balance, and the allocation can be read on the paid
/// outpoint.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_success() {
    initialize();

    let amount = 66;
    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let mut party_ext = get_empty_party!();
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_id = asset.asset_id.clone();

    // a script of a third wallet stands in for the HTLC lock
    let script_pubkey = BdkAddress::from_str(&party_ext.get_address())
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let receive_data = party_recv
        .wallet
        .witness_receive_external(
            Some(party_recv.online),
            script_pubkey.to_hex_string(),
            None,
            Assignment::Any,
            default_rcv_expiration(),
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    assert_eq!(
        script_buf_from_recipient_id(receive_data.recipient_id.clone()).unwrap(),
        Some(script_pubkey.clone())
    );
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: Some(WitnessData {
                amount_sat: 1000,
                blinding: None,
            }),
            assignment: Assignment::Fungible(amount),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
            public_key: Some(receive_data.public_key.clone()),
            expiration_timestamp: Some(receive_data.expiration_timestamp),
            encryption: Invoice::new(receive_data.invoice.clone())
                .unwrap()
                .invoice_data()
                .encryption,
        }],
    )]);
    let txid = party_send.send(recipient_map, FEE_RATE, None).txid;

    // the invoice names no asset, so the receive is not covered by an asset-filtered refresh
    party_recv.wait_for_refresh(None);
    assert!(party_recv.check_test_transfer_status_recipient(
        &receive_data.recipient_id,
        TransferStatus::WaitingConfirmations
    ));
    party_send.wait_for_refresh(Some(&asset_id));
    mine(false);
    party_recv.wait_for_refresh(None);
    assert!(
        party_recv.check_test_transfer_status_recipient(
            &receive_data.recipient_id,
            TransferStatus::Settled
        )
    );

    // nothing is the wallet's: no UTXO on the witness TX, nothing in the balance
    assert!(
        party_recv
            .list_unspents(false)
            .iter()
            .all(|u| u.utxo.outpoint.txid != txid)
    );
    assert_eq!(
        party_recv.get_asset_balance(&asset_id),
        Balance {
            settled: 0,
            future: 0,
            spendable: 0,
        }
    );
    // the allocation sits in the stash, on the external outpoint
    let transfer = party_recv.get_test_transfer_recipient(&receive_data.recipient_id);
    let Some(RecipientTypeFull::External { vout: Some(vout) }) = transfer.recipient_type else {
        panic!("external recipient with a vout expected");
    };
    let listed = party_recv
        .list_transfers(Some(&asset_id))
        .into_iter()
        .find(|t| t.recipient_id.as_deref() == Some(&receive_data.recipient_id))
        .unwrap();
    assert_eq!(listed.kind, TransferKind::ReceiveWitness);
    assert_eq!(listed.assignments, vec![Assignment::Fungible(amount)]);
    assert_eq!(
        listed.receive_utxo,
        Some(Outpoint {
            txid: txid.clone(),
            vout,
        })
    );
    assert_eq!(
        party_recv
            .wallet
            .contract_assignments_for_outpoints(
                ContractId::from_str(&asset_id).unwrap(),
                vec![Outpoint {
                    txid: txid.clone(),
                    vout,
                }],
            )
            .unwrap(),
        vec![(
            Outpoint {
                txid: txid.clone(),
                vout,
            },
            vec![Assignment::Fungible(amount)]
        )]
    );

    party_send.wait_for_refresh(Some(&asset_id));
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Settled));

    // the allocation can be spent: the lock is colored to a witness receive of the receiver, with
    // the consignment provided out of band and the lock owner signing the input
    let claim = party_recv
        .wallet
        .witness_receive(
            None,
            None,
            Assignment::Any,
            default_rcv_expiration(),
            vec![],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let tx = BdkTransaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&txid).unwrap(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: BdkAmount::from_sat(600),
            script_pubkey: script_buf_from_recipient_id(claim.recipient_id.clone())
                .unwrap()
                .unwrap(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let coloring = ColoringInfo {
        asset_info_map: HashMap::from([(
            ContractId::from_str(&asset_id).unwrap(),
            AssetColoringInfo {
                output_map: HashMap::from([(0, amount)]),
                static_blinding: None,
            },
        )]),
        static_blinding: None,
        nonce: None,
    };
    let transfers = party_recv
        .wallet
        .color_psbt_and_consume(&mut psbt, coloring)
        .unwrap();
    // coloring rebuilds the PSBT around the OP_RETURN output, so the input data goes after it
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: BdkAmount::from_sat(1000),
        script_pubkey,
    });
    let proof_dir = tempfile::tempdir().unwrap();
    let proof = proof_dir.path().join("claim.rgb");
    transfers[0].save_file(&proof).unwrap();
    party_recv
        .wallet
        .provide_out_of_band_consignment(party_recv.online, proof.to_str().unwrap().into(), vec![])
        .unwrap();
    let signed = party_ext
        .wallet
        .sign_psbt(
            psbt.to_string(),
            Some(SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            }),
        )
        .unwrap();
    let claim_tx = Psbt::from_str(&signed).unwrap().extract_tx().unwrap();
    build_indexer(&IndexerConfig::Electrum {
        url: ELECTRUM_URL.to_string(),
    })
    .unwrap()
    .broadcast(&claim_tx)
    .unwrap();
    mine(false);
    party_recv.wait_for_refresh(None);
    assert!(
        party_recv
            .check_test_transfer_status_recipient(&claim.recipient_id, TransferStatus::Settled)
    );
    assert_eq!(party_recv.get_asset_balance(&asset_id).settled, amount);
}

/// An external receive on a script already received on is refused, and one failed or expiring
/// unpaid leaves nothing behind.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_fail() {
    initialize();

    // let the expired receive be failed as soon as its expiration has passed
    MOCK_CLOCK_SKEW_MARGIN.replace(Some(0));

    let mut party = get_funded_party!();
    let mut party_ext = get_empty_party!();
    let receive = |party: &mut SinglesigParty, script: &str, expiration: u64| {
        party.wallet.witness_receive_external(
            Some(party.online),
            script.to_string(),
            None,
            Assignment::Any,
            expiration,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
            None,
        )
    };
    let leftovers = |party: &SinglesigParty| {
        let txn = party.wallet.database().begin_transaction().unwrap();
        let txos = txn.iter_txos().unwrap().len();
        let scripts = txn.iter_pending_witness_scripts().unwrap().len();
        txn.commit().unwrap();
        (txos, scripts)
    };
    let before = leftovers(&party);

    // an unknown contract is the caller's mistake, not a wallet fault
    let unknown = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E";
    let result = party
        .wallet
        .contract_assignments_for_outpoints(ContractId::from_str(unknown).unwrap(), vec![]);
    assert!(matches!(result, Err(Error::AssetNotFound { asset_id }) if asset_id == unknown));

    // a receive failed by fail_transfers leaves nothing behind
    let failed_script = BdkAddress::from_str(&party_ext.get_address())
        .unwrap()
        .assume_checked()
        .script_pubkey()
        .to_hex_string();
    let failed = receive(&mut party, &failed_script, default_rcv_expiration()).unwrap();
    assert!(party.fail_transfers_single(failed.batch_transfer_idx));
    assert!(
        party.check_test_transfer_status_recipient(&failed.recipient_id, TransferStatus::Failed)
    );
    assert_eq!(leftovers(&party), before);

    // a script can be received on once, as the receive files are keyed by recipient ID
    let script = BdkAddress::from_str(&party_ext.get_address())
        .unwrap()
        .assume_checked()
        .script_pubkey()
        .to_hex_string();
    let expiration_secs = 3;
    let receive_data = receive(
        &mut party,
        &script,
        (now().unix_timestamp() + expiration_secs) as u64,
    )
    .unwrap();
    assert_matches!(
        receive(&mut party, &script, default_rcv_expiration()),
        Err(Error::RecipientIDAlreadyUsed)
    );

    // the receive expires unpaid
    std::thread::sleep(std::time::Duration::from_millis(
        expiration_secs as u64 * 1000 + 2000,
    ));
    assert!(party.fail_transfers_all());
    assert!(
        party.check_test_transfer_status_recipient(
            &receive_data.recipient_id,
            TransferStatus::Failed
        )
    );
    assert_eq!(leftovers(&party), before);
    assert!(
        !party
            .wallet
            .get_transfers_dir()
            .join(receive_data.recipient_id.replace(':', "_"))
            .exists()
    );
    assert_matches!(
        receive(&mut party, &script, default_rcv_expiration()),
        Err(Error::RecipientIDAlreadyUsed)
    );
}

/// A wallet script past the BDK lookahead is not detected as the wallet's, so it can be received
/// on as an external script. Once the wallet reveals it, the paid output is a vanilla UTXO, but a
/// vanilla send cannot spend it, which would burn the allocation.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_past_lookahead() {
    initialize();

    let amount = 66;
    let index = 1000;
    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_id = asset.asset_id.clone();

    let script_pubkey = party_recv
        .wallet
        .bdk_wallet()
        .peek_address(KeychainKind::Internal, index)
        .address
        .script_pubkey();
    let receive_data = party_recv
        .wallet
        .witness_receive_external(
            Some(party_recv.online),
            script_pubkey.to_hex_string(),
            None,
            Assignment::Any,
            default_rcv_expiration(),
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: Some(WitnessData {
                amount_sat: 2_500,
                blinding: None,
            }),
            assignment: Assignment::Fungible(amount),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
            public_key: Some(receive_data.public_key.clone()),
            expiration_timestamp: Some(receive_data.expiration_timestamp),
            encryption: Invoice::new(receive_data.invoice.clone())
                .unwrap()
                .invoice_data()
                .encryption,
        }],
    )]);
    let txid = party_send.send(recipient_map, FEE_RATE, None).txid;
    party_recv.wait_for_refresh(None);
    party_send.wait_for_refresh(Some(&asset_id));
    mine(false);
    party_recv.wait_for_refresh(None);
    party_send.wait_for_refresh(Some(&asset_id));
    let transfer = party_recv.get_test_transfer_recipient(&receive_data.recipient_id);
    let Some(RecipientTypeFull::External { vout: Some(vout) }) = transfer.recipient_type else {
        panic!("external recipient with a vout expected");
    };

    // with the vanilla funds drained, the wallet reveals the script: the paid output is then its
    // only vanilla UTXO, but a vanilla send cannot spend it
    party_recv.drain_to(&party_send.get_address());
    mine(false);
    party_recv
        .wallet
        .bdk_wallet_mut()
        .reveal_addresses_to(KeychainKind::Internal, index)
        .last();
    let result = party_recv.send_btc_result(&party_send.get_address(), 500);
    assert_matches!(result, Err(Error::InsufficientBitcoins { .. }));
    let result =
        party_recv
            .wallet
            .create_utxos(party_recv.online, false, Some(1), None, FEE_RATE, false);
    assert_matches!(result, Err(Error::InsufficientBitcoins { .. }));
    assert!(party_recv.wallet.bdk_wallet().list_unspent().any(|o| {
        o.outpoint
            == OutPoint {
                txid: Txid::from_str(&txid).unwrap(),
                vout,
            }
    }));
    assert_eq!(
        party_recv
            .wallet
            .contract_assignments_for_outpoints(
                ContractId::from_str(&asset_id).unwrap(),
                vec![Outpoint {
                    txid: txid.clone(),
                    vout,
                }],
            )
            .unwrap()[0]
            .1,
        vec![Assignment::Fungible(amount)]
    );
}

/// HTLC claim and refund: the lock output on an external script is spent with a prepared sweep,
/// by the receiver (claim) or by the sender (refund), to a witness receive of the spending wallet.
/// a lock on a script of a third wallet, which stands in for the HTLC
#[cfg(feature = "electrum")]
fn lock_on_external_script(
    party_send: &mut SinglesigParty,
    party_recv: &mut SinglesigParty,
    party_ext: &mut SinglesigParty,
    asset_id: &str,
    amount: u64,
    lock_sats: u64,
) -> (OutPoint, ScriptBuf) {
    let lock_script = BdkAddress::from_str(&party_ext.get_address())
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let receive_data = party_recv
        .wallet
        .witness_receive_external(
            Some(party_recv.online),
            lock_script.to_hex_string(),
            None,
            Assignment::Any,
            default_rcv_expiration(),
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let recipient_map = HashMap::from([(
        asset_id.to_string(),
        vec![Recipient {
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: Some(WitnessData {
                amount_sat: lock_sats,
                blinding: None,
            }),
            assignment: Assignment::Fungible(amount),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
            public_key: Some(receive_data.public_key.clone()),
            expiration_timestamp: Some(receive_data.expiration_timestamp),
            encryption: Invoice::new(receive_data.invoice.clone())
                .unwrap()
                .invoice_data()
                .encryption,
        }],
    )]);
    let txid = party_send.send(recipient_map, FEE_RATE, None).txid;
    party_recv.wait_for_refresh(None);
    party_send.wait_for_refresh(Some(asset_id));
    mine(false);
    party_recv.wait_for_refresh(None);
    party_send.wait_for_refresh(Some(asset_id));
    let transfer = party_recv.get_test_transfer_recipient(&receive_data.recipient_id);
    let Some(RecipientTypeFull::External { vout: Some(vout) }) = transfer.recipient_type else {
        panic!("external recipient with a vout expected");
    };
    (
        OutPoint {
            txid: Txid::from_str(&txid).unwrap(),
            vout,
        },
        lock_script,
    )
}

/// an unsigned sweep of the lock to a new witness receive of the spending wallet, with the
/// receive's recipient ID
#[cfg(feature = "electrum")]
fn lock_sweep_psbt(
    party: &mut SinglesigParty,
    lock: &(OutPoint, ScriptBuf),
    lock_sats: u64,
    fee: u64,
) -> (Psbt, String) {
    let receive_data = party
        .wallet
        .witness_receive(
            None,
            None,
            Assignment::Any,
            default_rcv_expiration(),
            vec![],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let to = script_buf_from_recipient_id(receive_data.recipient_id.clone())
        .unwrap()
        .unwrap();
    let tx = BdkTransaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: lock.0,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: BdkAmount::from_sat(lock_sats - fee),
            script_pubkey: to,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: BdkAmount::from_sat(lock_sats),
        script_pubkey: lock.1.clone(),
    });
    (psbt, receive_data.recipient_id)
}

/// prepare a sweep of the lock to a witness receive of the spending wallet, as an HTLC claim or
/// refund would: the PSBT, the prepared sweep and the receive's recipient ID
#[cfg(feature = "electrum")]
fn prepare_lock_sweep(
    party: &mut SinglesigParty,
    lock: &(OutPoint, ScriptBuf),
    lock_sats: u64,
    fee: u64,
    asset_id: &str,
    coloring: &ColoringInfo,
) -> (Psbt, ColorPrepareResult, String) {
    let (mut psbt, recipient_id) = lock_sweep_psbt(party, lock, lock_sats, fee);
    let balance = party.get_asset_balance(asset_id);
    let prepared = party
        .wallet
        .color_psbt_and_prepare_consume(
            &mut psbt,
            coloring.clone(),
            vec![lock.0.into()],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    assert_eq!(prepared.transfers.len(), 1);
    // the lock is not the wallet's allocation: preparing the sweep does not change the balance
    assert_eq!(party.get_asset_balance(asset_id), balance);
    assert!(party.wallet.list_assets(vec![]).is_ok());
    (psbt, prepared, recipient_id)
}

/// provide the sweep consignments out of band (the spender is its own counterparty) and hand the
/// sweep off for signing: its batch
#[cfg(feature = "electrum")]
fn hand_off_sweep(party: &mut SinglesigParty, psbt: &Psbt, prepared: &ColorPrepareResult) -> i32 {
    let proof_dir = tempfile::tempdir().unwrap();
    for (i, transfer) in prepared.transfers.iter().enumerate() {
        let proof = proof_dir.path().join(format!("sweep{i}.rgb"));
        transfer.save_file(&proof).unwrap();
        party
            .wallet
            .provide_out_of_band_consignment(party.online, proof.to_str().unwrap().into(), vec![])
            .unwrap();
    }
    let batch = prepared.batch_transfer_idx;
    party
        .wallet
        .mark_prepared_sweep_handed_off(batch, psbt.unsigned_tx.compute_txid().to_string())
        .unwrap();
    batch
}

/// the sweep projects a transfer row on the same recipient, so look at the incoming batch
#[cfg(feature = "electrum")]
fn incoming_batch(party: &SinglesigParty, recipient_id: &str) -> DbBatchTransfer {
    let txn = party.wallet.database().begin_transaction().unwrap();
    let asset_transfers = txn.iter_asset_transfers().unwrap();
    let batch_transfers = txn.iter_batch_transfers().unwrap();
    let batch = txn
        .iter_transfers()
        .unwrap()
        .into_iter()
        .filter(|t| t.recipient_id.as_deref() == Some(recipient_id))
        .map(|t| t.related_transfers(&asset_transfers, &batch_transfers).1)
        .find(|b| b.incoming)
        .unwrap();
    txn.commit().unwrap();
    batch
}

/// the sweep's phase, batch status and number of reserved TXOs
#[cfg(feature = "electrum")]
fn sweep_state(party: &SinglesigParty, batch: i32) -> (String, TransferStatus, usize) {
    let txn = party.wallet.database().begin_transaction().unwrap();
    let phase = txn.prepared_sweep_read(batch).unwrap().1;
    let status = txn
        .get_batch_transfer_or_fail(batch, &txn.iter_batch_transfers().unwrap())
        .unwrap()
        .status;
    let reservations = txn
        .iter_reserved_txos()
        .unwrap()
        .into_iter()
        .filter(|r| r.reserved_for_colored == Some(batch))
        .count();
    txn.commit().unwrap();
    (phase, status, reservations)
}

/// the lock script owner signs the lock inputs, then the sweep is broadcast, mined and consumed,
/// settling the given receives: (recipient ID, asset ID, amount)
#[cfg(feature = "electrum")]
fn settle_lock_sweep(
    party: &mut SinglesigParty,
    party_ext: &mut SinglesigParty,
    psbt: &Psbt,
    batch: i32,
    receives: &[(&str, &str, u64)],
) {
    let signed = party_ext
        .wallet
        .sign_psbt(
            psbt.to_string(),
            Some(SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            }),
        )
        .unwrap();
    let tx = Psbt::from_str(&signed).unwrap().extract_tx().unwrap();
    let txid = tx.compute_txid().to_string();
    build_indexer(&IndexerConfig::Electrum {
        url: ELECTRUM_URL.to_string(),
    })
    .unwrap()
    .broadcast(&tx)
    .unwrap();
    // the mempool is not enough to consume
    assert!(matches!(
        party.wallet.consume_transfer_fascia(party.online, batch),
        Err(Error::InvalidColoringInfo { details })
            if details == "prepared sweep witness is not sufficiently confirmed"
    ));
    mine_tx(&txid);
    party
        .wallet
        .consume_transfer_fascia(party.online, batch)
        .unwrap();
    assert_eq!(sweep_state(party, batch).1, TransferStatus::Settled);
    let settled = |party: &SinglesigParty| {
        receives
            .iter()
            .all(|(r, _, _)| incoming_batch(party, r).status == TransferStatus::Settled)
    };
    for _ in 0..3 {
        party.wait_for_refresh(None);
        if settled(party) {
            break;
        }
    }
    assert!(settled(party));
    let unspents = party.list_unspents(true);
    for (_, asset_id, amount) in receives {
        assert!(unspents.iter().any(|u| {
            u.utxo.outpoint.txid == txid
                && u.rgb_allocations.iter().any(|a| {
                    a.asset_id.as_deref() == Some(asset_id)
                        && a.assignment == Assignment::Fungible(*amount)
                })
        }));
    }
}

#[cfg(feature = "electrum")]
fn lock_coloring(contract_id: ContractId, amount: u64) -> ColoringInfo {
    ColoringInfo {
        asset_info_map: HashMap::from([(
            contract_id,
            AssetColoringInfo {
                output_map: HashMap::from([(0, amount)]),
                static_blinding: None,
            },
        )]),
        static_blinding: None,
        nonce: None,
    }
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_claim_and_refund() {
    initialize();

    let amount = 66;
    let lock_sats = 1000;
    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let mut party_ext = get_empty_party!();
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_id = asset.asset_id.clone();
    let coloring = lock_coloring(ContractId::from_str(&asset_id).unwrap(), amount);

    let mut locks = vec![];
    for _ in 0..2 {
        locks.push(lock_on_external_script(
            &mut party_send,
            &mut party_recv,
            &mut party_ext,
            &asset_id,
            amount,
            lock_sats,
        ));
    }
    assert_eq!(
        party_send.get_asset_balance(&asset_id).settled,
        AMOUNT - 2 * amount
    );

    let balances = |party_send: &SinglesigParty, party_recv: &SinglesigParty| {
        (
            party_send.get_asset_balance(&asset_id),
            party_recv.get_asset_balance(&asset_id),
        )
    };
    let balance = |amount| Balance {
        settled: amount,
        future: amount,
        spendable: amount,
    };

    // claim by the receiver: the lock counts for neither party before the claim settles
    let (psbt, prepared, receive) = prepare_lock_sweep(
        &mut party_recv,
        &locks[0],
        lock_sats,
        400,
        &asset_id,
        &coloring,
    );
    assert_eq!(
        balances(&party_send, &party_recv),
        (balance(AMOUNT - 2 * amount), balance(0))
    );
    let batch = hand_off_sweep(&mut party_recv, &psbt, &prepared);
    settle_lock_sweep(
        &mut party_recv,
        &mut party_ext,
        &psbt,
        batch,
        &[(&receive, &asset_id, amount)],
    );
    assert_eq!(
        balances(&party_send, &party_recv),
        (balance(AMOUNT - 2 * amount), balance(amount))
    );

    // refund by the sender
    let (psbt, prepared, receive) = prepare_lock_sweep(
        &mut party_send,
        &locks[1],
        lock_sats,
        400,
        &asset_id,
        &coloring,
    );
    assert_eq!(
        balances(&party_send, &party_recv),
        (balance(AMOUNT - 2 * amount), balance(amount))
    );
    let batch = hand_off_sweep(&mut party_send, &psbt, &prepared);
    settle_lock_sweep(
        &mut party_send,
        &mut party_ext,
        &psbt,
        batch,
        &[(&receive, &asset_id, amount)],
    );
    assert_eq!(
        balances(&party_send, &party_recv),
        (balance(AMOUNT - amount), balance(amount))
    );
}

/// one sweep moves the locks of two assets, each to its own receive of the claimer
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_claim_two_assets() {
    initialize();

    let amount = 66;
    let lock_sats = 1000;
    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let mut party_ext = get_empty_party!();
    let assets = [
        party_send.issue_asset_nia(Some(&[AMOUNT])).asset_id,
        party_send.issue_asset_nia(Some(&[AMOUNT])).asset_id,
    ];
    let locks: Vec<_> = assets
        .iter()
        .map(|asset_id| {
            lock_on_external_script(
                &mut party_send,
                &mut party_recv,
                &mut party_ext,
                asset_id,
                amount,
                lock_sats,
            )
        })
        .collect();

    // one receive per asset
    let mut receives = vec![];
    let mut output = vec![];
    for _ in &assets {
        let receive_data = party_recv
            .wallet
            .witness_receive(
                None,
                None,
                Assignment::Any,
                default_rcv_expiration(),
                vec![],
                MIN_CONFIRMATIONS,
                None,
            )
            .unwrap();
        output.push(TxOut {
            value: BdkAmount::from_sat(lock_sats - 400),
            script_pubkey: script_buf_from_recipient_id(receive_data.recipient_id.clone())
                .unwrap()
                .unwrap(),
        });
        receives.push(receive_data.recipient_id);
    }
    let tx = BdkTransaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: locks
            .iter()
            .map(|lock| TxIn {
                previous_output: lock.0,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    for (input, lock) in psbt.inputs.iter_mut().zip(&locks) {
        input.witness_utxo = Some(TxOut {
            value: BdkAmount::from_sat(lock_sats),
            script_pubkey: lock.1.clone(),
        });
    }
    let coloring = ColoringInfo {
        asset_info_map: assets
            .iter()
            .enumerate()
            .map(|(vout, asset_id)| {
                (
                    ContractId::from_str(asset_id).unwrap(),
                    AssetColoringInfo {
                        output_map: HashMap::from([(vout as u32, amount)]),
                        static_blinding: None,
                    },
                )
            })
            .collect(),
        static_blinding: None,
        nonce: None,
    };
    let prepared = party_recv
        .wallet
        .color_psbt_and_prepare_consume(
            &mut psbt,
            coloring,
            locks.iter().map(|lock| lock.0.into()).collect(),
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    assert_eq!(prepared.transfers.len(), 2);
    for asset_id in &assets {
        assert_eq!(party_recv.get_asset_balance(asset_id).future, 0);
        assert_eq!(
            party_send.get_asset_balance(asset_id).future,
            AMOUNT - amount
        );
    }
    let batch = hand_off_sweep(&mut party_recv, &psbt, &prepared);
    settle_lock_sweep(
        &mut party_recv,
        &mut party_ext,
        &psbt,
        batch,
        &[
            (&receives[0], &assets[0], amount),
            (&receives[1], &assets[1], amount),
        ],
    );
    for asset_id in &assets {
        assert_eq!(party_recv.get_asset_balance(asset_id).settled, amount);
        assert_eq!(
            party_send.get_asset_balance(asset_id).settled,
            AMOUNT - amount
        );
    }
}

/// the receiver's handed-off claims lose to the sender's confirmed refunds of the same locks
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_lost_race() {
    initialize();

    let amount = 66;
    let lock_sats = 1000;
    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let mut party_ext = get_empty_party!();
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_id = asset.asset_id.clone();
    let coloring = lock_coloring(ContractId::from_str(&asset_id).unwrap(), amount);

    let mut locks = vec![];
    for _ in 0..2 {
        locks.push(lock_on_external_script(
            &mut party_send,
            &mut party_recv,
            &mut party_ext,
            &asset_id,
            amount,
            lock_sats,
        ));
    }
    let mut claims = vec![];
    for lock in &locks {
        let (psbt, prepared, receive) =
            prepare_lock_sweep(&mut party_recv, lock, lock_sats, 400, &asset_id, &coloring);
        let batch = hand_off_sweep(&mut party_recv, &psbt, &prepared);
        assert_eq!(
            sweep_state(&party_recv, batch),
            ("handed_off".to_string(), TransferStatus::Initiated, 1)
        );
        assert_eq!(
            incoming_batch(&party_recv, &receive).txid,
            Some(psbt.unsigned_tx.compute_txid().to_string())
        );
        claims.push((psbt, batch, receive));
    }
    // the sender refunds the locks and the refunds confirm
    for lock in &locks {
        let (psbt, prepared, receive) =
            prepare_lock_sweep(&mut party_send, lock, lock_sats, 400, &asset_id, &coloring);
        let batch = hand_off_sweep(&mut party_send, &psbt, &prepared);
        settle_lock_sweep(
            &mut party_send,
            &mut party_ext,
            &psbt,
            batch,
            &[(&receive, &asset_id, amount)],
        );
    }
    assert_eq!(party_send.get_asset_balance(&asset_id).settled, AMOUNT);

    // a lost claim is released on consume, the others on refresh
    assert!(
        party_recv
            .wallet
            .consume_transfer_fascia(party_recv.online, claims[1].1)
            .is_err()
    );
    assert_eq!(
        sweep_state(&party_recv, claims[0].1),
        ("handed_off".to_string(), TransferStatus::Initiated, 1)
    );
    party_recv
        .wallet
        .refresh(party_recv.online, None, vec![], false)
        .unwrap();
    for (psbt, batch, receive) in &claims {
        assert_eq!(
            sweep_state(&party_recv, *batch),
            ("cancelled".to_string(), TransferStatus::Failed, 0)
        );
        // the receive already holds the claim consignment, which can never confirm
        assert_eq!(
            incoming_batch(&party_recv, receive).status,
            TransferStatus::Failed
        );
        assert!(matches!(
            party_recv.wallet.sign_psbt(psbt.to_string(), None),
            Err(Error::WrongOperation { .. })
        ));
        assert!(
            party_recv
                .wallet
                .consume_transfer_fascia(party_recv.online, *batch)
                .is_err()
        );
    }
    assert!(party_recv.wallet.list_prepared_sweeps().unwrap().is_empty());
    let balance = party_recv.get_asset_balance(&asset_id);
    assert_eq!((balance.settled, balance.future), (0, 0));
    // the failed receives are deleted, the released sweeps stay as tombstones
    assert!(party_recv.wallet.delete_transfers(None, false).unwrap());
    for (_, batch, _) in &claims {
        assert_eq!(sweep_state(&party_recv, *batch).1, TransferStatus::Failed);
    }
}

/// a handed-off claim paying too low a fee is replaced by one paying a higher fee
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_replace_claim() {
    initialize();

    let amount = 66;
    let lock_sats = 1000;
    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let mut party_ext = get_empty_party!();
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_id = asset.asset_id.clone();
    let coloring = lock_coloring(ContractId::from_str(&asset_id).unwrap(), amount);
    let lock = lock_on_external_script(
        &mut party_send,
        &mut party_recv,
        &mut party_ext,
        &asset_id,
        amount,
        lock_sats,
    );

    // a sweep not handed off yet cannot be replaced, only cancelled
    let (mut first, _) = lock_sweep_psbt(&mut party_recv, &lock, lock_sats, 400);
    let first_batch = party_recv
        .wallet
        .color_psbt_and_prepare_consume(
            &mut first,
            coloring.clone(),
            vec![lock.0.into()],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap()
        .batch_transfer_idx;
    let (mut second, _) = lock_sweep_psbt(&mut party_recv, &lock, lock_sats, 600);
    assert!(matches!(
        party_recv.wallet.color_psbt_and_prepare_consume(
            &mut second,
            coloring.clone(),
            vec![lock.0.into()],
            MIN_CONFIRMATIONS,
            None,
        ),
        Err(Error::InvalidColoringInfo { .. })
    ));
    party_recv
        .wallet
        .cancel_prepared_sweep(first_batch)
        .unwrap();

    // the lock stays reserved by the handed-off claim, its replacement reserves nothing new
    let (psbt_low, low, receive_low) =
        prepare_lock_sweep(&mut party_recv, &lock, lock_sats, 400, &asset_id, &coloring);
    let batch_low = hand_off_sweep(&mut party_recv, &psbt_low, &low);
    let (psbt_high, high, receive_high) =
        prepare_lock_sweep(&mut party_recv, &lock, lock_sats, 600, &asset_id, &coloring);
    let batch_high = hand_off_sweep(&mut party_recv, &psbt_high, &high);
    assert_eq!(
        sweep_state(&party_recv, batch_low),
        ("handed_off".to_string(), TransferStatus::Initiated, 1)
    );
    assert_eq!(
        sweep_state(&party_recv, batch_high),
        ("handed_off".to_string(), TransferStatus::Initiated, 0)
    );

    // the replacement confirms and settles, the replaced claim is released
    settle_lock_sweep(
        &mut party_recv,
        &mut party_ext,
        &psbt_high,
        batch_high,
        &[(&receive_high, &asset_id, amount)],
    );
    assert_eq!(
        sweep_state(&party_recv, batch_low),
        ("cancelled".to_string(), TransferStatus::Failed, 0)
    );
    assert_eq!(
        incoming_batch(&party_recv, &receive_low).status,
        TransferStatus::Failed
    );
    assert!(party_recv.wallet.list_prepared_sweeps().unwrap().is_empty());
    assert_eq!(party_recv.get_asset_balance(&asset_id).settled, amount);
}

/// a send signed before a sweep reserved its inputs cannot be ended
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_end_refuses_sweep_inputs() {
    initialize();

    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_id = asset.asset_id.clone();

    // a dry-run send reserves nothing
    let receive_data = party_recv.blind_receive();
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            public_key: Some(receive_data.public_key.clone()),
            expiration_timestamp: Some(receive_data.expiration_timestamp),
            encryption: Encryption::Optional,
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let send = party_send
        .wallet
        .send_begin(
            party_send.online,
            recipient_map,
            false,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
            Some(PROXY_ENDPOINT.clone()),
            true,
        )
        .unwrap();
    let signed = party_send
        .wallet
        .sign_psbt(send.psbt.clone(), None)
        .unwrap();
    let send_txid = Psbt::from_str(&send.psbt)
        .unwrap()
        .unsigned_tx
        .compute_txid();

    // a sweep of the asset UTXO to a receive of the sender
    let input: OutPoint = party_send
        .list_unspents(false)
        .into_iter()
        .find(|u| {
            u.rgb_allocations
                .iter()
                .any(|a| a.asset_id.as_deref() == Some(&asset_id))
        })
        .unwrap()
        .utxo
        .outpoint
        .into();
    let self_receive = party_send
        .wallet
        .witness_receive(
            None,
            None,
            Assignment::Any,
            default_rcv_expiration(),
            vec![],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let to = script_buf_from_recipient_id(self_receive.recipient_id)
        .unwrap()
        .unwrap();
    let mut builder = party_send.wallet.bdk_wallet_mut().build_tx();
    builder
        .add_utxo(input)
        .unwrap()
        .manually_selected_only()
        .drain_to(to)
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut sweep = builder.finish().unwrap();
    let coloring = lock_coloring(ContractId::from_str(&asset_id).unwrap(), AMOUNT);
    party_send
        .wallet
        .color_psbt_and_prepare_consume(
            &mut sweep,
            coloring,
            vec![input.into()],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    // the send is refused before anything is published
    assert!(matches!(
        party_send.wallet.send_end(party_send.online, signed),
        Err(Error::WrongOperation { .. })
    ));
    let txn = party_send.wallet.database().begin_transaction().unwrap();
    assert!(
        txn.get_batch_transfers_by_txid(&send_txid.to_string())
            .unwrap()
            .is_empty()
    );
    txn.commit().unwrap();
    // nothing reached the proxy: the recipient keeps waiting for the counterparty
    party_recv
        .wallet
        .refresh(party_recv.online, None, vec![], false)
        .unwrap();
    let transfer = party_recv.get_test_transfer_recipient(&receive_data.recipient_id);
    let (transfer_data, _) = party_recv.get_test_transfer_data(&transfer);
    assert_eq!(transfer_data.status, TransferStatus::WaitingCounterparty);
}
