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
    use bdk_wallet::bitcoin::{Sequence, TxIn, Witness, absolute::LockTime, transaction::Version};

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
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn external_script_claim_and_refund() {
    use crate::wallet::rust_only::{AssetColoringInfo, ColoringInfo};
    use bdk_wallet::bitcoin::{
        Sequence, TxIn, Txid, Witness, absolute::LockTime, transaction::Version,
    };

    initialize();

    let amount = 66;
    let lock_sats = 1000;
    let mut party_send = get_funded_party!();
    let mut party_recv = get_funded_party!();
    let mut party_ext = get_empty_party!();
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_id = asset.asset_id.clone();
    let contract_id = ContractId::from_str(&asset_id).unwrap();

    // two locks on scripts of a third wallet, which stands in for the HTLC
    let mut locks = vec![];
    for _ in 0..2 {
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
            asset_id.clone(),
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
        party_send.wait_for_refresh(Some(&asset_id));
        mine(false);
        party_recv.wait_for_refresh(None);
        party_send.wait_for_refresh(Some(&asset_id));
        let transfer = party_recv.get_test_transfer_recipient(&receive_data.recipient_id);
        let Some(RecipientTypeFull::External { vout: Some(vout) }) = transfer.recipient_type else {
            panic!("external recipient with a vout expected");
        };
        locks.push((
            OutPoint {
                txid: Txid::from_str(&txid).unwrap(),
                vout,
            },
            lock_script,
        ));
    }
    assert_eq!(
        party_send.get_asset_balance(&asset_id).settled,
        AMOUNT - 2 * amount
    );

    let coloring = ColoringInfo {
        asset_info_map: HashMap::from([(
            contract_id,
            AssetColoringInfo {
                output_map: HashMap::from([(0, amount)]),
                static_blinding: None,
            },
        )]),
        static_blinding: None,
        nonce: None,
    };
    let indexer = build_indexer(&IndexerConfig::Electrum {
        url: ELECTRUM_URL.to_string(),
    })
    .unwrap();
    // the sweep projects a transfer row on the same recipient, so look at the incoming batch
    let incoming_settled = |party: &SinglesigParty, recipient_id: &str| {
        let txn = party.wallet.database().begin_transaction().unwrap();
        let asset_transfers = txn.iter_asset_transfers().unwrap();
        let batch_transfers = txn.iter_batch_transfers().unwrap();
        let settled = txn
            .iter_transfers()
            .unwrap()
            .into_iter()
            .filter(|t| t.recipient_id.as_deref() == Some(recipient_id))
            .map(|t| t.related_transfers(&asset_transfers, &batch_transfers).1)
            .find(|b| b.incoming)
            .unwrap()
            .status
            == TransferStatus::Settled;
        txn.commit().unwrap();
        settled
    };
    // spend a lock to a witness receive of the spending wallet, as an HTLC claim or refund would
    let spend_lock = |party: &mut SinglesigParty, lock: &(OutPoint, ScriptBuf)| {
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
                value: BdkAmount::from_sat(lock_sats - 400),
                script_pubkey: to,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: BdkAmount::from_sat(lock_sats),
            script_pubkey: lock.1.clone(),
        });
        let prepared = party
            .wallet
            .color_psbt_and_prepare_consume(&mut psbt, coloring.clone(), MIN_CONFIRMATIONS, None)
            .unwrap();
        assert_eq!(prepared.transfers.len(), 1);
        // the spender is its own counterparty: the consignment is provided out of band
        let proof_dir = tempfile::tempdir().unwrap();
        let proof = proof_dir.path().join("sweep.rgb");
        prepared.transfers[0].save_file(&proof).unwrap();
        party
            .wallet
            .provide_out_of_band_consignment(party.online, proof.to_str().unwrap().into(), vec![])
            .unwrap();
        let batch = prepared.batch_transfer_idx;
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        party
            .wallet
            .mark_prepared_sweep_handed_off(batch, txid.clone())
            .unwrap();
        // the lock script owner signs the lock input
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
        indexer.broadcast(&tx).unwrap();
        // the mempool is not enough to consume
        assert!(
            party
                .wallet
                .consume_transfer_fascia(party.online, batch)
                .is_err()
        );
        mine_tx(&txid);
        party
            .wallet
            .consume_transfer_fascia(party.online, batch)
            .unwrap();
        let txn = party.wallet.database().begin_transaction().unwrap();
        let status = txn
            .get_batch_transfer_or_fail(batch, &txn.iter_batch_transfers().unwrap())
            .unwrap()
            .status;
        txn.commit().unwrap();
        assert_eq!(status, TransferStatus::Settled);
        for _ in 0..3 {
            party.wait_for_refresh(None);
            if incoming_settled(party, &receive_data.recipient_id) {
                break;
            }
        }
        assert!(incoming_settled(party, &receive_data.recipient_id));
        assert!(party.list_unspents(true).iter().any(|u| {
            u.utxo.outpoint.txid == txid
                && u.rgb_allocations.iter().any(|a| {
                    a.asset_id.as_deref() == Some(&asset_id)
                        && a.assignment == Assignment::Fungible(amount)
                })
        }));
    };

    // claim by the receiver
    spend_lock(&mut party_recv, &locks[0]);
    assert_eq!(party_recv.get_asset_balance(&asset_id).settled, amount);

    // refund by the sender
    spend_lock(&mut party_send, &locks[1]);
    assert_eq!(
        party_send.get_asset_balance(&asset_id).settled,
        AMOUNT - amount
    );
}
