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
        crate::utils::script_buf_from_recipient_id(receive_data.recipient_id.clone()).unwrap(),
        Some(script_pubkey.clone())
    );
    // a wallet script is refused
    let own_script = BdkAddress::from_str(&party_recv.get_address())
        .unwrap()
        .assume_checked()
        .script_pubkey()
        .to_hex_string();
    let result = party_recv.wallet.witness_receive_external(
        Some(party_recv.online),
        own_script,
        None,
        Assignment::Any,
        default_rcv_expiration(),
        TRANSPORT_ENDPOINTS.clone(),
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(result, Err(Error::InvalidScript { .. }));

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
}
