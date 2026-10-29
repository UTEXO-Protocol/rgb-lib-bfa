use super::*;

/// The number of allocations of the link right of the asset with the given ID held by the given
/// party.
#[cfg(feature = "electrum")]
fn link_rights(party: &mut SinglesigParty, asset_id: &str) -> usize {
    party
        .list_unspents(false)
        .iter()
        .flat_map(|u| u.rgb_allocations.iter())
        .filter(|a| {
            a.asset_id.as_deref() == Some(asset_id) && a.assignment == Assignment::LinkRight
        })
        .count()
}

/// A recipient of the link right of the asset with the given ID.
#[cfg(feature = "electrum")]
fn link_right_recipient(receive_data: &ReceiveData) -> Recipient {
    Recipient {
        assignment: Assignment::LinkRight,
        recipient_id: receive_data.recipient_id.clone(),
        public_key: Some(receive_data.public_key.clone()),
        expiration_timestamp: Some(receive_data.expiration_timestamp),
        encryption: Encryption::Optional,
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    }
}

/// An IFA asset can be issued with its link right, which can be sent and then spent by its holder
/// to link the asset to another contract (e.g. one replacing it), as the asset metadata reports.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    // wallets
    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    // the contracts the asset is linked from and to
    let linked_from = party.issue_asset_nia(None).asset_id;
    let linked_to = party.issue_asset_nia(None).asset_id;

    // issue with the link right
    let asset = party
        .wallet
        .issue_asset_ifa(
            TICKER.to_string(),
            NAME.to_string(),
            PRECISION,
            vec![AMOUNT],
            vec![],
            None,
            true,
            Some(linked_from.clone()),
        )
        .unwrap();
    let metadata = party.get_asset_metadata(&asset.asset_id);
    assert_eq!(metadata.linked_from_contract, Some(linked_from.clone()));
    assert_eq!(metadata.linked_to_contract, None);
    assert_eq!(link_rights(&mut party, &asset.asset_id), 1);
    let issuance = party.list_transfers(Some(&asset.asset_id));
    assert!(issuance[0].assignments.contains(&Assignment::LinkRight));

    // send the link right to a receiver not knowing the asset yet
    let receive_data = rcv_party.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![link_right_recipient(&receive_data)],
    )]);
    let txid = party.send_retry(&recipient_map);
    assert!(!txid.is_empty());
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    mine(false);
    rcv_party.wait_for_refresh(Some(&asset.asset_id));
    party.wait_for_refresh(Some(&asset.asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Settled));
    assert_eq!(link_rights(&mut party, &asset.asset_id), 0);
    assert_eq!(link_rights(&mut rcv_party, &asset.asset_id), 1);
    let rcv_transfer = rcv_party
        .list_transfers(Some(&asset.asset_id))
        .into_iter()
        .find(|t| t.kind == TransferKind::ReceiveBlind)
        .unwrap();
    assert_eq!(rcv_transfer.assignments, vec![Assignment::LinkRight]);
    assert_eq!(
        rcv_party
            .get_asset_metadata(&asset.asset_id)
            .linked_from_contract,
        Some(linked_from.clone())
    );

    // the receiver links the asset, spending the link right
    let res = rcv_party
        .wallet
        .link(
            rcv_party.online,
            asset.asset_id.clone(),
            linked_to.clone(),
            FEE_RATE,
            MIN_CONFIRMATIONS,
        )
        .unwrap();
    mine(false);
    assert!(rcv_party.refresh_asset(&asset.asset_id));
    let transfer = rcv_party
        .list_transfers(Some(&asset.asset_id))
        .into_iter()
        .find(|t| t.txid.as_ref() == Some(&res.txid))
        .unwrap();
    assert_eq!(transfer.kind, TransferKind::Link);
    assert_eq!(transfer.status, TransferStatus::Settled);
    assert_eq!(transfer.requested_assignment, Some(Assignment::LinkRight));
    assert_eq!(link_rights(&mut rcv_party, &asset.asset_id), 0);
    let metadata = rcv_party.get_asset_metadata(&asset.asset_id);
    assert_eq!(metadata.linked_from_contract, Some(linked_from));
    assert_eq!(metadata.linked_to_contract, Some(linked_to.clone()));

    // the link consignment proves the link transition, spending the link right
    let inspection = inspect_consignment(
        transfer.consignment_path.clone().unwrap(),
        BundleFilter::Terminals,
    )
    .unwrap();
    let link = inspection
        .witnesses
        .iter()
        .flat_map(|w| w.operations.iter().flat_map(|o| o.transitions.iter()))
        .find(|t| t.r#type == TypeOfTransition::Link)
        .unwrap();
    let inputs: Vec<_> = link.inputs.iter().map(|i| &i.assignment).collect();
    assert_eq!(inputs, vec![&Assignment::LinkRight]);
    assert!(link.outputs.is_empty());
    assert_eq!(
        link.globals,
        vec![TransitionGlobal::LinkedToContract(linked_to)]
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fail() {
    initialize();

    // wallets
    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();
    // more UTXOs to have free allocation slots
    party.create_utxos_default();

    let asset_nia = party.issue_asset_nia(None);
    let asset_no_link = party.issue_asset_ifa(None, None, None);
    let asset = party
        .wallet
        .issue_asset_ifa(
            TICKER.to_string(),
            NAME.to_string(),
            PRECISION,
            vec![AMOUNT],
            vec![],
            None,
            true,
            None,
        )
        .unwrap();
    let link_begin = |party: &mut SinglesigParty, asset_id: &str, linked_to: &str| {
        party.wallet.link_begin(
            party.online,
            asset_id.to_string(),
            linked_to.to_string(),
            FEE_RATE,
            MIN_CONFIRMATIONS,
            true,
        )
    };

    // issuance: invalid contract the asset is linked from
    let result = party.wallet.issue_asset_ifa(
        TICKER.to_string(),
        NAME.to_string(),
        PRECISION,
        vec![AMOUNT],
        vec![],
        None,
        true,
        Some(s!("invalid")),
    );
    assert_matches!(result, Err(Error::InvalidContractId { contract_id }) if contract_id == "invalid");

    // link: schema without a link right
    let result = link_begin(&mut party, &asset_nia.asset_id, &asset.asset_id);
    assert_matches!(
        result,
        Err(Error::UnsupportedLink {
            asset_schema: AssetSchema::Nia
        })
    );
    // link: invalid contract to link to
    let result = link_begin(&mut party, &asset.asset_id, "invalid");
    assert_matches!(result, Err(Error::InvalidContractId { contract_id }) if contract_id == "invalid");
    // link: the asset's own contract
    let result = link_begin(&mut party, &asset.asset_id, &asset.asset_id);
    assert_matches!(result, Err(Error::InvalidContractId { contract_id }) if contract_id == asset.asset_id);
    // link: no link right
    let result = link_begin(&mut party, &asset_no_link.asset_id, &asset_nia.asset_id);
    assert_matches!(result, Err(Error::InsufficientAssignments { .. }));

    // send: the link right to more than one recipient
    let receive_data_1 = rcv_party.blind_receive();
    let receive_data_2 = rcv_party.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![
            link_right_recipient(&receive_data_1),
            link_right_recipient(&receive_data_2),
        ],
    )]);
    let result = party.send_begin_result(&recipient_map);
    assert_matches!(result, Err(Error::InvalidRecipientData { .. }));

    // link: an asset already linked
    party
        .wallet
        .link(
            party.online,
            asset.asset_id.clone(),
            asset_nia.asset_id.clone(),
            FEE_RATE,
            MIN_CONFIRMATIONS,
        )
        .unwrap();
    mine(false);
    assert!(party.refresh_asset(&asset.asset_id));
    let result = link_begin(&mut party, &asset.asset_id, &asset_nia.asset_id);
    assert_matches!(result, Err(Error::InsufficientAssignments { .. }));
}
