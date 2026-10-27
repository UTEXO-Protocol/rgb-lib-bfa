//! Library-owned, durable preparation for externally signed RGB sweeps.
//! No RGB assignment is consumed until an independently resolved, confirmed exact witness exists.
use super::rust_only::ColoringInfo;
use super::*;
use crate::utils::recipient_id_from_script_buf;

const MAX_COMPONENT: usize = 16 * 1024 * 1024;

/// Consignments and the protected batch reserved by a prepared sweep.
pub struct ColorPrepareResult {
    /// Complete consignments, composed before any RGB state is consumed.
    pub transfers: Vec<RgbTransfer>,
    /// Durable protected batch identity, retained across process restarts.
    pub batch_transfer_idx: i32,
}

/// An active sweep recoverable even if its caller's separate receipt write failed.
pub struct PreparedSweep {
    /// Exact colored unsigned PSBT; callers must reuse its transaction and output layout.
    pub psbt: String,
    /// Exact originally prepared consignments.
    pub transfers: Vec<RgbTransfer>,
    /// Protected native batch identity.
    pub batch_transfer_idx: i32,
    /// Once true, cancellation is forbidden: signed copies may exist outside this library.
    pub handed_off: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSweep {
    version: u8,
    psbt: String,
    fascia: Vec<u8>,
    consignments: Vec<(String, Vec<u8>)>,
    beneficiaries: Vec<(String, Vec<SecretSeal>)>,
    min_confirmations: u8,
}

fn invalid(details: impl Into<String>) -> Error {
    Error::InvalidColoringInfo {
        details: details.into(),
    }
}

impl StoredSweep {
    fn decode(payload: &[u8], txid: &str) -> Result<(Self, Psbt, Fascia, Vec<RgbTransfer>), Error> {
        let record: Self = serde_json::from_slice(payload)
            .map_err(|_| invalid("invalid prepared sweep record"))?;
        if record.version != 1
            || record.min_confirmations == 0
            || record.psbt.len() > MAX_COMPONENT
            || record.fascia.len() > MAX_COMPONENT
            || record.consignments.is_empty()
            || record.consignments.len() > 64
        {
            return Err(invalid("invalid prepared sweep bounds"));
        }
        let psbt = Psbt::from_str(&record.psbt)?;
        if psbt.unsigned_tx.compute_txid().to_string() != txid {
            return Err(invalid("prepared sweep transaction identity mismatch"));
        }
        let confined = amplify::confinement::Confined::<Vec<u8>, 0, MAX_COMPONENT>::try_from(
            record.fascia.clone(),
        )
        .map_err(|_| invalid("invalid sweep fascia bounds"))?;
        let fascia = Fascia::from_strict_serialized::<MAX_COMPONENT>(confined)
            .map_err(|_| invalid("invalid prepared sweep fascia"))?;
        if fascia.witness_id().to_string() != txid {
            return Err(invalid("prepared sweep fascia witness mismatch"));
        }
        // Bind the entire decoded fascia to the actual transaction commitment, independently
        // of the journal hash. A self-consistent replacement payload must not substitute proof.
        let entropy = psbt
            .outputs
            .iter()
            .find_map(|output| output.mpc_entropy())
            .ok_or_else(|| invalid("prepared sweep is missing commitment entropy"))?;
        let mut messages = BTreeMap::new();
        for (contract, bundle) in fascia.bundles() {
            bundle
                .check_opid_commitments()
                .map_err(|_| invalid("prepared sweep has invalid transition commitments"))?;
            messages.insert(
                ProtocolId::from(*contract),
                Message::from(bundle.bundle_id()),
            );
        }
        let mut source = MultiSource::with_static_entropy(entropy);
        source.messages = MediumOrdMap::from_checked(messages);
        let commitment = MerkleTree::try_commit(&source)
            .map_err(|_| invalid("invalid sweep MPC commitment"))?
            .commit_id();
        crate::no_wallet::inspection::verify_witness_commitment(
            &fascia.seal_witness().dbc_proof,
            &commitment,
            &psbt.unsigned_tx,
        )?;
        let beneficiaries: BTreeMap<_, _> = record.beneficiaries.iter().cloned().collect();
        if beneficiaries.len() != record.beneficiaries.len()
            || beneficiaries.len() != record.consignments.len()
        {
            return Err(invalid("prepared sweep beneficiary identity mismatch"));
        }
        let mut transfers = Vec::new();
        let mut contracts = BTreeSet::new();
        for (asset, data) in &record.consignments {
            if data.is_empty() || data.len() > MAX_COMPONENT {
                return Err(invalid("invalid prepared consignment bounds"));
            }
            let transfer = RgbTransfer::load(data.as_slice())
                .map_err(|_| invalid("invalid prepared consignment"))?;
            if transfer.contract_id().to_string() != *asset
                || !contracts.insert(transfer.contract_id())
            {
                return Err(invalid("prepared consignment contract mismatch"));
            }
            let contract = transfer.contract_id();
            let expected = fascia
                .bundles()
                .get(&contract)
                .ok_or_else(|| invalid("prepared proof has an unexpected contract"))?;
            let bundle_id = expected.bundle_id();
            let terminals = transfer
                .terminals
                .get(&bundle_id)
                .ok_or_else(|| invalid("prepared proof omits the prepared bundle"))?;
            let seals: BTreeSet<SecretSeal> = terminals
                .into_iter()
                .map(|seal| seal.to_secret_seal())
                .collect();
            let expected_seals: BTreeSet<SecretSeal> = beneficiaries
                .get(asset)
                .ok_or_else(|| invalid("prepared proof has no beneficiaries"))?
                .iter()
                .copied()
                .collect();
            if transfer.terminals.len() != 1 || seals != expected_seals || seals.is_empty() {
                return Err(invalid("prepared proof has different beneficiaries"));
            }
            let matching: Vec<_> = transfer
                .bundled_witnesses()
                .filter(|witness| witness.witness_id().to_string() == txid)
                .collect();
            if matching.len() != 1 || matching[0].bundle.bundle_id() != bundle_id {
                return Err(invalid(
                    "prepared proof belongs to a different witness or bundle",
                ));
            }
            let witness = matching[0];
            let mut unsigned = witness.tx.clone();
            for input in &mut unsigned.input {
                input.witness = Default::default();
            }
            if unsigned != psbt.unsigned_tx {
                return Err(invalid("prepared proof transaction differs from the PSBT"));
            }
            let commitment = witness
                .anchor
                .convolve(contract, bundle_id)
                .map_err(|_| invalid("prepared proof has an invalid anchor"))?;
            crate::no_wallet::inspection::verify_witness_commitment(
                &witness.anchor.dbc_proof,
                &commitment,
                &witness.tx,
            )?;
            let mut canonical = Vec::new();
            transfer.save(&mut canonical)?;
            if canonical != *data {
                return Err(invalid("prepared proof is not canonically encoded"));
            }
            transfers.push(transfer);
        }
        if contracts != fascia.bundles().keys().copied().collect() {
            return Err(invalid("prepared sweep proof set mismatch"));
        }
        Ok((record, psbt, fascia, transfers))
    }
}

fn input_set(psbt: &Psbt) -> HashSet<OutPoint> {
    psbt.unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect()
}

/// Validation ported from rgb-lib v0.3.0-beta.50-bfa / 1b951af0, adapted to transactional stock.
/// Work on a clone, and preserve PSBT maps while inserting the RGB commitment host.
fn unsigned_layout(psbt: &Psbt) -> Result<(Psbt, bool), Error> {
    if psbt.inputs.is_empty()
        || psbt.inputs.len() > 1000
        || psbt.outputs.is_empty()
        || psbt.outputs.len() > 1000
        || psbt.inputs.len() != psbt.unsigned_tx.input.len()
        || psbt.outputs.len() != psbt.unsigned_tx.output.len()
        || input_set(psbt).len() != psbt.inputs.len()
        || psbt.to_string().len() > MAX_COMPONENT
    {
        return Err(invalid("invalid sweep PSBT dimensions or duplicate inputs"));
    }
    let reserved_prefix = |prefix: &[u8]| {
        [
            b"RGB".as_slice(),
            b"MPC".as_slice(),
            b"OPRET".as_slice(),
            b"TAPRET".as_slice(),
        ]
        .contains(&prefix)
    };
    if psbt
        .proprietary
        .keys()
        .any(|key| reserved_prefix(&key.prefix))
        || psbt.outputs.iter().any(|output| {
            output
                .proprietary
                .keys()
                .any(|key| reserved_prefix(&key.prefix))
        })
    {
        return Err(invalid("sweep PSBT already contains RGB commitments"));
    }
    for (index, (input, txin)) in psbt.inputs.iter().zip(&psbt.unsigned_tx.input).enumerate() {
        if !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
            || !txin.script_sig.is_empty()
            || !txin.witness.is_empty()
        {
            return Err(invalid("cannot color an already signed sweep PSBT"));
        }
        if input
            .proprietary
            .keys()
            .any(|key| reserved_prefix(&key.prefix))
        {
            return Err(invalid("sweep input already contains RGB consumers"));
        }
        let witness = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| invalid(format!("sweep input {index} has no witness_utxo")))?;
        if !witness.script_pubkey.is_witness_program() || input.redeem_script.is_some() {
            return Err(invalid("sweep inputs must be native SegWit"));
        }
        if let Some(previous) = &input.non_witness_utxo {
            if previous.compute_txid() != txin.previous_output.txid
                || previous.output.get(txin.previous_output.vout as usize) != Some(witness)
            {
                return Err(invalid("sweep previous output does not match witness_utxo"));
            }
        }
    }
    let mut working = psbt.clone();
    let shift = working
        .unsigned_tx
        .output
        .iter()
        .any(|output| output.script_pubkey.is_p2tr());
    let hosts: Vec<usize> = working
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .filter_map(|(index, output)| output.script_pubkey.is_op_return().then_some(index))
        .collect();
    match hosts.as_slice() {
        [] => {
            let host = TxOut {
                value: BdkAmount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            };
            if shift {
                working.unsigned_tx.output.insert(0, host);
                working.outputs.insert(0, Default::default());
            } else {
                working.unsigned_tx.output.push(host);
                working.outputs.push(Default::default());
            }
        }
        [index] if !shift || *index == 0 => {
            let host = &working.unsigned_tx.output[*index];
            if host.value != BdkAmount::ZERO
                || (host.script_pubkey != ScriptBuf::new_op_return([])
                    && host.script_pubkey != ScriptBuf::new_op_return([0; 32]))
            {
                return Err(invalid("sweep OP_RETURN contains unrelated data"));
            }
        }
        _ => return Err(invalid("sweep needs one OP_RETURN before Taproot outputs")),
    }
    Ok((working, shift))
}

fn receive_scripts(txn: &DbTxn) -> Result<HashSet<String>, Error> {
    let mut scripts: HashSet<String> = txn
        .iter_pending_witness_scripts()?
        .into_iter()
        .map(|row| row.script)
        .collect();
    let batches = txn.iter_batch_transfers()?;
    let assets = txn.iter_asset_transfers()?;
    let incoming: HashSet<i32> = batches
        .iter()
        .filter(|batch| batch.incoming && !batch.status.settled() && !batch.status.failed())
        .map(|batch| batch.idx)
        .collect();
    let incoming_assets: HashSet<i32> = assets
        .iter()
        .filter(|asset| incoming.contains(&asset.batch_transfer_idx))
        .map(|asset| asset.idx)
        .collect();
    for transfer in txn.iter_transfers()? {
        if incoming_assets.contains(&transfer.asset_transfer_idx)
            && matches!(
                transfer.recipient_type,
                Some(RecipientTypeFull::Witness { .. })
            )
        {
            if let Some(recipient) = transfer.recipient_id {
                if let Some(script) = script_buf_from_recipient_id(recipient)? {
                    scripts.insert(script.to_hex_string());
                }
            }
        }
    }
    Ok(scripts)
}

/// A self-receive is a distinct incoming batch, but must not bypass the canonical sweep
/// consume transaction through the generic incoming-transfer acceptance path.
pub(super) fn prepared_sweep_incoming_ready(txn: &DbTxn, txid: &str) -> Result<bool, Error> {
    let Some(batch) = txn.prepared_sweep_batch_by_txid(txid)? else {
        return Ok(true);
    };
    let (stored_txid, phase, payload) = txn.prepared_sweep_read(batch)?;
    StoredSweep::decode(&payload, &stored_txid)?;
    Ok(phase == "consumed")
}

/// Historical consumed witnesses are ordinary transfer history. Only a still active protected
/// witness must not be imported indirectly as an ancestor of a newer incoming consignment.
pub(super) fn prepared_sweep_ancestry_ready(
    txn: &DbTxn,
    consignment: &RgbTransfer,
    current: RgbTxid,
) -> Result<bool, Error> {
    for witness in consignment.bundled_witnesses() {
        if witness.witness_id() != current
            && txn.is_active_prepared_sweep_txid(&witness.witness_id().to_string())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn bind_sweep_receives(
    wallet: &Wallet,
    txn: &DbTxn,
    psbt: &Psbt,
    coloring: &ColoringInfo,
    shift: bool,
) -> Result<(), Error> {
    let stock = wallet.rgb_stock(txn)?;
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let mut payments: HashMap<String, Vec<(String, Assignment)>> = HashMap::new();
    for (contract, info) in &coloring.asset_info_map {
        let schema = AssetSchema::get_from_contract_id(*contract, &stock)?;
        for (vout, amount) in &info.output_map {
            if *amount == 0 {
                continue;
            }
            let output = &psbt.unsigned_tx.output[(*vout + u32::from(shift)) as usize];
            payments
                .entry(output.script_pubkey.to_hex_string())
                .or_default()
                .push((contract.to_string(), output_assignment(schema, *amount)));
        }
    }
    let data = txn.get_db_data(false)?;
    let mut bound_scripts = HashSet::new();
    for batch in &data.batch_transfers {
        if !batch.incoming || batch.status.failed() || batch.status.settled() {
            continue;
        }
        let (asset, transfer) =
            batch.get_incoming_transfer(&data.asset_transfers, &data.transfers)?;
        if !matches!(
            transfer.recipient_type,
            Some(RecipientTypeFull::Witness { .. })
        ) {
            continue;
        }
        let Some(recipient) = transfer.recipient_id.as_ref() else {
            continue;
        };
        let Some(script) = script_buf_from_recipient_id(recipient.clone())? else {
            continue;
        };
        let Some(paid) = payments.get(&script.to_hex_string()) else {
            continue;
        };
        if paid.len() != 1
            || !bound_scripts.insert(script.to_hex_string())
            || batch.status != TransferStatus::WaitingCounterparty
            || !transfer.uses_out_of_band_exchange()
            || asset
                .asset_id
                .as_ref()
                .is_some_and(|asset| asset != &paid[0].0)
            || transfer
                .requested_assignment
                .as_ref()
                .is_some_and(|requested| {
                    !matches!(requested, Assignment::Any | Assignment::Fungible(0))
                        && requested != &paid[0].1
                })
        {
            return Err(invalid(
                "prepared sweep conflicts with a pending self-receive",
            ));
        }
        if let Some(previous) = &batch.txid {
            let can_rebind = match txn.prepared_sweep_batch_by_txid(previous)? {
                Some(previous_batch) => txn.prepared_sweep_read(previous_batch)?.1 == "cancelled",
                None => false,
            };
            if previous != &txid && !can_rebind {
                return Err(invalid(
                    "pending self-receive is already bound to another transfer",
                ));
            }
        }
        let mut update: DbBatchTransferActMod = batch.clone().into();
        update.txid = ActiveValue::Set(Some(txid.clone()));
        txn.update_batch_transfer(&mut update)?;
    }
    Ok(())
}

impl Wallet {
    /// The library's own key path obeys the same explicit handoff boundary as external signers.
    pub(crate) fn guard_prepared_sweep_signing(&self, psbt: &Psbt) -> Result<(), Error> {
        let txn = self.database().begin_transaction()?;
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        if let Some(batch) = txn.prepared_sweep_batch_by_txid(&txid)? {
            let (_, phase, payload) = txn.prepared_sweep_read(batch)?;
            let (_, prepared, _, _) = StoredSweep::decode(&payload, &txid)?;
            if phase != "handed_off" || prepared != *psbt {
                return Err(Error::WrongOperation { txid });
            }
        } else {
            txn.ensure_no_prepared_sweep_mutation(&psbt.unsigned_tx)?;
        }
        txn.commit()
    }

    /// Color and durably reserve an externally signed sweep, without consuming RGB state.
    ///
    /// Output keys use the legacy pre-OP_RETURN indices (Taproot paths shift them by one).
    /// All inputs must be unsigned native SegWit and every owned assignment must be preserved.
    /// The protected batch never expires. Use `None` for expiration and at least one confirmation.
    /// Recover an interrupted caller receipt with [`Self::list_prepared_sweeps`].
    pub fn color_psbt_and_prepare_consume(
        &mut self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<ColorPrepareResult, Error> {
        let txn = self.database().begin_transaction()?;
        let (working, result) = self.prepare_sweep_in_txn(
            &txn,
            psbt,
            coloring_info,
            min_confirmations,
            expiration_timestamp,
        )?;
        txn.commit()?;
        *psbt = working;
        Ok(result)
    }

    fn prepare_sweep_in_txn(
        &self,
        txn: &DbTxn,
        psbt: &Psbt,
        coloring_info: ColoringInfo,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<(Psbt, ColorPrepareResult), Error> {
        if min_confirmations == 0 || expiration_timestamp.is_some() {
            return Err(invalid(
                "prepared sweeps require confirmations and cannot expire",
            ));
        }
        if coloring_info.asset_info_map.is_empty() || coloring_info.asset_info_map.len() > 64 {
            return Err(invalid("invalid prepared sweep contract set"));
        }
        let (mut working, shift) = unsigned_layout(psbt)?;
        let inputs = input_set(&working);
        if txn.prepared_sweep_active_batches()?.len() >= 64 {
            return Err(invalid("too many active prepared sweeps"));
        }
        if txn.iter_reserved_txos()?.iter().any(|reservation| {
            inputs.contains(&OutPoint::from(Outpoint {
                txid: reservation.txid.clone(),
                vout: reservation.vout,
            }))
        }) {
            return Err(invalid("sweep inputs overlap another reserved operation"));
        }
        let stock = self.rgb_stock(&txn)?;
        let assigning: BTreeSet<ContractId> = stock
            .assignments_by_contract(inputs.iter().copied())?
            .into_keys()
            .collect();
        let requested: BTreeSet<ContractId> =
            coloring_info.asset_info_map.keys().copied().collect();
        if assigning != requested {
            return Err(invalid(
                "sweep must include every contract assigned to its inputs",
            ));
        }
        let receives = receive_scripts(&txn)?;
        let mut spent = BTreeMap::new();
        for (contract, coloring) in &coloring_info.asset_info_map {
            let schema = AssetSchema::get_from_contract_id(*contract, &stock)?;
            let mut by_outpoint = HashMap::new();
            let mut available = 0u64;
            for (seal, assignments) in
                stock.contract_assignments_for(*contract, inputs.iter().copied())?
            {
                let mut values = Vec::new();
                for (opout, state) in assignments {
                    if opout.ty != OS_ASSET {
                        return Err(invalid(
                            "sweep cannot destroy inflation, mint or other non-owner rights",
                        ));
                    }
                    let amount = match &state {
                        AllocatedState::Amount(value) => value.as_u64(),
                        AllocatedState::Data(_) if schema == AssetSchema::Uda => 1,
                        _ => return Err(invalid("unsupported sweep assignment")),
                    };
                    available = available
                        .checked_add(amount)
                        .ok_or_else(|| invalid("sweep input amount overflow"))?;
                    values.push(Assignment::from_opout_and_state(opout, &state));
                }
                by_outpoint.insert(seal.to_outpoint(), values);
            }
            let mut total = 0u64;
            for (index, amount) in &coloring.output_map {
                if *amount == 0 {
                    continue;
                }
                let vout = index
                    .checked_add(u32::from(shift))
                    .ok_or_else(|| invalid("sweep output index overflow"))?;
                let output = working
                    .unsigned_tx
                    .output
                    .get(vout as usize)
                    .ok_or_else(|| invalid("sweep output index outside transaction"))?;
                if output.script_pubkey.is_op_return() {
                    return Err(invalid("sweep assigns assets to OP_RETURN"));
                }
                AddressPayload::from_script(&output.script_pubkey)
                    .map_err(|_| invalid("sweep output must pay a standard script"))?;
                if self
                    .bdk_wallet()
                    .derivation_of_spk(output.script_pubkey.clone())
                    .is_some_and(|(keychain, _)| keychain == KeychainKind::Internal)
                    && !receives.contains(&output.script_pubkey.to_hex_string())
                {
                    return Err(invalid(
                        "sweep cannot assign assets to a vanilla wallet output",
                    ));
                }
                total = total
                    .checked_add(*amount)
                    .ok_or_else(|| invalid("sweep output amount overflow"))?;
            }
            if available == 0 || total != available || (schema == AssetSchema::Uda && total != 1) {
                return Err(invalid(
                    "sweep must preserve every input assignment exactly",
                ));
            }
            spent.insert(*contract, by_outpoint);
        }
        for (input, txin) in working.inputs.iter().zip(&working.unsigned_tx.input) {
            if let Some(local) = self.bdk_wallet().get_utxo(txin.previous_output) {
                if Some(&local.txout) != input.witness_utxo.as_ref() {
                    return Err(invalid("sweep witness_utxo differs from the wallet input"));
                }
            }
        }
        // The commitment host is already inserted, so color_psbt cannot rebuild/erase PSBT maps.
        let (fascia, beneficiaries) =
            self.color_psbt_in_txn(txn, &mut working, coloring_info.clone())?;
        let txid = working.unsigned_tx.compute_txid().to_string();
        let mut stock = self.rgb_stock(&txn)?;
        let mut transfers = Vec::new();
        let mut serialized = Vec::new();
        for (contract, seals) in &beneficiaries {
            let (witness, blinded): (Vec<_>, Vec<_>) = seals
                .iter()
                .partition(|seal| matches!(seal, BuilderSeal::Revealed(_)));
            let witness: Vec<_> = witness
                .into_iter()
                .map(|seal| match seal {
                    BuilderSeal::Revealed(seal) => {
                        ExplicitSeal::with(fascia.witness_id(), seal.vout)
                    }
                    _ => unreachable!(),
                })
                .collect();
            let blinded: Vec<_> = blinded
                .into_iter()
                .map(|seal| match seal {
                    BuilderSeal::Concealed(seal) => SecretSeal::from(*seal),
                    _ => unreachable!(),
                })
                .collect();
            let (transfer, proofs) = stock.transfer_from_fascia(
                *contract,
                witness,
                blinded,
                [],
                &fascia,
                self.spv_resolver(),
            )?;
            stock.store_spv_proofs(proofs)?;
            let mut bytes = Vec::new();
            transfer.save(&mut bytes)?;
            if bytes.len() > MAX_COMPONENT {
                return Err(invalid("sweep consignment exceeds limit"));
            }
            serialized.push((contract.to_string(), bytes));
            transfers.push(transfer);
        }
        let batch = txn.set_batch_transfer(DbBatchTransferActMod {
            txid: ActiveValue::Set(Some(txid.clone())),
            status: ActiveValue::Set(TransferStatus::Initiated),
            created_at: ActiveValue::Set(now().unix_timestamp()),
            min_confirmations: ActiveValue::Set(min_confirmations),
            incoming: ActiveValue::Set(false),
            ..Default::default()
        })?;
        self.reserve_colored_txos(&txn, &working, batch)?;
        persist_projection(
            self,
            &txn,
            batch,
            &working,
            &coloring_info,
            shift,
            &spent,
            &receives,
        )?;
        let fascia = fascia
            .to_strict_serialized::<MAX_COMPONENT>()
            .map_err(|_| invalid("sweep fascia exceeds limit"))?
            .to_vec();
        let payload = serde_json::to_vec(&StoredSweep {
            version: 1,
            psbt: working.to_string(),
            fascia,
            consignments: serialized,
            beneficiaries: beneficiaries
                .iter()
                .map(|(contract, seals)| {
                    (
                        contract.to_string(),
                        seals.iter().map(|seal| seal.to_secret_seal()).collect(),
                    )
                })
                .collect(),
            min_confirmations,
        })
        .map_err(InternalError::from)?;
        txn.prepared_sweep_insert(batch, &txid, payload)?;
        // Protect matching receives before any handoff/signing. Their status and balance remain
        // unchanged; a later out-of-band provide still performs normal proof admission.
        bind_sweep_receives(self, txn, &working, &coloring_info, shift)?;
        self.update_backup_info(&txn, false)?;
        Ok((
            working,
            ColorPrepareResult {
                transfers,
                batch_transfer_idx: batch,
            },
        ))
    }

    /// Recover active native preparations, including one orphaned before a caller's receipt write.
    pub fn list_prepared_sweeps(&self) -> Result<Vec<PreparedSweep>, Error> {
        let txn = self.database().begin_transaction()?;
        let mut sweeps = Vec::new();
        for batch in txn.prepared_sweep_active_batches()? {
            let (txid, phase, payload) = txn.prepared_sweep_read(batch)?;
            let (stored, _, _, transfers) = StoredSweep::decode(&payload, &txid)?;
            sweeps.push(PreparedSweep {
                psbt: stored.psbt,
                transfers,
                batch_transfer_idx: batch,
                handed_off: phase == "handed_off",
            });
        }
        txn.commit()?;
        Ok(sweeps)
    }

    /// Persist before ANY signing or handoff to LDK. Once handed off, cancellation is forbidden.
    pub fn mark_prepared_sweep_handed_off(
        &mut self,
        batch: i32,
        expected_txid: String,
    ) -> Result<(), Error> {
        let txn = self.database().begin_transaction()?;
        let (txid, phase, payload) = txn.prepared_sweep_read(batch)?;
        StoredSweep::decode(&payload, &txid)?;
        if txid != expected_txid {
            return Err(invalid("sweep handoff transaction mismatch"));
        }
        match phase.as_str() {
            "prepared" => {
                txn.prepared_sweep_phase(batch, "prepared", "handed_off")?;
                self.update_backup_info(&txn, false)?;
            }
            "handed_off" => {}
            _ => return Err(invalid("sweep cannot be handed off in its terminal phase")),
        }
        txn.commit()
    }

    /// Cancel only a preparation that has never been handed to an external signer or LDK.
    pub fn cancel_prepared_sweep(&mut self, batch: i32) -> Result<(), Error> {
        let txn = self.database().begin_transaction()?;
        let (txid, phase, payload) = txn.prepared_sweep_read(batch)?;
        StoredSweep::decode(&payload, &txid)?;
        if phase == "cancelled" {
            txn.commit()?;
            return Ok(());
        }
        if phase != "prepared" {
            return Err(Error::CannotFailBatchTransfer);
        }
        let transfer = txn.get_batch_transfer_or_fail(batch, &txn.iter_batch_transfers()?)?;
        if transfer.status != TransferStatus::Initiated {
            return Err(Error::CannotFailBatchTransfer);
        }
        let mut transfer: DbBatchTransferActMod = transfer.into();
        transfer.status = ActiveValue::Set(TransferStatus::Failed);
        txn.update_batch_transfer(&mut transfer)?;
        txn.del_reserved_txos_for_batch_transfer(batch)?;
        txn.prepared_sweep_phase(batch, "prepared", "cancelled")?;
        self.update_backup_info(&txn, false)?;
        txn.commit()
    }

    /// Consume only after independently resolving the exact transaction with the required confirmations.
    /// Stock, input state, batch status, reservations and consumed phase commit atomically.
    pub fn consume_transfer_fascia(&mut self, online: Online, batch: i32) -> Result<(), Error> {
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let (txid, phase, payload) = txn.prepared_sweep_read(batch)?;
        let (stored, psbt, mut fascia, _) = StoredSweep::decode(&payload, &txid)?;
        txn.commit()?;
        if phase != "handed_off" && phase != "consumed" {
            return Err(invalid("sweep has not been handed off"));
        }
        if self.indexer().get_tx_confirmations(&txid)?.unwrap_or(0)
            < u64::from(stored.min_confirmations)
        {
            return Err(invalid(
                "prepared sweep witness is not sufficiently confirmed",
            ));
        }
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let (transaction, position) = match self
            .blockchain_resolver()
            .resolve_witness(witness_id)
            .map_err(|error| Error::Network {
            details: error.to_string(),
        })? {
            WitnessStatus::Resolved(transaction, WitnessOrd::Mined(position)) => {
                (transaction, position)
            }
            _ => return Err(invalid("prepared sweep witness is not confirmed")),
        };
        let mut unsigned = transaction.clone();
        for input in &mut unsigned.input {
            input.witness = Default::default();
        }
        if unsigned != psbt.unsigned_tx {
            return Err(invalid(
                "confirmed sweep differs from its prepared transaction",
            ));
        }
        fascia.update_witness_tx(transaction);
        let txn = self.database().begin_transaction()?;
        let (current_txid, current_phase, current_payload) = txn.prepared_sweep_read(batch)?;
        if current_txid != txid || current_payload != payload {
            return Err(invalid("prepared sweep changed during confirmation check"));
        }
        if current_phase == "consumed" {
            txn.commit()?;
            return Ok(());
        }
        if current_phase != "handed_off" {
            return Err(invalid(
                "prepared sweep phase changed during confirmation check",
            ));
        }
        let transfer = txn.get_batch_transfer_or_fail(batch, &txn.iter_batch_transfers()?)?;
        if transfer.status != TransferStatus::Initiated {
            return Err(invalid("prepared sweep batch status mismatch"));
        }
        self.rgb_stock(&txn)?
            .consume_fascia(fascia, Some(WitnessOrd::Mined(position)))?;
        for input in &psbt.unsigned_tx.input {
            let outpoint = Outpoint::from(input.previous_output);
            if let Some(row) = txn.get_txo(&outpoint)? {
                let mut row: DbTxoActMod = row.into();
                row.spent = ActiveValue::Set(true);
                txn.update_txo(row)?;
            }
        }
        let mut transfer: DbBatchTransferActMod = transfer.into();
        transfer.status = ActiveValue::Set(TransferStatus::Settled);
        txn.update_batch_transfer(&mut transfer)?;
        txn.del_reserved_txos_for_batch_transfer(batch)?;
        txn.prepared_sweep_phase(batch, "handed_off", "consumed")?;
        self.update_backup_info(&txn, false)?;
        txn.commit()
    }
}

fn output_assignment(schema: AssetSchema, amount: u64) -> Assignment {
    if schema == AssetSchema::Uda {
        Assignment::NonFungible
    } else {
        Assignment::Fungible(amount)
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_projection(
    wallet: &Wallet,
    txn: &DbTxn,
    batch: i32,
    psbt: &Psbt,
    coloring: &ColoringInfo,
    shift: bool,
    spent: &BTreeMap<ContractId, HashMap<OutPoint, Vec<Assignment>>>,
    receives: &HashSet<String>,
) -> Result<(), Error> {
    let stock = wallet.rgb_stock(txn)?;
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    for (contract, inputs) in spent {
        let schema = AssetSchema::get_from_contract_id(*contract, &stock)?;
        let asset = txn.set_asset_transfer(DbAssetTransferActMod {
            batch_transfer_idx: ActiveValue::Set(batch),
            asset_id: ActiveValue::Set(Some(contract.to_string())),
            user_driven: ActiveValue::Set(true),
            transition_type: ActiveValue::Set(Some(TypeOfTransition::Transfer)),
            ..Default::default()
        })?;
        for (outpoint, assignments) in inputs {
            if let Some(txo) = txn.get_txo(&Outpoint::from(*outpoint))? {
                for assignment in assignments {
                    txn.set_coloring(DbColoringActMod {
                        asset_transfer_idx: ActiveValue::Set(asset),
                        txo_idx: ActiveValue::Set(txo.idx),
                        r#type: ActiveValue::Set(ColoringType::Input),
                        assignment: ActiveValue::Set(assignment.clone()),
                        ..Default::default()
                    })?;
                }
            } else if wallet.bdk_wallet().get_utxo(*outpoint).is_some() {
                return Err(invalid("wallet sweep input is missing its colored TXO row"));
            }
        }
        for (index, amount) in &coloring.asset_info_map[contract].output_map {
            if *amount == 0 {
                continue;
            }
            let vout = index
                .checked_add(u32::from(shift))
                .ok_or_else(|| invalid("sweep output index overflow"))?;
            let output = psbt
                .unsigned_tx
                .output
                .get(vout as usize)
                .ok_or_else(|| invalid("invalid sweep projection vout"))?;
            AddressPayload::from_script(&output.script_pubkey)
                .map_err(|_| invalid("sweep output must pay a standard script"))?;
            let recipient = recipient_id_from_script_buf(
                output.script_pubkey.clone(),
                wallet.bitcoin_network(),
            );
            let owned = wallet
                .bdk_wallet()
                .derivation_of_spk(output.script_pubkey.clone())
                .is_some_and(|(keychain, _)| keychain == KeychainKind::External);
            if owned && !receives.contains(&output.script_pubkey.to_hex_string()) {
                let outpoint = Outpoint {
                    txid: txid.clone(),
                    vout,
                };
                let txo = match txn.get_txo(&outpoint)? {
                    Some(row) => row.idx,
                    None => txn.set_txo(DbTxoActMod {
                        txid: ActiveValue::Set(txid.clone()),
                        vout: ActiveValue::Set(vout),
                        btc_amount: ActiveValue::Set(output.value.to_sat().to_string()),
                        spent: ActiveValue::Set(false),
                        exists: ActiveValue::Set(false),
                        pending_witness: ActiveValue::Set(false),
                        ..Default::default()
                    })?,
                };
                txn.set_coloring(DbColoringActMod {
                    asset_transfer_idx: ActiveValue::Set(asset),
                    txo_idx: ActiveValue::Set(txo),
                    r#type: ActiveValue::Set(ColoringType::Change),
                    assignment: ActiveValue::Set(output_assignment(schema, *amount)),
                    ..Default::default()
                })?;
            }
            txn.set_transfer(DbTransferActMod {
                asset_transfer_idx: ActiveValue::Set(asset),
                requested_assignment: ActiveValue::Set(Some(output_assignment(schema, *amount))),
                recipient_id: ActiveValue::Set(Some(recipient)),
                recipient_type: ActiveValue::Set(Some(RecipientTypeFull::Witness {
                    vout: Some(vout),
                })),
                ..Default::default()
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{Sequence, TxIn, Witness, absolute::LockTime, transaction::Version};
    use serial_test::parallel;

    fn unsigned() -> Psbt {
        let script = ScriptBuf::from_bytes([vec![0x51, 0x20], vec![1; 32]].concat());
        let mut psbt = Psbt::from_unsigned_tx(BdkTransaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(&"01".repeat(32)).unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: BdkAmount::from_sat(9000),
                script_pubkey: script.clone(),
            }],
        })
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: BdkAmount::from_sat(10000),
            script_pubkey: script,
        });
        psbt
    }

    #[test]
    #[parallel]
    fn prepared_sweep_layout_preserves_maps_and_never_mutates_on_error() {
        let mut psbt = unsigned();
        psbt.inputs[0].proprietary.insert(
            bdk_wallet::bitcoin::psbt::raw::ProprietaryKey {
                prefix: b"application".to_vec(),
                subtype: 1,
                key: vec![2],
            },
            vec![3],
        );
        psbt.outputs[0].proprietary.insert(
            bdk_wallet::bitcoin::psbt::raw::ProprietaryKey {
                prefix: b"application".to_vec(),
                subtype: 4,
                key: vec![5],
            },
            vec![6],
        );
        let before = psbt.clone();
        let (prepared, shift) = unsigned_layout(&psbt).unwrap();
        assert!(shift);
        assert_eq!(psbt, before);
        assert_eq!(prepared.inputs, before.inputs);
        assert_eq!(prepared.outputs[1], before.outputs[0]);
        assert_eq!(prepared.proprietary, before.proprietary);
        assert!(prepared.unsigned_tx.output[0].script_pubkey.is_op_return());
    }

    #[test]
    #[parallel]
    fn prepared_sweep_rejects_signed_legacy_duplicate_and_precolored_inputs() {
        let base = unsigned();
        for case in 0..6 {
            let mut psbt = base.clone();
            match case {
                0 => psbt.inputs[0].final_script_witness = Some(Witness::new()),
                1 => psbt.inputs[0].redeem_script = Some(ScriptBuf::new()),
                2 => psbt.inputs[0].witness_utxo = None,
                3 => {
                    psbt.inputs.push(psbt.inputs[0].clone());
                    psbt.unsigned_tx
                        .input
                        .push(psbt.unsigned_tx.input[0].clone());
                }
                4 => {
                    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = ScriptBuf::new();
                }
                5 => {
                    psbt.inputs[0].proprietary.insert(
                        bdk_wallet::bitcoin::psbt::raw::ProprietaryKey {
                            prefix: b"RGB".to_vec(),
                            subtype: 1,
                            key: vec![],
                        },
                        vec![1],
                    );
                }
                _ => unreachable!(),
            }
            let before = psbt.clone();
            assert!(unsigned_layout(&psbt).is_err());
            assert_eq!(psbt, before);
        }
    }

    #[test]
    #[parallel]
    fn prepared_sweep_rejects_ambiguous_opreturn_hosts() {
        for case in 0..3 {
            let mut psbt = unsigned();
            let script = if case == 0 {
                ScriptBuf::new_op_return([7])
            } else {
                ScriptBuf::new_op_return([])
            };
            let host = TxOut {
                value: BdkAmount::ZERO,
                script_pubkey: script,
            };
            if case < 2 {
                psbt.unsigned_tx.output.push(host);
                psbt.outputs.push(Default::default());
            } else {
                psbt.unsigned_tx.output.insert(0, host.clone());
                psbt.outputs.insert(0, Default::default());
                psbt.unsigned_tx.output.push(host);
                psbt.outputs.push(Default::default());
            }
            assert!(unsigned_layout(&psbt).is_err());
        }
    }

    #[test]
    #[parallel]
    fn prepared_sweep_journal_is_bounded_digest_checked_and_phase_conditional() {
        let directory = crate::wallet::test::PrivateDataDir::new();
        let wallet = directory.wallet(false, None);
        let txn = wallet.database().begin_transaction().unwrap();
        let batch = txn
            .set_batch_transfer(DbBatchTransferActMod {
                incoming: ActiveValue::Set(false),
                status: ActiveValue::Set(TransferStatus::Initiated),
                min_confirmations: ActiveValue::Set(1),
                created_at: ActiveValue::Set(1),
                ..Default::default()
            })
            .unwrap();
        assert!(txn.prepared_sweep_insert(batch, "one", Vec::new()).is_err());
        txn.prepared_sweep_insert(batch, "one", b"payload".to_vec())
            .unwrap();
        assert_eq!(txn.prepared_sweep_read(batch).unwrap().2, b"payload");
        assert!(txn.is_prepared_rgb_sweep(batch).unwrap());
        assert!(txn.is_prepared_rgb_sweep_txid("one").unwrap());
        assert!(
            txn.prepared_sweep_phase(batch, "handed_off", "consumed")
                .is_err()
        );
        txn.prepared_sweep_phase(batch, "prepared", "handed_off")
            .unwrap();
        assert!(
            txn.prepared_sweep_phase(batch, "prepared", "cancelled")
                .is_err()
        );
        txn.commit().unwrap();
        assert!(wallet.list_prepared_sweeps().is_err()); // invalid receipt cannot be silently ignored
    }

    #[cfg(feature = "bitcoind")]
    mod funded {
        use super::*;
        use crate::wallet::channel_funding_tests::Fixture;
        use bdk_wallet::{descriptor::IntoWalletDescriptor, signer::SignersContainer};
        use sea_orm::ConnectionTrait;
        use serde_json::json;
        use serial_test::serial;

        fn sweep(
            wallet: &mut Wallet,
            online: Online,
            target: &mut Wallet,
            asset: &str,
        ) -> (Psbt, ColoringInfo) {
            let receive = target
                .witness_receive(
                    None,
                    None,
                    Assignment::Fungible(100),
                    (now().unix_timestamp() + 3600) as u64,
                    vec![],
                    1,
                    None,
                )
                .unwrap();
            let script = script_buf_from_recipient_id(receive.recipient_id)
                .unwrap()
                .unwrap();
            sweep_to_script(wallet, online, script, asset)
        }

        fn sweep_to_script(
            wallet: &mut Wallet,
            online: Online,
            script: ScriptBuf,
            asset: &str,
        ) -> (Psbt, ColoringInfo) {
            let unspent = wallet
                .list_unspents(Some(online), false, false)
                .unwrap()
                .into_iter()
                .find(|output| {
                    output.rgb_allocations.iter().any(|allocation| {
                        allocation.asset_id.as_deref() == Some(asset)
                            && allocation.assignment == Assignment::Fungible(100)
                    })
                })
                .unwrap();
            let input: OutPoint = unspent.utxo.outpoint.into();
            let mut builder = wallet.bdk_wallet_mut().build_tx();
            builder
                .add_utxo(input)
                .unwrap()
                .manually_selected_only()
                .drain_to(script)
                .fee_rate(FeeRate::from_sat_per_vb_u32(2));
            let psbt = builder.finish().unwrap();
            let coloring = ColoringInfo {
                asset_info_map: HashMap::from([(
                    ContractId::from_str(asset).unwrap(),
                    rust_only::AssetColoringInfo {
                        output_map: HashMap::from([(0, 100)]),
                        static_blinding: Some(777),
                    },
                )]),
                static_blinding: None,
                nonce: None,
            };
            (psbt, coloring)
        }

        fn sql(wallet: &Wallet, query: &str) {
            let connection = block_on(Database::connect(format!(
                "sqlite:{}?mode=rw",
                wallet.get_wallet_dir().join("rgb_lib_db").display()
            )))
            .unwrap();
            block_on(connection.execute_unprepared(query)).unwrap();
            block_on(connection.close()).unwrap();
        }

        fn batch_state(wallet: &Wallet, batch: i32) -> (String, TransferStatus, usize) {
            let txn = wallet.database().begin_transaction().unwrap();
            let phase = txn.prepared_sweep_read(batch).unwrap().1;
            let status = txn
                .get_batch_transfer_or_fail(batch, &txn.iter_batch_transfers().unwrap())
                .unwrap()
                .status;
            let reservations = txn
                .iter_reserved_txos()
                .unwrap()
                .into_iter()
                .filter(|row| row.reserved_for_colored == Some(batch))
                .count();
            txn.commit().unwrap();
            (phase, status, reservations)
        }

        #[test]
        #[serial]
        fn prepared_sweep_self_receive_waits_for_canonical_consume_without_double_credit() {
            let fixture = Fixture::new();
            let (_directory, mut wallet, online, asset) = fixture.colored_wallet();
            let contradictory = wallet
                .witness_receive(
                    None,
                    None,
                    Assignment::Fungible(99),
                    (now().unix_timestamp() + 3600) as u64,
                    vec![],
                    0,
                    None,
                )
                .unwrap();
            let script = script_buf_from_recipient_id(contradictory.recipient_id)
                .unwrap()
                .unwrap();
            let (mut rejected, coloring) = sweep_to_script(&mut wallet, online, script, &asset);
            let original = rejected.clone();
            assert!(
                wallet
                    .color_psbt_and_prepare_consume(&mut rejected, coloring, 1, None)
                    .is_err()
            );
            assert_eq!(rejected, original);
            assert!(wallet.list_prepared_sweeps().unwrap().is_empty());
            // Exercise even the pre-existing zero-confirmation receive policy. The protected
            // source, rather than the receiver's policy, owns first stock consumption.
            let receive = wallet
                .witness_receive(
                    None,
                    None,
                    Assignment::Fungible(100),
                    (now().unix_timestamp() + 3600) as u64,
                    vec![],
                    0,
                    None,
                )
                .unwrap();
            let script = script_buf_from_recipient_id(receive.recipient_id)
                .unwrap()
                .unwrap();
            let (mut psbt, coloring) = sweep_to_script(&mut wallet, online, script, &asset);
            let old_input = psbt.unsigned_tx.input[0].previous_output;
            let original = psbt.clone();
            let first = wallet
                .color_psbt_and_prepare_consume(&mut psbt, coloring.clone(), 1, None)
                .unwrap();
            let incoming = receive.batch_transfer_idx;
            assert!(matches!(
                wallet.fail_transfers(online, Some(incoming), false, true),
                Err(Error::CannotFailBatchTransfer)
            ));
            let txn = wallet.database().begin_transaction().unwrap();
            let data = txn.get_db_data(true).unwrap();
            let staged = txn
                .get_batch_transfer_or_fail(incoming, &data.batch_transfers)
                .unwrap();
            assert_eq!(staged.status, TransferStatus::WaitingCounterparty);
            assert_eq!(
                staged.txid,
                Some(psbt.unsigned_tx.compute_txid().to_string())
            );
            assert!(matches!(
                wallet.delete_batch_transfer(
                    &txn,
                    &staged,
                    &staged.get_asset_transfers(&data.asset_transfers),
                    &data.colorings,
                    &data.txos,
                ),
                Err(Error::CannotDeleteBatchTransfer)
            ));
            txn.commit().unwrap();
            // A preparation cancelled before handoff may release/rebind its still unused receive.
            wallet
                .cancel_prepared_sweep(first.batch_transfer_idx)
                .unwrap();
            psbt = original;
            psbt.unsigned_tx.lock_time = LockTime::from_height(1).unwrap();
            let prepared = wallet
                .color_psbt_and_prepare_consume(&mut psbt, coloring, 1, None)
                .unwrap();
            let batch = prepared.batch_transfer_idx;
            let txid = psbt.unsigned_tx.compute_txid().to_string();
            let proof_directory = tempfile::tempdir().unwrap();
            let proof = proof_directory.path().join("sweep.rgb");
            prepared.transfers[0].save_file(&proof).unwrap();
            let result = wallet
                .provide_out_of_band_consignment(online, proof.to_str().unwrap().into(), vec![])
                .unwrap();
            assert_eq!(*result.keys().next().unwrap(), incoming);
            assert_ne!(incoming, batch);
            let assert_pending = |wallet: &Wallet| {
                let txn = wallet.database().begin_transaction().unwrap();
                let incoming = txn
                    .get_batch_transfer_or_fail(incoming, &txn.iter_batch_transfers().unwrap())
                    .unwrap();
                assert_eq!(incoming.status, TransferStatus::WaitingBroadcast);
                assert!(txn.is_protected_sweep_batch(&incoming).unwrap());
                let stock = wallet.rgb_stock(&txn).unwrap();
                assert!(
                    stock
                        .assignments_by_contract([old_input])
                        .unwrap()
                        .contains_key(&ContractId::from_str(&asset).unwrap())
                );
                assert!(
                    stock
                        .assignments_by_contract([OutPoint::new(
                            bdk_wallet::bitcoin::Txid::from_str(&txid).unwrap(),
                            1,
                        )])
                        .unwrap()
                        .is_empty()
                );
                let data = txn.get_db_data(true).unwrap();
                assert!(matches!(
                    wallet.delete_batch_transfer(
                        &txn,
                        &incoming,
                        &incoming.get_asset_transfers(&data.asset_transfers),
                        &data.colorings,
                        &data.txos,
                    ),
                    Err(Error::CannotDeleteBatchTransfer)
                ));
                txn.commit().unwrap();
                assert!(wallet.get_asset_balance(asset.clone()).unwrap().future <= 100);
            };
            wallet.refresh(online, None, vec![], false).unwrap();
            assert_pending(&wallet);
            assert!(matches!(
                wallet.fail_transfers(online, Some(incoming), false, true),
                Err(Error::CannotFailBatchTransfer)
            ));
            assert!(matches!(
                wallet.accept_transfer_consignment(online, proof.clone(), txid.clone(), 1, 777,),
                Err(Error::WrongOperation { .. })
            ));
            wallet
                .mark_prepared_sweep_handed_off(batch, txid.clone())
                .unwrap();
            let signed = wallet.sign_psbt(psbt.to_string(), None).unwrap();
            let transaction = Psbt::from_str(&signed).unwrap().extract_tx().unwrap();
            fixture.rpc(
                false,
                "sendrawtransaction",
                json!([hex::encode(
                    bdk_wallet::bitcoin::consensus::encode::serialize(&transaction)
                )]),
            );
            wallet.refresh(online, None, vec![], false).unwrap();
            assert_pending(&wallet);
            assert!(wallet.consume_transfer_fascia(online, batch).is_err());
            assert!(matches!(
                wallet.fail_transfers(online, Some(incoming), false, true),
                Err(Error::CannotFailBatchTransfer)
            ));
            fixture.mine(1);
            wallet.refresh(online, None, vec![], false).unwrap();
            assert_pending(&wallet); // even a confirmed generic receive cannot bypass the journal
            wallet.consume_transfer_fascia(online, batch).unwrap();
            wallet.refresh(online, None, vec![], false).unwrap();
            assert_eq!(
                wallet.get_asset_balance(asset.clone()).unwrap(),
                Balance {
                    settled: 100,
                    future: 100,
                    spendable: 100,
                }
            );
            let data = wallet.get_wallet_data();
            let keys = wallet.get_keys();
            drop(wallet);
            let mut wallet = Wallet::new(data, keys).unwrap();
            let online = wallet.go_online(fixture.online_options()).unwrap();
            for _ in 0..2 {
                wallet.refresh(online, None, vec![], false).unwrap();
                wallet.consume_transfer_fascia(online, batch).unwrap();
            }
            assert_eq!(
                wallet.get_asset_balance(asset.clone()).unwrap(),
                Balance {
                    settled: 100,
                    future: 100,
                    spendable: 100,
                }
            );
            let outputs = wallet.list_unspents(Some(online), false, false).unwrap();
            let allocations: Vec<_> = outputs
                .iter()
                .filter(|output| output.utxo.outpoint.txid == txid)
                .flat_map(|output| &output.rgb_allocations)
                .filter(|allocation| allocation.asset_id.as_deref() == Some(asset.as_str()))
                .collect();
            assert_eq!(allocations.len(), 1);
            assert_eq!(allocations[0].assignment, Assignment::Fungible(100));
            assert_eq!(
                batch_state(&wallet, batch),
                ("consumed".into(), TransferStatus::Settled, 0)
            );
            // A real subsequent proof contains the consumed sweep as an ancestor. It remains
            // admissible, whereas fault-injecting an active ancestor makes it wait rather than
            // importing that protected state indirectly.
            let next_receive = wallet
                .witness_receive(
                    None,
                    None,
                    Assignment::Any,
                    (now().unix_timestamp() + 3600) as u64,
                    vec![],
                    1,
                    None,
                )
                .unwrap();
            let script = script_buf_from_recipient_id(next_receive.recipient_id)
                .unwrap()
                .unwrap();
            let (mut next_psbt, next_coloring) =
                sweep_to_script(&mut wallet, online, script, &asset);
            let next = wallet
                .color_psbt_and_prepare_consume(&mut next_psbt, next_coloring, 1, None)
                .unwrap();
            let next_txid = next_psbt.unsigned_tx.compute_txid().to_string();
            let current = RgbTxid::from_str(&next_txid).unwrap();
            let txn = wallet.database().begin_transaction().unwrap();
            assert!(prepared_sweep_ancestry_ready(&txn, &next.transfers[0], current).unwrap());
            txn.commit().unwrap();
            sql(
                &wallet,
                &format!(
                    "UPDATE prepared_rgb_sweep SET phase = 'handed_off' WHERE batch_transfer_idx = {batch}"
                ),
            );
            let txn = wallet.database().begin_transaction().unwrap();
            assert!(!prepared_sweep_ancestry_ready(&txn, &next.transfers[0], current).unwrap());
            txn.commit().unwrap();
            sql(
                &wallet,
                &format!(
                    "UPDATE prepared_rgb_sweep SET phase = 'consumed' WHERE batch_transfer_idx = {batch}"
                ),
            );
            let next_proof = proof_directory.path().join("next.rgb");
            next.transfers[0].save_file(&next_proof).unwrap();
            let provided = wallet
                .provide_out_of_band_consignment(
                    online,
                    next_proof.to_str().unwrap().into(),
                    vec![],
                )
                .unwrap();
            assert_eq!(
                provided[&next_receive.batch_transfer_idx].updated_status,
                Some(TransferStatus::WaitingBroadcast)
            );
            wallet
                .cancel_prepared_sweep(next.batch_transfer_idx)
                .unwrap();
        }

        #[test]
        #[serial]
        fn prepared_sweep_funded_reopen_confirmed_consume_is_atomic_and_idempotent() {
            let fixture = Fixture::new();
            let (_directory, mut wallet, online, asset) = fixture.colored_wallet();
            let (_target_dir, mut target, _) = fixture.wallet(false);
            let (mut psbt, coloring) = sweep(&mut wallet, online, &mut target, &asset);
            let prepared = wallet
                .color_psbt_and_prepare_consume(&mut psbt, coloring.clone(), 1, None)
                .unwrap();
            let batch = prepared.batch_transfer_idx;
            let txid = psbt.unsigned_tx.compute_txid().to_string();
            assert_eq!(
                batch_state(&wallet, batch),
                ("prepared".into(), TransferStatus::Initiated, 1)
            );
            assert!(
                wallet
                    .color_psbt_and_prepare_consume(&mut psbt.clone(), coloring.clone(), 1, None)
                    .is_err()
            );
            assert!(wallet.consume_transfer_fascia(online, batch).is_err());
            assert!(matches!(
                wallet.sign_psbt(psbt.to_string(), None),
                Err(Error::WrongOperation { .. })
            ));
            let txn = wallet.database().begin_transaction().unwrap();
            let (_, _, payload) = txn.prepared_sweep_read(batch).unwrap();
            let (_, _, fascia, _) = StoredSweep::decode(&payload, &txid).unwrap();
            txn.commit().unwrap();
            assert!(matches!(
                wallet.consume_fascia(fascia.clone(), None),
                Err(Error::WrongOperation { .. })
            ));
            let mut raw = psbt.clone();
            assert!(matches!(
                wallet.color_psbt_and_consume(&mut raw, coloring.clone()),
                Err(Error::WrongOperation { .. })
            ));
            assert!(matches!(
                wallet.mark_prepared_sweep_handed_off(batch, "wrong".into()),
                Err(Error::InvalidColoringInfo { .. })
            ));
            let data = wallet.get_wallet_data();
            let keys = wallet.get_keys();
            let online_options = OnlineOptions {
                indexer_config: wallet
                    .online_data()
                    .as_ref()
                    .unwrap()
                    .indexer_config
                    .clone(),
                skip_consistency_check: false,
                vanilla_sync_lookback: 20,
                failed_witness_receive_grace_secs: 604800,
                proxy_auth_keys: HashMap::new(),
                evm_rpc_urls: HashMap::new(),
            };
            drop(wallet);
            let mut wallet = Wallet::new(data, keys).unwrap();
            let online = wallet.go_online(online_options).unwrap();
            let recovered = wallet.list_prepared_sweeps().unwrap();
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].psbt, psbt.to_string());
            assert!(!recovered[0].handed_off);
            wallet
                .mark_prepared_sweep_handed_off(batch, txid.clone())
                .unwrap();
            wallet
                .mark_prepared_sweep_handed_off(batch, txid.clone())
                .unwrap();
            assert!(matches!(
                wallet.cancel_prepared_sweep(batch),
                Err(Error::CannotFailBatchTransfer)
            ));
            assert!(matches!(
                wallet.fail_transfers(online, Some(batch), false, true),
                Err(Error::CannotFailBatchTransfer)
            ));
            assert!(wallet.fail_transfers(online, None, false, true).is_ok());
            assert_eq!(batch_state(&wallet, batch).0, "handed_off");
            let signed = wallet.sign_psbt(psbt.to_string(), None).unwrap();
            assert!(matches!(
                wallet.consume_fascia(fascia.clone(), None),
                Err(Error::WrongOperation { .. })
            ));
            let mut replacement = psbt.clone();
            replacement.unsigned_tx.lock_time = LockTime::from_height(1).unwrap();
            assert_ne!(replacement.unsigned_tx.compute_txid().to_string(), txid);
            assert!(matches!(
                wallet.sign_psbt(replacement.to_string(), None),
                Err(Error::WrongOperation { .. })
            ));
            // A malicious caller can bring its own valid signatures. The generic broadcast
            // path must still reject a different transaction spending the protected inputs.
            // This independent signer has no synced BDK chain graph. Supply authenticated
            // previous transactions rather than relaxing its witness-UTXO trust policy.
            for (input, txin) in replacement
                .inputs
                .iter_mut()
                .zip(&replacement.unsigned_tx.input)
            {
                let raw = fixture.rpc(
                    false,
                    "getrawtransaction",
                    json!([txin.previous_output.txid.to_string(), false,]),
                );
                let previous: BdkTransaction = bdk_wallet::bitcoin::consensus::encode::deserialize(
                    &hex::decode(raw.as_str().unwrap()).unwrap(),
                )
                .unwrap();
                assert_eq!(previous.compute_txid(), txin.previous_output.txid);
                assert_eq!(
                    previous.output.get(txin.previous_output.vout as usize),
                    input.witness_utxo.as_ref()
                );
                input.non_witness_utxo = Some(previous);
            }
            let (descriptors, _) = wallet
                .get_keys()
                .build_descriptors(&BitcoinNetwork::Regtest)
                .unwrap();
            let external_signer =
                BdkWallet::create(descriptors.colored.clone(), descriptors.vanilla.clone())
                    .network(BdkNetwork::Regtest)
                    .create_wallet_no_persist()
                    .unwrap();
            let build_signers = |descriptor: &str, keychain| {
                let (_, keymap) = descriptor
                    .into_wallet_descriptor(
                        external_signer.secp_ctx(),
                        BitcoinNetwork::Regtest.network_kind(),
                    )
                    .unwrap();
                SignersContainer::build(
                    keymap,
                    external_signer.public_descriptor(keychain),
                    external_signer.secp_ctx(),
                )
            };
            let colored_signer = build_signers(&descriptors.colored, KeychainKind::External);
            let vanilla_signer = build_signers(&descriptors.vanilla, KeychainKind::Internal);
            assert!(
                external_signer
                    .sign_with_signers(
                        &mut replacement,
                        &[&colored_signer, &vanilla_signer],
                        SignOptions::default(),
                    )
                    .unwrap()
            );
            assert!(matches!(
                wallet.send_btc_end(online, replacement.to_string()),
                Err(Error::WrongOperation { .. })
            ));
            assert!(matches!(
                wallet.send_end(online, signed.clone()),
                Err(Error::WrongOperation { .. })
            ));
            assert!(matches!(
                wallet.send_btc_end(online, signed.clone()),
                Err(Error::WrongOperation { .. })
            ));
            let transaction = Psbt::from_str(&signed).unwrap().extract_tx().unwrap();
            fixture.rpc(
                false,
                "sendrawtransaction",
                json!([hex::encode(
                    bdk_wallet::bitcoin::consensus::encode::serialize(&transaction)
                )]),
            );
            assert!(wallet.consume_transfer_fascia(online, batch).is_err()); // mempool alone is insufficient
            fixture.mine(1);
            sql(
                &wallet,
                &format!(
                    "CREATE TRIGGER sweep_consume_failure BEFORE UPDATE ON batch_transfer WHEN NEW.idx = {batch} BEGIN SELECT RAISE(ABORT, 'sweep fixture commit failure'); END"
                ),
            );
            assert!(wallet.consume_transfer_fascia(online, batch).is_err());
            assert_eq!(
                batch_state(&wallet, batch),
                ("handed_off".into(), TransferStatus::Initiated, 1)
            );
            sql(&wallet, "DROP TRIGGER sweep_consume_failure");
            wallet.consume_transfer_fascia(online, batch).unwrap();
            assert_eq!(
                batch_state(&wallet, batch),
                ("consumed".into(), TransferStatus::Settled, 0)
            );
            wallet.consume_transfer_fascia(online, batch).unwrap();
            assert_eq!(
                batch_state(&wallet, batch),
                ("consumed".into(), TransferStatus::Settled, 0)
            );
            assert!(wallet.list_prepared_sweeps().unwrap().is_empty());
            assert!(matches!(
                wallet.consume_fascia(fascia, None),
                Err(Error::WrongOperation { .. })
            ));
            assert!(matches!(
                wallet.sign_psbt(psbt.to_string(), None),
                Err(Error::WrongOperation { .. })
            ));
            assert!(matches!(
                wallet.cancel_prepared_sweep(batch),
                Err(Error::CannotFailBatchTransfer)
            ));
        }

        #[test]
        #[serial]
        fn prepared_sweep_admission_rejects_a_second_connection_write_instead_of_committing_stale_proofs()
         {
            let fixture = Fixture::new();
            let (_directory, mut wallet, online, asset) = fixture.colored_wallet();
            let (_target_dir, mut target, _) = fixture.wallet(false);
            let (psbt, coloring) = sweep(&mut wallet, online, &mut target, &asset);
            sql(&wallet, "PRAGMA journal_mode=WAL");
            let txn = wallet.database().begin_transaction().unwrap();
            assert!(txn.get_asset(asset.clone()).unwrap().is_some()); // pin the real read snapshot
            sql(
                &wallet,
                "UPDATE backup_info SET last_operation_timestamp = '2'",
            );
            // This is the exact production admission/color/proof/reservation helper. SQLite must
            // reject upgrading its stale read snapshot to a write; no production race hook exists.
            assert!(
                wallet
                    .prepare_sweep_in_txn(&txn, &psbt, coloring, 1, None)
                    .is_err()
            );
            drop(txn);
            assert!(wallet.list_prepared_sweeps().unwrap().is_empty());
            assert_eq!(wallet.get_asset_balance(asset).unwrap().settled, 100);
        }

        #[test]
        #[serial]
        fn prepared_sweep_reserves_vanilla_fee_inputs_against_every_internal_builder() {
            let fixture = Fixture::new();
            let (_directory, mut wallet, online, asset) = fixture.colored_wallet();
            let (_target_dir, mut target, _) = fixture.wallet(false);
            let (psbt, coloring) = sweep(&mut wallet, online, &mut target, &asset);
            let colored_input = psbt.unsigned_tx.input[0].previous_output;
            let vanilla_input = wallet.internal_unspents().next().unwrap().outpoint;
            let destination = psbt.unsigned_tx.output[0].script_pubkey.clone();
            let mut builder = wallet.bdk_wallet_mut().build_tx();
            builder
                .add_utxos(&[colored_input, vanilla_input])
                .unwrap()
                .manually_selected_only()
                .drain_to(destination)
                .fee_rate(FeeRate::from_sat_per_vb_u32(2));
            let mut mixed = builder.finish().unwrap();
            let prepared = wallet
                .color_psbt_and_prepare_consume(&mut mixed, coloring, 1, None)
                .unwrap();
            assert_eq!(batch_state(&wallet, prepared.batch_transfer_idx).2, 2);
            assert_eq!(
                wallet
                    .get_btc_balance(Some(online), true)
                    .unwrap()
                    .vanilla
                    .spendable,
                0
            );
            let address = target.get_address().unwrap();
            assert!(
                wallet
                    .send_btc_begin(online, address.clone(), 1000, 2, true, true)
                    .is_err()
            );
            assert!(
                wallet
                    .create_utxos_begin(online, false, Some(1), Some(1000), 2, true, true)
                    .is_err()
            );
            if let Ok(drain) = wallet.drain_to_begin(online, address, 2, true) {
                let drain = Psbt::from_str(&drain).unwrap();
                assert!(input_set(&drain).is_disjoint(&input_set(&mixed)));
            }
            wallet
                .cancel_prepared_sweep(prepared.batch_transfer_idx)
                .unwrap();
            assert!(
                wallet
                    .get_btc_balance(Some(online), true)
                    .unwrap()
                    .vanilla
                    .spendable
                    > 0
            );
        }

        #[test]
        #[serial]
        fn prepared_sweep_funded_rejections_and_unsigned_cancel_preserve_assets() {
            let fixture = Fixture::new();
            let (_directory, mut wallet, online, asset) = fixture.colored_wallet();
            let (_target_dir, mut target, _) = fixture.wallet(false);
            let (mut psbt, coloring) = sweep(&mut wallet, online, &mut target, &asset);
            let original = psbt.clone();
            for case in 0..5 {
                let mut request = coloring.clone();
                let entry = request.asset_info_map.values_mut().next().unwrap();
                match case {
                    0 => {
                        entry.output_map.insert(0, 99);
                    }
                    1 => {
                        entry.output_map.insert(0, 101);
                    }
                    2 => {
                        entry.output_map = HashMap::from([(1, 100)]);
                    }
                    3 => {
                        request.asset_info_map.clear();
                    }
                    4 => {}
                    _ => unreachable!(),
                }
                let result = wallet.color_psbt_and_prepare_consume(
                    &mut psbt,
                    request,
                    1,
                    (case == 4).then_some(1),
                );
                assert!(result.is_err());
                assert_eq!(psbt, original);
                assert!(wallet.list_prepared_sweeps().unwrap().is_empty());
            }
            let prepared = wallet
                .color_psbt_and_prepare_consume(&mut psbt, coloring, 1, None)
                .unwrap();
            let batch = prepared.batch_transfer_idx;
            assert!(matches!(
                wallet.delete_transfers(Some(batch), false),
                Err(Error::CannotDeleteBatchTransfer)
            ));
            wallet.cancel_prepared_sweep(batch).unwrap();
            wallet.cancel_prepared_sweep(batch).unwrap();
            assert_eq!(
                batch_state(&wallet, batch),
                ("cancelled".into(), TransferStatus::Failed, 0)
            );
            assert!(wallet.list_prepared_sweeps().unwrap().is_empty());
            assert!(matches!(
                wallet.delete_transfers(Some(batch), false),
                Err(Error::CannotDeleteBatchTransfer)
            ));
            assert_eq!(
                wallet.get_asset_balance(asset.clone()).unwrap().settled,
                100
            );
            assert!(matches!(
                wallet.sign_psbt(psbt.to_string(), None),
                Err(Error::WrongOperation { .. })
            ));

            let txn = wallet.database().begin_transaction().unwrap();
            let old_payload = txn.prepared_sweep_read(batch).unwrap().2;
            txn.commit().unwrap();
            let old: StoredSweep = serde_json::from_slice(&old_payload).unwrap();
            let (mut second_psbt, second_coloring) =
                sweep(&mut wallet, online, &mut target, &asset);
            let second = wallet
                .color_psbt_and_prepare_consume(&mut second_psbt, second_coloring, 1, None)
                .unwrap();
            let second_batch = second.batch_transfer_idx;
            let txn = wallet.database().begin_transaction().unwrap();
            let (second_txid, _, original_payload) = txn.prepared_sweep_read(second_batch).unwrap();
            txn.commit().unwrap();
            let mut substituted: StoredSweep = serde_json::from_slice(&original_payload).unwrap();
            substituted.consignments = old.consignments; // same asset, different sweep witness/beneficiaries
            let forged = serde_json::to_vec(&substituted).unwrap();
            let digest = hex::encode(Sha256::digest(&forged));
            sql(
                &wallet,
                &format!(
                    "UPDATE prepared_rgb_sweep SET payload = X'{}', payload_sha256 = '{}' WHERE batch_transfer_idx = {second_batch}",
                    hex::encode(&forged),
                    digest
                ),
            );
            assert!(StoredSweep::decode(&forged, &second_txid).is_err());
            assert!(wallet.list_prepared_sweeps().is_err()); // recomputing the journal hash cannot admit substituted proof
            assert!(
                wallet
                    .mark_prepared_sweep_handed_off(second_batch, second_txid)
                    .is_err()
            );
            let original_digest = hex::encode(Sha256::digest(&original_payload));
            sql(
                &wallet,
                &format!(
                    "UPDATE prepared_rgb_sweep SET payload = X'{}', payload_sha256 = '{}' WHERE batch_transfer_idx = {second_batch}",
                    hex::encode(&original_payload),
                    original_digest
                ),
            );
            wallet.cancel_prepared_sweep(second_batch).unwrap();
        }
    }
}
