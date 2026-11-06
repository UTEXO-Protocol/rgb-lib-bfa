//! Typed access to the protected external-sweep ownership journal.
use super::*;
use sea_orm::{ConnectionTrait, DbBackend, Statement};

#[cfg(feature = "_online")]
pub(crate) const MAX_SWEEP_PAYLOAD: usize = 32 * 1024 * 1024;
#[cfg(feature = "_online")]
const MAX_SWEEP_SET_BYTES: usize = 64 * 1024 * 1024;

#[cfg(feature = "_online")]
fn admit_sizes(sizes: impl IntoIterator<Item = i64>) -> Result<(), Error> {
    let mut total = 0usize;
    for size in sizes {
        if !(1..=MAX_SWEEP_PAYLOAD as i64).contains(&size) {
            return Err(Error::InvalidColoringInfo {
                details: "invalid prepared sweep payload size".into(),
            });
        }
        total = total
            .checked_add(size as usize)
            .ok_or_else(|| Error::InvalidColoringInfo {
                details: "prepared sweep aggregate size overflow".into(),
            })?;
        if total > MAX_SWEEP_SET_BYTES {
            return Err(Error::InvalidColoringInfo {
                details: "prepared sweep set exceeds aggregate memory budget".into(),
            });
        }
    }
    Ok(())
}

impl DbTxn {
    /// Every phase is protected from generic send/fail/delete paths, including tombstones.
    pub(crate) fn is_prepared_rgb_sweep(&self, batch: i32) -> Result<bool, Error> {
        Ok(
            block_on(self.inner().query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT batch_transfer_idx FROM prepared_rgb_sweep WHERE batch_transfer_idx = ?",
                [batch.into()],
            )))?
            .is_some(),
        )
    }

    pub(crate) fn prepared_sweep_batch_by_txid(&self, txid: &str) -> Result<Option<i32>, Error> {
        let row = block_on(self.inner().query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT batch_transfer_idx FROM prepared_rgb_sweep WHERE txid = ?",
            [txid.into()],
        )))?;
        row.map(|row| row.try_get("", "batch_transfer_idx").map_err(Error::from))
            .transpose()
    }

    pub(crate) fn is_prepared_rgb_sweep_txid(&self, txid: &str) -> Result<bool, Error> {
        Ok(self.prepared_sweep_batch_by_txid(txid)?.is_some())
    }

    pub(crate) fn is_active_prepared_sweep_txid(&self, txid: &str) -> Result<bool, Error> {
        Ok(block_on(self.inner().query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT batch_transfer_idx FROM prepared_rgb_sweep WHERE txid = ? AND phase IN ('prepared', 'handed_off')",
            [txid.into()],
        )))?.is_some())
    }

    /// Keep the separately staged self-receive recoverable while signatures may exist outside
    /// the library. After confirmed consumption its ordinary incoming lifecycle may finish.
    pub(crate) fn is_protected_sweep_batch(&self, batch: &DbBatchTransfer) -> Result<bool, Error> {
        if self.is_prepared_rgb_sweep(batch.idx)? {
            return Ok(true);
        }
        if !batch.incoming {
            return Ok(false);
        }
        let Some(txid) = &batch.txid else {
            return Ok(false);
        };
        self.is_active_prepared_sweep_txid(txid)
    }

    /// Generic mutation paths cannot consume or broadcast a protected witness, nor replace an
    /// active sweep with another transaction spending its reserved inputs.
    pub(crate) fn ensure_no_prepared_sweep_mutation(
        &self,
        transaction: &BdkTransaction,
    ) -> Result<(), Error> {
        let txid = transaction.compute_txid().to_string();
        if self.is_prepared_rgb_sweep_txid(&txid)? {
            return Err(Error::WrongOperation { txid });
        }
        for input in &transaction.input {
            if block_on(self.inner().query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT r.idx FROM reserved_txo r JOIN prepared_rgb_sweep p ON r.reserved_for_colored = p.batch_transfer_idx WHERE r.txid = ? AND r.vout = ? AND p.phase IN ('prepared', 'handed_off') LIMIT 1",
                [input.previous_output.txid.to_string().into(), input.previous_output.vout.into()],
            )))?.is_some() {
                return Err(Error::WrongOperation { txid });
            }
        }
        Ok(())
    }

    #[cfg(feature = "_online")]
    pub(crate) fn prepared_sweep_read(
        &self,
        batch: i32,
    ) -> Result<(String, String, Vec<u8>), Error> {
        let row = block_on(self.inner().query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT txid, phase, length(payload) AS size FROM prepared_rgb_sweep WHERE batch_transfer_idx = ?",
            [batch.into()],
        )))?.ok_or(Error::BatchTransferNotFound { idx: batch })?;
        let size: i64 = row.try_get("", "size")?;
        if !(1..=MAX_SWEEP_PAYLOAD as i64).contains(&size) {
            return Err(Error::InvalidColoringInfo {
                details: "invalid prepared sweep payload size".into(),
            });
        }
        let txid: String = row.try_get("", "txid")?;
        let phase: String = row.try_get("", "phase")?;
        let row = block_on(self.inner().query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT payload, payload_sha256 FROM prepared_rgb_sweep WHERE batch_transfer_idx = ?",
            [batch.into()],
        )))?
        .ok_or(Error::BatchTransferNotFound { idx: batch })?;
        let payload: Vec<u8> = row.try_get("", "payload")?;
        let digest: String = row.try_get("", "payload_sha256")?;
        if hex::encode(Sha256::digest(&payload)) != digest {
            return Err(Error::InvalidColoringInfo {
                details: "prepared sweep payload digest mismatch".into(),
            });
        }
        Ok((txid, phase, payload))
    }

    #[cfg(feature = "_online")]
    pub(crate) fn prepared_sweep_insert(
        &self,
        batch: i32,
        txid: &str,
        payload: Vec<u8>,
    ) -> Result<(), Error> {
        if payload.is_empty() || payload.len() > MAX_SWEEP_PAYLOAD {
            return Err(Error::InvalidColoringInfo {
                details: "prepared sweep payload exceeds limit".into(),
            });
        }
        let sizes = block_on(self.inner().query_all_raw(Statement::from_string(DbBackend::Sqlite,
            "SELECT length(payload) AS size FROM prepared_rgb_sweep WHERE phase IN ('prepared', 'handed_off')".to_owned())))?;
        let mut sizes: Vec<i64> = sizes
            .iter()
            .map(|row| row.try_get("", "size"))
            .collect::<Result<_, _>>()?;
        sizes.push(payload.len() as i64);
        admit_sizes(sizes)?;
        let digest = hex::encode(Sha256::digest(&payload));
        block_on(self.inner().execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO prepared_rgb_sweep (batch_transfer_idx, txid, phase, payload, payload_sha256) VALUES (?, ?, 'prepared', ?, ?)",
            [batch.into(), txid.into(), payload.into(), digest.into()],
        )))?;
        Ok(())
    }

    #[cfg(feature = "_online")]
    pub(crate) fn prepared_sweep_phase(
        &self,
        batch: i32,
        expected: &str,
        next: &str,
    ) -> Result<(), Error> {
        let result = block_on(self.inner().execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE prepared_rgb_sweep SET phase = ? WHERE batch_transfer_idx = ? AND phase = ?",
            [next.into(), batch.into(), expected.into()],
        )))?;
        if result.rows_affected() != 1 {
            return Err(Error::InvalidColoringInfo {
                details: "prepared sweep phase changed".into(),
            });
        }
        Ok(())
    }

    #[cfg(feature = "_online")]
    pub(crate) fn prepared_sweep_active_batches(&self) -> Result<Vec<i32>, Error> {
        let rows = block_on(self.inner().query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT batch_transfer_idx, length(payload) AS size FROM prepared_rgb_sweep WHERE phase IN ('prepared', 'handed_off') ORDER BY batch_transfer_idx LIMIT 65".to_owned(),
        )))?;
        if rows.len() > 64 {
            return Err(Error::InvalidColoringInfo {
                details: "too many active prepared sweeps".into(),
            });
        }
        // Bound the complete result before fetching or decoding even its first payload.
        let sizes: Vec<i64> = rows
            .iter()
            .map(|row| row.try_get("", "size"))
            .collect::<Result<_, _>>()?;
        admit_sizes(sizes)?;
        rows.into_iter()
            .map(|row| row.try_get("", "batch_transfer_idx").map_err(Error::from))
            .collect()
    }
}

#[cfg(all(test, feature = "_online"))]
mod tests {
    use super::*;
    #[test]
    fn prepared_sweep_sizes_reject_aggregate_before_payload_allocation() {
        assert!(admit_sizes([MAX_SWEEP_PAYLOAD as i64; 2]).is_ok());
        assert!(admit_sizes([MAX_SWEEP_PAYLOAD as i64; 3]).is_err());
        assert!(admit_sizes([MAX_SWEEP_PAYLOAD as i64 + 1]).is_err());
        assert!(admit_sizes([i64::MAX]).is_err());
        assert!(admit_sizes([0]).is_err());
    }
}
