# Standalone contracts and acknowledged snapshots

These Rust APIs add contract registration and transport-independent snapshots.
They do not add a VSS client, network retry policy, signer protocol or wallet seed
handling to RGB Lib.

## Registering a public contract

```rust,ignore
use rgb_lib::wallet::RgbWalletOpsOffline;

let asset_id = wallet.import_contract(contract_path, Some(expected_asset_id))?;
```

`import_contract` accepts a standalone genesis-only CON file. It checks its ID,
supported schema, genesis validation and Bitcoin network before changing the
wallet. Stock and metadata are registered in one database transaction. A repeated
valid import is a no-op; a metadata row without RGB genesis is not accepted as an
already registered asset. Registration creates no transfer history or spendable
balance. Receiving assets must still perform the normal online witness, external
anchor and reject-list validation.

The public Signet fixture in `tests/fixtures/dev-bridge-usdt.rgb` is **Bridged USDT**,
**BUSDT**, precision **6**. Its SHA-256 is
`dfb49261fed5ad3dd237dd3a03913793b76fe70e486372bbeb0769b82158a895`.
Import tests do not establish funded transfer or hosted-bridge qualification.

## Preparing and acknowledging a snapshot

```rust,ignore
use rgb_lib::wallet::RgbWalletOpsOffline;

let snapshot = wallet.prepare_snapshot()?;
// snapshot.data is a PRIVATE, unencrypted raw ZIP. Encrypt before remote transport.
// Only acknowledge after the exact archive's remote commit has been confirmed.
let acknowledged = wallet.acknowledge_snapshot(&snapshot.token)?;
```

Callers must serialize wallet mutations. Both APIs require exclusive mutable
wallet access. `prepare_snapshot` never declares that a backup completed. An
omitted acknowledgement, such as after transport failure or cancellation, leaves
existing dirty state intact. A previously clean fresh wallet can still need an
initial remote backup; only the caller knows whether that remote archive exists.

SQLite `VACUUM INTO` creates a consistent standalone database, including committed
WAL data. The raw ZIP keeps the fingerprint root, database, manifest, media,
consignments and other nontransient wallet files. It does not copy SQLite WAL/SHM
or logs. A token hashes canonical typed logical rows and file contents, rather
than database page layout, clock values or modification times. This covers BDK,
RGB stock, proxy operation keys and persisted transfer state. Unexpected SQLite
REAL values fail closed because the current wallet schema has no floating-point
columns and text conversion would not provide a lossless content identity.

Preparation hashes the standalone captured database and the exact file bytes
streamed into the archive. Their identity must match both live observations before
and after capture. This also rejects an outside writer's A-to-B-to-A change during
capture; a matching final live state alone cannot acknowledge a different archive.

Acknowledgement recalculates that identity in a database transaction. A changed
wallet returns `false` without clearing dirty state. Successful acknowledgement
stores the content digest; subsequent `backup_info()` compares current contents
with that digest, including after reopen or clock correction. Backup timestamps,
the digest itself and its row bookkeeping do not invalidate their own token. The
processed-operation cursor remains part of the wallet content.

The existing encrypted-file `backup` API retains its timestamp-based contract;
this snapshot API does not replace it or change its file format. A raw snapshot
is not an encrypted-file backup and must not be passed to `restore_backup`.

## Archive admission and restore ownership

Preparation rejects symlinks, special files and uncoordinated additional SQLite
databases. Output is limited to 128 MiB compressed, 512 MiB expanded, 25,000 entries
and a 2,000:1 per-entry expansion ratio. Snapshot temporaries live outside the
wallet tree and are removed when preparation finishes or fails.

The receiving adapter remains responsible for authenticated decryption, bounded
canonical extraction, expected network/fingerprint/xpub validation, remote-version
stability, no-replace atomic promotion and locally authenticated restore receipts.
This API does not make the existing encrypted-file extractor a bounded cloud
restore interface. Raw archive creation is not proof of full Lightning recovery.

## Offline qualification

```sh
cargo test --locked --lib --no-default-features --features wallet -- --test-threads=1
cargo test --locked --lib --no-default-features --features wallet,bitcoind migration_prerequisites -- --test-threads=1
```

The prerequisite tests use fresh private wallets and the supplied public contract.
They require no chain, proxy, bridge, VSS server or hosted-service operation. The
second command additionally checks persisted proxy operation-secret mutations.
Funded flows, real VSS transport/restore, platform artifacts and app acceptance are
separate integration scopes.
