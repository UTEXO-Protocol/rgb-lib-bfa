# Prepared RGB sweeps

These Rust-only APIs prepare a transaction for an external signer without consuming
its RGB inputs. They require an online-capable wallet build. Ordinary sends and
channel funding use their existing APIs; funding builders are described in
[channel-funding-builders.md](channel-funding-builders.md).

## Caller sequence

1. Create any required witness receive before constructing the sweep outputs.
2. Call `color_psbt_and_prepare_consume` with the unsigned native SegWit PSBT,
   complete contract/output assignments, at least one confirmation, and no expiry.
   Output indices use the pre-commitment layout documented by the API.
3. Durably save the returned batch ID, exact colored PSBT and complete consignments
   in the caller's own recovery store. `list_prepared_sweeps` recovers an interrupted
   save from the library's journal; reuse that exact preparation.
4. Validate the caller's receipt against the canonical library record and call
   `mark_prepared_sweep_handed_off` with the batch ID and exact transaction ID
   **before any signer sees the PSBT**. The signer must only sign and return the
   transaction. The caller owns durable signed-transaction storage before broadcast.
5. Stage a self-receive consignment if required. This does not authorize early
   consumption. Persist the signed transaction before handing it to the broadcaster.
6. After confirmation, call `consume_transfer_fascia`. The library independently
   resolves the witness and required confirmation count, checks its exact transaction
   identity, then commits stock, input state, transfer status, reservations and phase
   together. Repeating successful consumption is idempotent.
7. Refresh matching incoming transfers after native consumption. Remove the caller's
   recovery receipt only after successful consumption and its own required durable
   transaction handling.

Preparation admits, colors, composes proofs, reserves inputs, binds compatible
pending self-receives and writes the journal in one database transaction. Failure
does not return a partially colored caller PSBT or a partially committed preparation.
The journal binds proofs to the prepared witness, bundle and beneficiaries, beyond
the stored payload hash. Caller-owned PSBT metadata and proof bytes must also match
before signing; matching transaction IDs alone is insufficient.

## Phases and recovery

| Phase | Meaning | Permitted completion |
| --- | --- | --- |
| `prepared` | No signer or broadcaster has received the transaction | Persist and mark handoff, or cancel explicitly |
| `handed_off` | Signed copies may exist outside the library | Retain reservations and reconcile the exact confirmed witness |
| `consumed` | Confirmed witness applied atomically | Idempotent confirmation check; retained identity tombstone |
| `cancelled` | Explicitly abandoned before handoff | Retained identity tombstone; a later operation needs a new preparation |

`cancel_prepared_sweep` is only for a preparation that has never been exposed to a
signer. Cancellation after handoff is forbidden, including after a signing error:
an external signer may already hold a broadcastable copy. Generic fail, expiry,
delete, send-end, raw consume and broadcast paths cannot resolve a protected sweep.
Active matching self-receives are protected from discard. Incoming acceptance that
would advance an active prepared witness waits for its canonical consumption.

The library's public signing API requires a valid handed-off record for protected
transactions. Wallet-only builds omit full prepared-proof admission and reject
protected signing. External signers must enforce the caller sequence themselves;
possession of an unsigned PSBT is not permission to sign or broadcast it.

## Bounds and trust

Preparation supports unsigned native SegWit inputs, complete owned contract sets,
and supported owner assignments with exact amount conservation. It rejects signed,
precolored, duplicate or overlapping inputs, unrelated commitment hosts, and
unsupported rights. It preserves PSBT maps while inserting the commitment host.

Known BDK previous outputs are checked against their witness UTXOs. For external
LDK inputs, the caller and signer must authenticate the previous-output value,
script and spend descriptor. Preparation has no independent indexer lookup for
those previous outputs. Confirmation uses the configured indexer's trust model.

Each payload is bounded to 32 MiB, individual components to 16 MiB, active records
to 64, and the aggregate active payload set to 64 MiB before recovery allocation.
Terminal records remain retained. Snapshots contain the journal and sensitive proof
and wallet data and require encrypted transport.

On bfa.5, the journal stores commitment entropy separately because the upstream
PSBT builder strips RGB/MPC metadata before handoff. Recovery recomputes the
commitment from the exact fascia bundles and this entropy, then verifies it against
the transaction. Previous journal records may still supply entropy through the
PSBT map. Missing or changed entropy is rejected. Consignments must contain exactly
the prepared terminal operations, beneficiaries, witness transaction and bundle;
the old terminal-bundle container is not used by this release.

These guards do not establish arbitrary external-signer broadcast recovery,
post-consumption reorg qualification, every Lightning channel lifecycle or platform
acceptance. Test results must identify the exact source graph and exercised scope.
