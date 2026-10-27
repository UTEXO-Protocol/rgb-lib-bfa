# Channel funding transaction preparation

The Rust `Wallet` API has two additive entry points for channel funding:

- `send_channel_funding_begin` takes the same arguments and returns the same
  `SendBeginResult` as `send_begin`.
- `send_btc_channel_funding_begin` takes the same arguments and returns the same
  PSBT string as `send_btc_begin`.

Both select absolute Bitcoin locktime zero in the BDK transaction builder before
it finishes. RGB commitments, the unsigned PSBT, its transaction ID, on-disk
transfer data and input reservations therefore identify the same transaction.
The fee-input and reject-list retry paths retain this selection. Callers must
not rewrite the unsigned transaction after preparation.

These entry points do not sign or broadcast. They support watch-only wallets
and the existing external-signing flow. They do not change input sequence or
RBF policy. Ordinary `send_begin` and `send_btc_begin` retain their existing BDK
locktime policy; this is not a global change to ordinary wallet sends.

The existing `dry_run` contract also applies. A vanilla dry run reserves no
inputs. An RGB dry run writes its unsigned PSBT and transfer files but creates
no Initiated transfer or input reservation. A real RGB preparation creates its
Initiated transfer and input reservations using the final PSBT transaction ID.
The normal matching `_end` method completes a signed preparation.

## Funded regression scope

`wallet::channel_funding_tests` exercises:

1. Vanilla preview, reservation, separate signing and broadcast with one exact
   transaction ID, while an ordinary send retains its chain-height locktime.
2. RGB preview and persisted preparation, including additional fee-input
   retries, matching transfer files/reservations, signing and broadcast.
3. Existing offline-context, fee, recipient-map and insufficient-funds errors
   without reservations for failed requests.
4. Both preparations in a watch-only wallet without a local signer fallback.

Run the module with the `bitcoind` feature and the usual test services:

```sh
cargo test --locked --no-default-features --features bitcoind \
  --lib channel_funding_tests -- --test-threads=1
```

For an already owned isolated regtest fixture, set
`RGB_FUNDING_TEST_EXTERNAL=1` and provide `RGB_FUNDING_TEST_RPC_URL`,
`RGB_FUNDING_TEST_RPC_USER` and `RGB_FUNDING_TEST_RPC_PASSWORD` in the process
environment. This mode does not invoke the standard service initializer. The
RPC URL must use HTTP on `127.0.0.1` or `localhost`; each fixture verifies
`getblockchaininfo.chain == "regtest"` before any mutation and uses its dedicated
`rgb-channel-funding-source-tests` miner with fresh application wallet keys.
A fresh fixture mines 101 blocks once to mature the source funds. Repeated runs
reuse that miner; a bounded top-up can use only older miners created by this
harness with the `rgb-channel-funding-` prefix. Other wallets are never used.
After funding, only necessary confirmation blocks are mined on that isolated
chain. The harness does not use a proxy, stop services or reset any existing
wallet. Never select a shared or public network for these tests.

These are source-level funded builder tests. They do not replace LDK/RLN
channel-funding acceptance or native/mobile artifact qualification.
