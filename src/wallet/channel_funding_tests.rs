//! Funded regression tests for the Rust-only channel funding builders.
//!
//! The standard test services are used by default. An already owned isolated fixture can be
//! selected with `RGB_FUNDING_TEST_EXTERNAL=1` and explicit loopback RPC credentials; doing so
//! does not start, stop or reset any service. Every mutation follows a regtest-chain check and
//! uses a dedicated fixture-owned miner and freshly generated application wallet keys.

#![cfg(feature = "bitcoind")]

use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, Instant},
};

use bdk_wallet::bitcoin::{Amount, absolute::LockTime, psbt::Psbt};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use serial_test::serial;

use super::{core::WalletCore, offline::WalletOffline, *};
use crate::{
    AssetSchema, Assignment, BitcoinNetwork, Encryption, Error, TransferStatus,
    keys::{WitnessVersion, generate_keys},
};

const SOURCE_MINER: &str = "rgb-channel-funding-source-tests";
const SOURCE_MINER_PREFIX: &str = "rgb-channel-funding-";

pub(super) struct Fixture {
    client: Client,
    url: String,
    user: String,
    password: String,
    miner: String,
    mining_address: String,
}

impl Fixture {
    pub(super) fn new() -> Self {
        if std::env::var("RGB_FUNDING_TEST_EXTERNAL").as_deref() != Ok("1") {
            super::test::initialize();
        }
        let url = std::env::var("RGB_FUNDING_TEST_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18443".into());
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert_eq!(parsed.scheme(), "http");
        assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
        assert!(parsed.username().is_empty() && parsed.password().is_none());
        assert_eq!(parsed.path(), "/");
        assert!(parsed.query().is_none() && parsed.fragment().is_none());
        let mut fixture = Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            url,
            user: std::env::var("RGB_FUNDING_TEST_RPC_USER").unwrap_or_else(|_| "user".into()),
            password: std::env::var("RGB_FUNDING_TEST_RPC_PASSWORD")
                .unwrap_or_else(|_| "default_password".into()),
            miner: SOURCE_MINER.into(),
            mining_address: String::new(),
        };
        // Never fund or mine before proving that the selected node is a disposable regtest.
        assert_eq!(
            fixture.rpc(false, "getblockchaininfo", json!([]))["chain"],
            "regtest"
        );
        let loaded = fixture.rpc(false, "listwallets", json!([]));
        if !loaded
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name.as_str() == Some(SOURCE_MINER))
        {
            let directory = fixture.rpc(false, "listwalletdir", json!([]));
            let exists = directory["wallets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["name"].as_str() == Some(SOURCE_MINER));
            fixture.rpc(
                false,
                if exists { "loadwallet" } else { "createwallet" },
                json!([SOURCE_MINER]),
            );
        }
        fixture.mining_address = fixture
            .rpc(true, "getnewaddress", json!([]))
            .as_str()
            .unwrap()
            .to_owned();
        fixture.ensure_source_funds(&loaded);
        fixture
    }

    fn trusted_sats(&self, name: &str) -> u64 {
        let value = self.named_wallet_rpc(name, "getbalances", json!([]));
        Amount::from_btc(value["mine"]["trusted"].as_f64().unwrap())
            .unwrap()
            .to_sat()
    }

    fn ensure_source_funds(&self, previously_loaded: &Value) {
        const BUDGET_SATS: u64 = 10_000_000;
        if self.trusted_sats(SOURCE_MINER) >= BUDGET_SATS {
            return;
        }
        // Repeated source suites must not spend another 101 blocks per case and exhaust
        // regtest's 150-block subsidy halvings. Reuse only this harness's older miners.
        let started = Instant::now();
        let mut candidates: Vec<_> = previously_loaded
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .filter(|name| *name != SOURCE_MINER && name.starts_with(SOURCE_MINER_PREFIX))
            .collect();
        candidates.sort_unstable();
        for name in candidates.into_iter().take(64) {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "owned source-miner scan timed out"
            );
            if self.trusted_sats(name) < 101_000_000 {
                continue;
            }
            self.named_wallet_rpc(name, "sendtoaddress", json!([self.mining_address, 1]));
            self.mine(1);
            break;
        }
        if self.trusted_sats(SOURCE_MINER) < BUDGET_SATS {
            let info = self.rpc(true, "getwalletinfo", json!([]));
            // A fresh CI fixture matures its dedicated miner exactly once. Existing
            // exhausted pools fail explicitly instead of mining indefinitely or borrowing
            // from unrelated wallets such as iris-output-tests or the shared stack.
            if info["txcount"].as_u64() == Some(0) {
                self.mine(101);
            }
        }
        assert!(
            self.trusted_sats(SOURCE_MINER) >= BUDGET_SATS,
            "owned source-test miner needs regtest funds; unrelated wallets are never used"
        );
    }

    fn named_wallet_rpc(&self, name: &str, method: &str, params: Value) -> Value {
        assert!(name.starts_with(SOURCE_MINER_PREFIX));
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        );
        self.request(
            format!("{}/wallet/{name}", self.url.trim_end_matches('/')),
            method,
            params,
        )
    }

    pub(super) fn rpc(&self, wallet: bool, method: &str, params: Value) -> Value {
        let endpoint = if wallet {
            format!("{}/wallet/{}", self.url.trim_end_matches('/'), self.miner)
        } else {
            self.url.clone()
        };
        self.request(endpoint, method, params)
    }

    fn request(&self, endpoint: String, method: &str, params: Value) -> Value {
        let response: Value = self
            .client
            .post(endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert!(
            matches!(&response["error"], Value::Null),
            "regtest RPC {method} failed: {}",
            response["error"]
        );
        response["result"].clone()
    }

    pub(super) fn mine(&self, count: u32) {
        self.rpc(
            false,
            "generatetoaddress",
            json!([count, self.mining_address]),
        );
    }

    pub(super) fn wallet(&self, fund: bool) -> (tempfile::TempDir, Wallet, Online) {
        let directory = tempfile::tempdir().unwrap();
        let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
        let mut wallet = Wallet::new(
            WalletData {
                data_dir: directory.path().to_str().unwrap().into(),
                bitcoin_network: BitcoinNetwork::Regtest,
                database_type: DatabaseType::Sqlite,
                max_allocations_per_utxo: 5,
                supported_schemas: vec![AssetSchema::Nia],
            },
            SinglesigKeys::from_keys(&keys, None),
        )
        .unwrap();
        if fund {
            self.rpc(
                true,
                "sendtoaddress",
                json!([wallet.get_address().unwrap(), 0.01]),
            );
            self.mine(1);
        }
        let online = wallet.go_online(self.online_options()).unwrap();
        (directory, wallet, online)
    }

    pub(super) fn online_options(&self) -> OnlineOptions {
        OnlineOptions {
            indexer_config: IndexerConfig::Bitcoind {
                url: self.url.clone(),
                auth: BitcoindAuth::UserPass {
                    username: self.user.clone(),
                    password: self.password.clone(),
                },
            },
            skip_consistency_check: false,
            vanilla_sync_lookback: 20,
            failed_witness_receive_grace_secs: 604800,
            proxy_auth_keys: HashMap::new(),
            evm_rpc_urls: HashMap::new(),
        }
    }

    pub(super) fn colored_wallet(&self) -> (tempfile::TempDir, Wallet, Online, String) {
        let (directory, mut wallet, online) = self.wallet(true);
        assert_eq!(
            wallet
                .create_utxos(online, false, Some(5), Some(10_000), 2, false)
                .unwrap(),
            5
        );
        self.mine(1);
        wallet
            .sync(
                online,
                SyncOptions {
                    keychain: SyncKeychain::Colored,
                    strategy: SyncStrategy::FullSync,
                },
            )
            .unwrap();
        let asset = wallet
            .issue_asset_nia("CHAN".into(), "Channel funding".into(), 0, vec![100])
            .unwrap();
        (directory, wallet, online, asset.asset_id)
    }
}

fn recipients(wallet: &mut Wallet, asset_id: &str, sats: u64) -> HashMap<String, Vec<Recipient>> {
    let receive = wallet
        .witness_receive(
            None,
            None,
            Assignment::Fungible(40),
            expiration(),
            vec![],
            1,
            None,
        )
        .unwrap();
    HashMap::from([(
        asset_id.into(),
        vec![Recipient {
            recipient_id: receive.recipient_id,
            witness_data: Some(WitnessData {
                amount_sat: sats,
                blinding: None,
            }),
            assignment: Assignment::Fungible(40),
            transport_endpoints: vec![],
            public_key: None,
            encryption: Encryption::Optional,
            expiration_timestamp: None,
        }],
    )])
}

fn expiration() -> u64 {
    (time::OffsetDateTime::now_utc().unix_timestamp() + 3600) as u64
}

fn assert_rgb_identity(wallet: &Wallet, begin: &SendBeginResult, persisted: bool) -> Psbt {
    let psbt = Psbt::from_str(&begin.psbt).unwrap();
    assert_eq!(psbt.unsigned_tx.lock_time, LockTime::ZERO);
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let directory = wallet.get_transfer_dir(&txid);
    assert_eq!(
        std::path::Path::new(&begin.details.fascia_path)
            .parent()
            .unwrap(),
        directory
    );
    assert!(std::path::Path::new(&begin.details.fascia_path).is_file());
    let disk_psbt =
        Psbt::from_str(&std::fs::read_to_string(directory.join(UNSIGNED_PSBT_FILE)).unwrap())
            .unwrap();
    assert_eq!(disk_psbt.unsigned_tx, psbt.unsigned_tx);
    let txn = wallet.database().begin_transaction().unwrap();
    let batches = txn.get_batch_transfers_by_txid(&txid).unwrap();
    if persisted {
        assert_eq!(batches.len(), 1);
        assert_eq!(Some(batches[0].idx), begin.batch_transfer_idx);
        assert_eq!(batches[0].status, TransferStatus::Initiated);
        let mut reserved = wallet.get_reserved_colored_outpoints(&txn).unwrap();
        let mut inputs: Vec<Outpoint> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| i.previous_output.into())
            .collect();
        reserved.sort_by_key(|o| o.to_string());
        inputs.sort_by_key(|o| o.to_string());
        assert_eq!(reserved, inputs);
    } else {
        assert!(begin.batch_transfer_idx.is_none());
        assert!(batches.is_empty());
        assert!(
            wallet
                .get_reserved_colored_outpoints(&txn)
                .unwrap()
                .is_empty()
        );
    }
    txn.commit().unwrap();
    psbt
}

fn assert_no_local_signer(wallet: &Wallet, psbt: String) {
    let original = Psbt::from_str(&psbt).unwrap();
    // The existing sign_psbt API permits partial signing: a watch-only wallet returns an
    // incomplete PSBT successfully. Prove that it contributes no signatures or witnesses.
    let attempted = Psbt::from_str(&wallet.sign_psbt(psbt, None).unwrap()).unwrap();
    assert_eq!(attempted.unsigned_tx, original.unsigned_tx);
    assert!(attempted.inputs.iter().all(|input| {
        input.partial_sigs.is_empty()
            && input.tap_key_sig.is_none()
            && input.tap_script_sigs.is_empty()
            && input.final_script_sig.is_none()
            && input.final_script_witness.is_none()
    }));
}

#[test]
#[serial]
fn vanilla_funding_zero_locktime_dry_run_reservation_and_broadcast_identity() {
    let fixture = Fixture::new();
    let (_dir, mut wallet, online) = fixture.wallet(true);
    let address = fixture
        .rpc(true, "getnewaddress", json!([]))
        .as_str()
        .unwrap()
        .to_owned();
    let ordinary = wallet
        .send_btc_begin(online, address.clone(), 50_000, 2, false, true)
        .unwrap();
    assert_ne!(
        Psbt::from_str(&ordinary).unwrap().unsigned_tx.lock_time,
        LockTime::ZERO
    );
    let preview = wallet
        .send_btc_channel_funding_begin(online, address.clone(), 50_000, 2, false, true)
        .unwrap();
    assert_eq!(
        Psbt::from_str(&preview).unwrap().unsigned_tx.lock_time,
        LockTime::ZERO
    );
    assert!(wallet.list_pending_vanilla_txs().unwrap().is_empty());
    let prepared = wallet
        .send_btc_channel_funding_begin(online, address, 50_000, 2, true, false)
        .unwrap();
    let prepared = Psbt::from_str(&prepared).unwrap();
    assert_eq!(prepared.unsigned_tx.lock_time, LockTime::ZERO);
    let txid = prepared.unsigned_tx.compute_txid().to_string();
    let pending = wallet.list_pending_vanilla_txs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].txid, txid);
    let signed = wallet.sign_psbt(prepared.to_string(), None).unwrap();
    assert_eq!(
        Psbt::from_str(&signed).unwrap().unsigned_tx,
        prepared.unsigned_tx
    );
    assert_eq!(wallet.send_btc_end(online, signed).unwrap(), txid);
    assert!(wallet.list_pending_vanilla_txs().unwrap().is_empty());
    assert_eq!(
        fixture.rpc(false, "getrawtransaction", json!([txid, true]))["locktime"],
        0
    );
}

#[test]
#[serial]
fn rgb_funding_zero_locktime_fee_input_retry_and_persisted_identity() {
    let fixture = Fixture::new();
    let (_dir, mut wallet, online, asset_id) = fixture.colored_wallet();
    let (_receiver_dir, mut receiver, _) = fixture.wallet(false);
    let ordinary = wallet
        .send_begin(
            online,
            recipients(&mut receiver, &asset_id, 30_000),
            true,
            2,
            1,
            expiration(),
            None,
            true,
        )
        .unwrap();
    assert_ne!(
        Psbt::from_str(&ordinary.psbt)
            .unwrap()
            .unsigned_tx
            .lock_time,
        LockTime::ZERO
    );
    let preview = wallet
        .send_channel_funding_begin(
            online,
            recipients(&mut receiver, &asset_id, 30_000),
            true,
            2,
            1,
            expiration(),
            None,
            true,
        )
        .unwrap();
    let preview = assert_rgb_identity(&wallet, &preview, false);
    // The RGB allocation lives on one 10,000-sat input. The 30,000-sat witness output
    // forces the actual builder to retry with additional uncolored allocation inputs.
    assert!(preview.unsigned_tx.input.len() >= 4);
    let begin = wallet
        .send_channel_funding_begin(
            online,
            recipients(&mut receiver, &asset_id, 30_000),
            true,
            2,
            1,
            expiration(),
            None,
            false,
        )
        .unwrap();
    let prepared = assert_rgb_identity(&wallet, &begin, true);
    assert!(prepared.unsigned_tx.input.len() >= 4);
    let signed = wallet.sign_psbt(begin.psbt, None).unwrap();
    assert_eq!(
        Psbt::from_str(&signed).unwrap().unsigned_tx,
        prepared.unsigned_tx
    );
    let result = wallet.send_end(online, signed).unwrap();
    assert_eq!(result.txid, prepared.unsigned_tx.compute_txid().to_string());
    assert_eq!(Some(result.batch_transfer_idx), begin.batch_transfer_idx);
    assert_eq!(
        fixture.rpc(false, "getrawtransaction", json!([result.txid, true]))["locktime"],
        0
    );
}

#[test]
#[serial]
fn funding_builders_preserve_validation_failures_and_do_not_reserve_failed_requests() {
    let fixture = Fixture::new();
    let (_dir, mut wallet, online) = fixture.wallet(false);
    let address = fixture
        .rpc(true, "getnewaddress", json!([]))
        .as_str()
        .unwrap()
        .to_owned();
    assert!(matches!(
        wallet.send_btc_channel_funding_begin(online, address.clone(), 50_000, 2, false, false),
        Err(Error::InsufficientBitcoins { .. })
    ));
    assert!(matches!(
        wallet.send_btc_channel_funding_begin(online, address, 50_000, 0, true, false),
        Err(Error::InvalidFeeRate { .. })
    ));
    assert!(matches!(
        wallet.send_channel_funding_begin(
            online,
            HashMap::new(),
            true,
            2,
            1,
            expiration(),
            None,
            false
        ),
        Err(Error::InvalidRecipientMap)
    ));
    assert!(matches!(
        wallet.send_btc_channel_funding_begin(
            Online {
                id: online.id.wrapping_add(1)
            },
            "not-an-address".into(),
            50_000,
            2,
            true,
            false
        ),
        Err(Error::CannotChangeOnline)
    ));
    assert!(wallet.list_pending_vanilla_txs().unwrap().is_empty());
}

#[test]
#[serial]
fn funding_builders_accept_watch_only_wallets_without_local_signer_fallback() {
    let fixture = Fixture::new();
    let (_dir, wallet, _, asset_id) = fixture.colored_wallet();
    let data = wallet.wallet_data().clone();
    let mut keys = wallet.keys.clone();
    keys.mnemonic = None;
    drop(wallet);
    let mut wallet = Wallet::new(data, keys).unwrap();
    assert!(wallet.get_keys().mnemonic.is_none());
    let online = wallet.go_online(fixture.online_options()).unwrap();
    let address = fixture
        .rpc(true, "getnewaddress", json!([]))
        .as_str()
        .unwrap()
        .to_owned();
    let btc = wallet
        .send_btc_channel_funding_begin(online, address, 50_000, 2, false, true)
        .unwrap();
    assert_eq!(
        Psbt::from_str(&btc).unwrap().unsigned_tx.lock_time,
        LockTime::ZERO
    );
    assert_no_local_signer(&wallet, btc);
    let (_receiver_dir, mut receiver, _) = fixture.wallet(false);
    let begin = wallet
        .send_channel_funding_begin(
            online,
            recipients(&mut receiver, &asset_id, 1000),
            true,
            2,
            1,
            expiration(),
            None,
            false,
        )
        .unwrap();
    assert_rgb_identity(&wallet, &begin, true);
    assert_no_local_signer(&wallet, begin.psbt);
}
