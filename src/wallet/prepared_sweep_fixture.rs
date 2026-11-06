//! Regtest fixture of the funded prepared sweep tests.
//!
//! The standard test services are used by default. An already owned isolated fixture can be
//! selected with `RGB_FUNDING_TEST_EXTERNAL=1` and explicit loopback RPC credentials; doing so
//! does not start, stop or reset any service. Every mutation follows a regtest-chain check and
//! uses a dedicated fixture-owned miner and freshly generated application wallet keys.

#![cfg(feature = "bitcoind")]

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use bdk_wallet::bitcoin::Amount;
use reqwest::blocking::Client;
use serde_json::{Value, json};

use super::*;
use crate::{
    AssetSchema, BitcoinNetwork,
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
            evm_chains: HashMap::new(),
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
