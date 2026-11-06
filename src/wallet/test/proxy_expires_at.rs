//! End-to-end regression tests: a malicious sender proxy must not be able to crash or brick the
//! recipient wallet via the `expires_at` it returns from `ack.post`.
//!
//! The sender picks its proxy, so `expires_at` is attacker-controlled. If `broadcast_deadline`
//! adds the retention grace to it with plain `+` (`online.rs`) under `overflow-checks`, a value
//! near `i64::MAX` overflows and panics. A value of `i64::MAX - grace` is worse: it is stored as
//! the broadcast deadline, and from then on every `refresh` recomputes `deadline + margin` and
//! panics. Since that panic aborts the whole refresh (and `fail_transfers` panics too), the wallet
//! can no longer sync: it cannot receive the payment, settle anything pending, or clear the bad
//! transfer — it is bricked until its DB is edited by hand.
//!
//! These assert the correct behavior: refresh never panics and the wallet stays usable. The
//! `broadcast_deadline` unit test covers the arithmetic in isolation; these drive a real
//! send/receive over the regtest stack.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;

const AMOUNT: u64 = 66;

/// A sender proxy that forwards to the real one but rewrites what it hands the recipient: the
/// `ack.post` `expires_at`, and the released-TX fields (dropped so the transfer stays pending).
/// `server.info` advertises the minimum retention grace a recipient accepts, so the ACK proceeds.
struct MaliciousProxy {
    expires_at: Mutex<Option<String>>,
    hide_signed_tx: AtomicBool,
}

impl MaliciousProxy {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            expires_at: Mutex::new(None),
            hide_signed_tx: AtomicBool::new(false),
        })
    }
}

fn start_malicious_proxy(proxy: Arc<MaliciousProxy>) -> (mockito::ServerGuard, mockito::Mock) {
    json_rpc_proxy(move |req| {
        let body = req.body().unwrap().clone();
        let body_str = String::from_utf8_lossy(&body);
        let is_info = body_str.contains("\"server.info\"");
        let is_ack_post = body_str.contains("\"ack.post\"");
        let res = forward_to_proxy(req, body);
        if !is_info && !is_ack_post {
            return res;
        }
        let mut res: serde_json::Value = serde_json::from_slice(&res).unwrap();
        if let Some(result) = res.get_mut("result").and_then(|r| r.as_object_mut()) {
            if is_info {
                // advertise the minimum grace a recipient accepts, so the ACK proceeds
                result.insert(
                    s!("retention_grace_secs"),
                    MIN_SENDER_RETENTION_GRACE_SECS.to_string().into(),
                );
            }
            if is_ack_post {
                if let Some(expires_at) = proxy.expires_at.lock().unwrap().clone() {
                    result.insert(s!("expires_at"), expires_at.into());
                }
                if proxy.hide_signed_tx.load(Ordering::Relaxed) {
                    for field in ["signed_tx", "signed_tx_hash", "sender_pk"] {
                        result.remove(field);
                    }
                }
            }
        }
        serde_json::to_vec(&res).unwrap()
    })
}

fn endpoint_of(server: &mockito::ServerGuard) -> String {
    format!("rpc://{}/json-rpc", server.host_with_port())
}

/// Send `AMOUNT` of `asset_id` to the recipient of `receive_data`, through `sender_endpoint` as
/// the sender proxy (or the real test proxy when `None`).
fn send_to(
    sender: &mut SinglesigParty,
    asset_id: &str,
    receive_data: &ReceiveData,
    sender_endpoint: Option<String>,
) {
    let sender_endpoint = sender_endpoint.or_else(|| Some(PROXY_ENDPOINT.clone()));
    let recipient_map = HashMap::from([(
        asset_id.to_string(),
        vec![Recipient {
            assignment: Assignment::Fungible(AMOUNT),
            recipient_id: receive_data.recipient_id.clone(),
            public_key: Some(receive_data.public_key.clone()),
            expiration_timestamp: Some(receive_data.expiration_timestamp),
            encryption: Encryption::Optional,
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let send_result = sender
        .wallet
        .send(
            sender.online,
            recipient_map,
            false,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
            sender_endpoint,
        )
        .unwrap();
    assert!(!send_result.txid.is_empty());
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| s!("non-string panic"))
}

/// Run one `refresh` the way an app would; return the panic message if it panicked.
fn refresh_panic(party: &mut SinglesigParty) -> Option<String> {
    catch_unwind(AssertUnwindSafe(|| {
        let _ = party.refresh_result(None, &[]);
    }))
    .err()
    .map(panic_message)
}

/// Immediate variant: the proxy returns `expires_at = i64::MAX`. When `broadcast_deadline` adds
/// the grace unchecked:
/// 1. `expires_at + grace` overflows, so the receiving `refresh` panics.
/// 2. The panic happens before the deadline is computed, so no bad deadline comes from it.
///
/// A correct wallet handles the value without panicking.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn max_expires_at_handled_without_panic() {
    initialize();

    let mut attacker = get_funded_party!();
    let mut victim = get_funded_party!();
    let asset = attacker.issue_asset_nia(None);

    let proxy = MaliciousProxy::new();
    *proxy.expires_at.lock().unwrap() = Some(i64::MAX.to_string());
    proxy.hide_signed_tx.store(true, Ordering::Relaxed);
    let (server, _mock) = start_malicious_proxy(proxy.clone());

    let receive_data = victim.blind_receive();
    send_to(
        &mut attacker,
        &asset.asset_id,
        &receive_data,
        Some(endpoint_of(&server)),
    );

    // neither the receiving refresh nor a follow-up refresh may panic on the hostile expires_at
    let first = refresh_panic(&mut victim);
    let second = refresh_panic(&mut victim);
    assert!(
        first.is_none() && second.is_none(),
        "refresh panicked on a hostile expires_at: first {first:?}, second {second:?}"
    );
}

/// Permanent-brick variant: the proxy returns `expires_at = i64::MAX - grace`. When
/// `broadcast_deadline` adds the grace unchecked:
/// 1. `expires_at + grace` is exactly `i64::MAX`, so it doesn't overflow.
/// 2. `i64::MAX` is saved to the DB as the broadcast deadline.
/// 3. The next `refresh` panics on `deadline + margin`, as does `fail_transfers`.
/// 4. The value stays in the DB, so every later `refresh` panics too, even with the attacker gone,
///    and an unrelated honest transfer can't be received.
///
/// A correct wallet keeps refreshing and processes the honest transfer.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn hostile_expires_at_does_not_brick_wallet() {
    initialize();

    let mut attacker = get_funded_party!();
    let mut honest_sender = get_funded_party!();
    let mut victim = get_funded_party!();
    let asset = attacker.issue_asset_nia(None);
    let honest_asset = honest_sender.issue_asset_nia(None);

    let proxy = MaliciousProxy::new();
    *proxy.expires_at.lock().unwrap() =
        Some((i64::MAX - i64::from(MIN_SENDER_RETENTION_GRACE_SECS)).to_string());
    proxy.hide_signed_tx.store(true, Ordering::Relaxed);
    let (server, mock) = start_malicious_proxy(proxy.clone());

    let receive_data = victim.blind_receive();
    send_to(
        &mut attacker,
        &asset.asset_id,
        &receive_data,
        Some(endpoint_of(&server)),
    );

    // receiving the hostile transfer must not panic or store a deadline that later overflows
    assert_eq!(
        refresh_panic(&mut victim),
        None,
        "refresh panicked while receiving a hostile expires_at"
    );

    // the attacker and its proxy go away; the damage must not persist in the victim's own DB
    drop(mock);
    drop(server);

    // an honest, unrelated sender then pays the victim through the real proxy
    let honest_receive = victim.blind_receive();
    send_to(
        &mut honest_sender,
        &honest_asset.asset_id,
        &honest_receive,
        None,
    );

    // the wallet must keep working: no refresh and no fail_transfers may panic
    let refresh_panics: Vec<_> = (0..3).filter_map(|_| refresh_panic(&mut victim)).collect();
    let fail_panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = victim.fail_transfers(Some(receive_data.batch_transfer_idx), false, false);
    }))
    .err()
    .map(panic_message);
    assert!(
        refresh_panics.is_empty() && fail_panic.is_none(),
        "the wallet crash-looped: refresh panics {refresh_panics:?}, fail_transfers panic \
         {fail_panic:?}"
    );

    // and the honest transfer must get processed, not stranded behind the hostile one
    assert!(
        !victim.check_test_transfer_status_recipient(
            &honest_receive.recipient_id,
            TransferStatus::WaitingCounterparty,
        ),
        "the honest transfer was never processed; the wallet is stuck on the hostile transfer"
    );
}
