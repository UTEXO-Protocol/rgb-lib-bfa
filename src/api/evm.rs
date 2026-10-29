use super::*;

/// Selector of `getFundsInBlock(uint256,uint256)` on a bridge contract (`MinimalBridge`)
const FUNDS_IN_BLOCK_SELECTOR: &str = "0x2ce06e2d";

/// Selector of `length()` on a reject list contract (`IRgbRejectList`)
const REJECT_LIST_LENGTH_SELECTOR: &str = "0x1f7b6d32";
/// Selector of `entries(uint256,uint256)` on a reject list contract (`IRgbRejectList`)
const REJECT_LIST_ENTRIES_SELECTOR: &str = "0x17b937e6";
/// Maximum number of reject list entries requested with a single `entries` call
///
/// The contract doesn't bound pages, the `eth_call` gas cap and timeout of the node do.
const REJECT_LIST_PAGE_SIZE: u64 = 1000;
/// Number of times a JSON-RPC request is sent again when it fails for a temporary reason (see
/// [`EvmClient::post`])
const RPC_RETRIES: u32 = 2;
/// Pause before sending a JSON-RPC request again, multiplied by the number of the retry
#[cfg(not(test))]
const RPC_RETRY_PAUSE: Duration = Duration::from_secs(1);
#[cfg(test)]
const RPC_RETRY_PAUSE: Duration = Duration::from_millis(10);

/// The status of the lock confirming a mint, which has to be included on the external chain
/// before the block the mint commits to (`before_block`), as recorded by the bridge contract as of
/// the latest finalized block (see [`EvmClient::mint_lock_status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintLockStatus {
    /// The lock is recorded, included before `before_block`
    Confirmed,
    /// No lock is recorded yet, but one may still be included before `before_block`
    Pending,
    /// The lock is recorded, but not included before `before_block`, or none is and the blocks
    /// before `before_block` are all finalized: the mint will never be confirmed
    Expired,
}

/// JSON-RPC client for an EVM node.
pub struct EvmClient {
    client: RestClient,
    rpc_url: String,
}

/// Strip the `0x` prefix the JSON-RPC API puts on every hex-encoded value, refusing values
/// without it.
fn strip_hex_prefix<'a>(value: &'a str, what: &str) -> Result<&'a str, Error> {
    value.strip_prefix("0x").ok_or_else(|| Error::Network {
        details: format!("invalid EVM {what} {value}: missing 0x prefix"),
    })
}

/// Parse a hex-encoded (`0x`-prefixed) quantity.
fn parse_quantity(value: &str, what: &str) -> Result<u64, Error> {
    u64::from_str_radix(strip_hex_prefix(value, what)?, 16).map_err(|e| Error::Network {
        details: format!("invalid EVM {what} {value}: {e}"),
    })
}

/// Parse a hex-encoded (`0x`-prefixed) block number.
fn parse_block_number(hex_block: &str) -> Result<u64, Error> {
    parse_quantity(hex_block, "block number")
}

#[derive(Debug, Serialize)]
struct NullRequest;

/// Decode a hex-encoded ABI word (32 bytes) at the given word index from `data`.
/// `data` must start with "0x".
fn abi_word(data: &str, index: usize) -> Result<[u8; 32], Error> {
    // work on bytes: slicing the str could split a (bogus) multi-byte char and panic
    let hex = strip_hex_prefix(data, "ABI data")?.as_bytes();
    let start = index * 64;
    let end = start + 64;
    if hex.len() < end {
        return Err(Error::Network {
            details: format!("ABI data too short: expected at least {end} hex chars"),
        });
    }
    let mut buf = [0u8; 32];
    hex::decode_to_slice(&hex[start..end], &mut buf).map_err(|e| Error::Network {
        details: format!("ABI hex decode error: {e}"),
    })?;
    Ok(buf)
}

/// Decode a hex-encoded ABI word as a `u64` at the given word index from `data`.
/// Returns `None` if the uint256 value doesn't fit in a `u64`.
fn abi_word_u64(data: &str, index: usize) -> Result<Option<u64>, Error> {
    let word = abi_word(data, index)?;
    if word[..24].iter().any(|b| *b != 0) {
        return Ok(None);
    }
    Ok(Some(u64::from_be_bytes(word[24..32].try_into().unwrap())))
}

/// An entry of a reject list kept by an EVM contract (`IRgbRejectList.Entry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RejectListEntry {
    /// RGB operation output the decision applies to.
    pub opout: Opout,
    /// Whether the opout is rejected (`true`) or allowed (`false`).
    pub reject: bool,
}

/// The entries of a reject list kept by an EVM contract, in append order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RejectListLog {
    /// All the entries, as of the latest block.
    pub entries: Vec<RejectListEntry>,
    /// How many of the leading entries were appended in finalized blocks.
    pub finalized: usize,
}

impl RejectListLog {
    /// The opouts currently rejected and allowed, as `(reject, allow)`.
    ///
    /// The latest entry for an opout wins, but entries in non-finalized blocks could still be
    /// dropped or reordered by a reorg. So, erring on the safe side, a reject counts as soon as
    /// it's seen, while an allow counts only once finalized: an opout is rejected if its finalized
    /// decision is a reject or if any non-finalized entry rejects it, and allowed if its finalized
    /// decision is an allow and no non-finalized entry rejects it.
    pub(crate) fn decisions(&self) -> (HashSet<Opout>, HashSet<Opout>) {
        let (finalized, pending) = self.entries.split_at(self.finalized);
        let finalized = finalized
            .iter()
            .map(|e| (e.opout, e.reject))
            .collect::<HashMap<_, _>>();
        let pending_rejects = pending
            .iter()
            .filter(|e| e.reject)
            .map(|e| e.opout)
            .collect::<HashSet<_>>();
        let (mut reject, mut allow) = (pending_rejects, HashSet::new());
        for (opout, rejected) in finalized {
            if rejected {
                reject.insert(opout);
            } else if !reject.contains(&opout) {
                allow.insert(opout);
            }
        }
        (reject, allow)
    }
}

fn abi_error(details: &str) -> Error {
    Error::Network {
        details: format!("invalid ABI data: {details}"),
    }
}

/// Decode a hex-encoded ABI word as a `uint16` at the given word index from `data`.
fn abi_word_u16(data: &str, index: usize) -> Result<u16, Error> {
    abi_word_u64(data, index)?
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| abi_error("bad uint16"))
}

/// Decode the result of `entries(uint256,uint256)`, an ABI-encoded
/// `(bytes32, uint16, uint16, bool)[]`: the offset of the array, its length, then each entry
/// inline as four words.
fn decode_reject_list_entries(data: &str) -> Result<Vec<RejectListEntry>, Error> {
    let offset = abi_word_u64(data, 0)?
        .filter(|o| o % 32 == 0)
        .ok_or_else(|| abi_error("bad array offset"))?;
    let len_index = (offset / 32) as usize;
    let len = abi_word_u64(data, len_index)?.ok_or_else(|| abi_error("bad array length"))?;
    let mut entries = vec![];
    for i in 0..len as usize {
        let base = len_index + 1 + 4 * i;
        let opout = Opout {
            op: OpId::from(abi_word(data, base)?),
            ty: AssignmentType::with(abi_word_u16(data, base + 1)?),
            no: abi_word_u16(data, base + 2)?,
        };
        let reject = match abi_word_u64(data, base + 3)? {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(abi_error("bad bool")),
        };
        entries.push(RejectListEntry { opout, reject });
    }
    Ok(entries)
}

/// ABI-encode a `uint256` argument as a hex word.
fn abi_encode_u64(value: u64) -> String {
    format!("{value:064x}")
}

/// JSON-RPC request envelope.
#[derive(Debug, Serialize)]
struct RpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    params: P,
    id: u64,
}

/// JSON-RPC response envelope, carrying either the result or the error of the request.
#[derive(Debug, Deserialize)]
struct RpcResponse<R> {
    result: Option<R>,
    error: Option<RpcError>,
}

/// Error object of a JSON-RPC response.
#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// Transaction call object for `eth_call`.
#[derive(Debug, Serialize)]
struct CallObject {
    /// Contract address to call.
    to: String,
    /// ABI-encoded call data (hex).
    data: String,
}

/// The part of a block header returned by `eth_getBlockByNumber` that is needed here.
#[derive(Debug, Deserialize)]
struct BlockHeader {
    /// Block number (hex).
    number: String,
}

impl EvmClient {
    pub(crate) fn new(rpc_url: &str) -> Result<Self, Error> {
        let client = RestClient::builder()
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT))
            .timeout(Duration::from_secs(READ_WRITE_TIMEOUT))
            .build()?;
        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
        })
    }

    fn req_err(e: impl std::fmt::Display) -> Error {
        Error::Network {
            details: format!("EVM RPC: {e}"),
        }
    }

    /// Post a JSON-RPC request, sending it again (up to [`RPC_RETRIES`] times, after a pause)
    /// when it fails for a temporary reason: it cannot be sent (e.g. for a dropped connection or a
    /// failed DNS lookup) or the node answering it is temporarily unavailable (HTTP 502, 503 or
    /// 504). The requests of this client only read the chain, so they can be repeated.
    ///
    /// A timed out request is not sent again, as it already took long.
    fn post(&self, body: &impl Serialize) -> Result<Response, Error> {
        let mut retries = 0;
        loop {
            let res = self
                .client
                .post(&self.rpc_url)
                .header(CONTENT_TYPE, JSON)
                .json(body)
                .send();
            let temporary = match &res {
                Ok(resp) => matches!(
                    resp.status(),
                    StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                ),
                Err(e) => !e.is_timeout() && !e.is_builder(),
            };
            if !temporary || retries == RPC_RETRIES {
                return res.map_err(Self::req_err);
            }
            retries += 1;
            std::thread::sleep(RPC_RETRY_PAUSE * retries);
        }
    }

    /// The block the lock of the mint of `amount` with operation `opid` was included in, as
    /// recorded by the bridge contract at `contract` as of `block`, if any.
    ///
    /// The contract keeps a permanent record of each lock, keyed by the operation ID and the
    /// amount (`getFundsInBlock`), so a single call tells whether, and where, the mint was locked.
    /// An address with no code (calling it returns no data) or a contract without the function
    /// (calling it reverts) cannot have recorded any lock.
    fn funds_in_block(
        &self,
        contract: &EvmAddress,
        opid: &OpId,
        amount: u64,
        block: u64,
    ) -> Result<Option<u64>, Error> {
        let data = format!(
            "{FUNDS_IN_BLOCK_SELECTOR}{}{}",
            hex::encode(opid.to_byte_array()),
            abi_encode_u64(amount)
        );
        let Some(result) = self.eth_call_unless_reverted(contract, data, block)? else {
            return Ok(None);
        };
        if result == "0x" {
            return Ok(None);
        }
        // compare the hex length exactly: a length rounded to whole words would let trailing
        // data through
        if strip_hex_prefix(&result, "ABI data")?.len() != 64 {
            return Err(abi_error("unexpected getFundsInBlock result size"));
        }
        // the record is the block plus one, zero meaning there's none
        let block_plus_one = abi_word_u64(&result, 0)?
            .ok_or_else(|| abi_error("lock block doesn't fit in a u64"))?;
        Ok(block_plus_one.checked_sub(1))
    }

    /// The status of the lock of the mint of `amount` with operation `opid`, which has to be
    /// included before `before_block`, as recorded by the bridge contract at `contract` as of the
    /// latest finalized block.
    pub(crate) fn mint_lock_status(
        &self,
        contract: &EvmAddress,
        opid: &OpId,
        amount: u64,
        before_block: u64,
    ) -> Result<MintLockStatus, Error> {
        let finalized_block = self.finalized_block_number()?;
        Ok(
            match self.funds_in_block(contract, opid, amount, finalized_block)? {
                Some(block) if block < before_block => MintLockStatus::Confirmed,
                Some(_) => MintLockStatus::Expired,
                // a lock not recorded as of the finalized block can only be included after it
                None if finalized_block.saturating_add(1) >= before_block => {
                    MintLockStatus::Expired
                }
                None => MintLockStatus::Pending,
            },
        )
    }

    /// Call a JSON-RPC method, failing if it reports an error or no result.
    fn rpc<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<R, Error> {
        self.try_rpc(method, params)?.map_err(|err| Error::Network {
            details: format!("{method} error {}: {}", err.code, err.message),
        })
    }

    /// Call a JSON-RPC method, returning the error it reports apart from the other failures, and
    /// failing if it reports no result.
    fn try_rpc<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<Result<R, RpcError>, Error> {
        let body = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: 1,
        };
        let resp: RpcResponse<R> = self.post(&body)?.json().map_err(Self::req_err)?;

        if let Some(err) = resp.error {
            return Ok(Err(err));
        }

        resp.result.map(Ok).ok_or_else(|| Error::Network {
            details: format!("{method} returned null result"),
        })
    }

    /// Number of the latest block (`eth_blockNumber`).
    pub(crate) fn block_number(&self) -> Result<u64, Error> {
        parse_block_number(&self.rpc::<_, String>("eth_blockNumber", NullRequest)?)
    }

    /// Call `contract` with `data` (`eth_call`) as of `block`, returning the raw result.
    fn eth_call(&self, contract: &EvmAddress, data: String, block: u64) -> Result<String, Error> {
        let call = CallObject {
            to: contract.to_string(),
            data,
        };
        self.rpc("eth_call", (call, format!("0x{block:x}")))
    }

    /// Call `contract` with `data` (`eth_call`) as of `block`, returning the raw result, or `None`
    /// if the call reverts.
    fn eth_call_unless_reverted(
        &self,
        contract: &EvmAddress,
        data: String,
        block: u64,
    ) -> Result<Option<String>, Error> {
        let call = CallObject {
            to: contract.to_string(),
            data,
        };
        match self.try_rpc("eth_call", (call, format!("0x{block:x}")))? {
            Ok(result) => Ok(Some(result)),
            // nodes report a revert with this message, followed by the reason if there's one
            Err(err) if err.message.starts_with("execution reverted") => Ok(None),
            Err(err) => Err(Error::Network {
                details: format!("eth_call error {}: {}", err.code, err.message),
            }),
        }
    }

    /// All the entries of the reject list kept by the `IRgbRejectList` contract at `contract`,
    /// in append order, telling which ones are finalized.
    ///
    /// The list is append-only, so the entries as of the latest finalized block are the leading
    /// ones as of the latest block: only the length is read at the former, while the length and
    /// every page are read as of the latter, so that entries appended in the meantime cannot make
    /// the result inconsistent.
    pub(crate) fn reject_list_entries(
        &self,
        contract: &EvmAddress,
    ) -> Result<RejectListLog, Error> {
        self.reject_list_entries_paged(contract, REJECT_LIST_PAGE_SIZE)
    }

    /// Length of the reject list kept by the `IRgbRejectList` contract at `contract` as of `block`.
    ///
    /// Returns `None` if there is no contract at `contract` as of `block`: calling an address with
    /// no code returns no data.
    fn reject_list_length(&self, contract: &EvmAddress, block: u64) -> Result<Option<u64>, Error> {
        let len_data = self.eth_call(contract, REJECT_LIST_LENGTH_SELECTOR.to_string(), block)?;
        if len_data == "0x" {
            return Ok(None);
        }
        abi_word_u64(&len_data, 0)?
            .map(Some)
            .ok_or_else(|| abi_error("reject list length doesn't fit in a u64"))
    }

    fn reject_list_entries_paged(
        &self,
        contract: &EvmAddress,
        page_size: u64,
    ) -> Result<RejectListLog, Error> {
        let block = self.block_number()?;
        // a node behind a load balancer could report a finalized block past the latest one read
        let finalized_block = std::cmp::min(self.finalized_block_number()?, block);
        // a contract deployed in a non-finalized block has no finalized entries
        let finalized_len = self
            .reject_list_length(contract, finalized_block)?
            .unwrap_or(0);
        let len = self
            .reject_list_length(contract, block)?
            .ok_or_else(|| Error::Network {
                details: format!("no contract at the reject list address {contract}"),
            })?;
        if finalized_len > len {
            return Err(Error::Network {
                details: s!("reject list shorter at the latest block than at the finalized one"),
            });
        }
        if len > MAX_REJECT_LIST_ENTRIES {
            return Err(Error::Network {
                details: format!(
                    "reject list too long: {len} entries, at most {MAX_REJECT_LIST_ENTRIES} supported"
                ),
            });
        }
        let mut entries = vec![];
        let mut start = 0;
        while start < len {
            let end = std::cmp::min(start.saturating_add(page_size), len);
            let data = format!(
                "{REJECT_LIST_ENTRIES_SELECTOR}{}{}",
                abi_encode_u64(start),
                abi_encode_u64(end)
            );
            let page = decode_reject_list_entries(&self.eth_call(contract, data, block)?)?;
            if page.len() as u64 != end - start {
                return Err(abi_error("unexpected reject list page size"));
            }
            entries.extend(page);
            start = end;
        }
        Ok(RejectListLog {
            entries,
            finalized: finalized_len as usize,
        })
    }

    /// Call a JSON-RPC method taking no parameters and returning a string.
    fn call_no_params(&self, method: &'static str) -> Result<String, Error> {
        let body: RpcRequest<NullRequest> = RpcRequest {
            jsonrpc: "2.0",
            method,
            params: NullRequest,
            id: 1,
        };
        let resp: RpcResponse<String> = self.post(&body)?.json().map_err(Self::req_err)?;

        if let Some(err) = resp.error {
            return Err(Error::Network {
                details: format!("{method} error {}: {}", err.code, err.message),
            });
        }

        resp.result.ok_or_else(|| Error::Network {
            details: format!("{method} returned null result"),
        })
    }

    /// Number of the latest finalized block (`eth_getBlockByNumber` with the `finalized` tag).
    ///
    /// Finality is the chain's own notion of irreversibility, whatever its consensus: two
    /// justified epochs on Ethereum, a milestone on Polygon, a batch finalized on L1 for a
    /// rollup, and so on. A reorged-out mint event would permanently invalidate the RGB-side
    /// history for every future receiver, so events are only accepted once finalized.
    pub(crate) fn finalized_block_number(&self) -> Result<u64, Error> {
        let method = "eth_getBlockByNumber";
        let body = RpcRequest {
            jsonrpc: "2.0",
            method,
            params: ("finalized", false),
            id: 1,
        };
        let resp: RpcResponse<Option<BlockHeader>> =
            self.post(&body)?.json().map_err(Self::req_err)?;

        if let Some(err) = resp.error {
            return Err(Error::Network {
                details: format!("{method} error {}: {}", err.code, err.message),
            });
        }

        let header = resp.result.flatten().ok_or_else(|| Error::Network {
            details: s!("the node reports no finalized block"),
        })?;
        parse_block_number(&header.number)
    }

    /// Check that the node serves what confirming mints needs, failing with an
    /// [`Error::InvalidEvmRpcUrl`] if it doesn't: the latest finalized block and the contract
    /// state as of it, since locks are only accepted once finalized and are read from the records
    /// of the bridge contract.
    ///
    /// The finalized block can be older than the blocks whose state some nodes keep (e.g. pruned
    /// ones), which would make the confirmation of a mint fail later, when receiving an asset.
    #[cfg(feature = "_online")]
    pub(crate) fn check_mint_support(&self) -> Result<(), Error> {
        let finalized_block =
            self.finalized_block_number()
                .map_err(|e| Error::InvalidEvmRpcUrl {
                    details: format!("cannot get the latest finalized block: {e}"),
                })?;
        self.eth_call(&EvmAddress::default(), s!("0x"), finalized_block)
            .map_err(|e| Error::InvalidEvmRpcUrl {
                details: format!(
                    "cannot read the state as of the latest finalized block, an endpoint keeping \
                     it is needed: {e}"
                ),
            })?;
        Ok(())
    }

    /// EIP-155 chain ID of the chain the node is connected to (`eth_chainId`).
    pub(crate) fn chain_id(&self) -> Result<u64, Error> {
        parse_quantity(&self.call_no_params("eth_chainId")?, "chain ID")
    }
}

/// Report a JSON-RPC client failure as the anchor resolver's issue.
///
/// The client only fails with [`Error::Network`]s: their details are reported as they are, to
/// avoid wrapping them in a second network error once mapped back to an [`Error`].
fn resolver_issue(e: Error) -> AnchorResolverError {
    match e {
        Error::Network { details } => AnchorResolverError::ResolverIssue(details),
        e => AnchorResolverError::ResolverIssue(e.to_string()),
    }
}

impl ResolveAnchor for EvmClient {
    fn evm_chain_id(&self) -> Result<u64, AnchorResolverError> {
        self.chain_id().map_err(resolver_issue)
    }

    /// Whether the bridge contract at `location` recorded a lock confirming `anchor`, as of the
    /// latest finalized block: one of the anchor's amount committing to its operation ID, included
    /// before the block the anchor commits to.
    fn is_confirmed(
        &self,
        location: &BridgeLocation,
        anchor: &ExternalAnchor,
    ) -> Result<bool, AnchorResolverError> {
        let BridgeLocation::Evm(EvmContract { address, .. }) = location;
        let ExternalAnchor::Mint {
            opid,
            amount,
            before_block,
        } = anchor;
        let status = self
            .mint_lock_status(address, opid, *amount, *before_block)
            .map_err(resolver_issue)?;
        Ok(status == MintLockStatus::Confirmed)
    }
}

/// An anchor resolver over an [`EvmClient`] recording the mints that will never be confirmed,
/// their lock not included before the block they commit to (see [`MintLockStatus::Expired`]).
pub(crate) struct MintAnchorResolver<'a> {
    client: &'a EvmClient,
    /// Operation IDs of the mints that will never be confirmed
    expired: RefCell<HashSet<OpId>>,
}

impl<'a> MintAnchorResolver<'a> {
    pub(crate) fn new(client: &'a EvmClient) -> Self {
        Self {
            client,
            expired: RefCell::new(HashSet::new()),
        }
    }

    /// Whether the mint with the given operation ID was found to never be confirmed.
    ///
    /// A mint that is not confirmed but not expired may still be, once its lock is made or
    /// finalized.
    pub(crate) fn is_expired(&self, opid: &OpId) -> bool {
        self.expired.borrow().contains(opid)
    }
}

impl ResolveAnchor for MintAnchorResolver<'_> {
    fn evm_chain_id(&self) -> Result<u64, AnchorResolverError> {
        self.client.evm_chain_id()
    }

    /// Whether `anchor` is confirmed, as [`EvmClient`] resolves it, recording it if it expired.
    fn is_confirmed(
        &self,
        location: &BridgeLocation,
        anchor: &ExternalAnchor,
    ) -> Result<bool, AnchorResolverError> {
        let BridgeLocation::Evm(EvmContract { address, .. }) = location;
        let ExternalAnchor::Mint {
            opid,
            amount,
            before_block,
        } = anchor;
        let status = self
            .client
            .mint_lock_status(address, opid, *amount, *before_block)
            .map_err(resolver_issue)?;
        if status == MintLockStatus::Expired {
            self.expired.borrow_mut().insert(*opid);
        }
        Ok(status == MintLockStatus::Confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An opout whose operation ID is filled with `b`, with an assignment type and number derived
    /// from `b` too, all different, so that decoding them in the wrong order is caught.
    fn test_opout(b: u8) -> Opout {
        Opout {
            op: OpId::from([b; 32]),
            ty: AssignmentType::with(4000 + b as u16),
            no: 100 + b as u16,
        }
    }

    fn test_entry(b: u8, reject: bool) -> RejectListEntry {
        RejectListEntry {
            opout: test_opout(b),
            reject,
        }
    }

    #[test]
    fn reject_list_entries() {
        // abi.encode of [(0x01..01, 4001, 101, true), (0x02..02, 4002, 102, false)]
        let page = format!(
            "0x{:064x}{:064x}{}{:064x}{:064x}{:064x}{}{:064x}{:064x}{:064x}",
            32,
            2,
            "01".repeat(32),
            4001,
            101,
            1,
            "02".repeat(32),
            4002,
            102,
            0
        );
        assert_eq!(page, encode_entries(&[(1, true), (2, false)]));
        let expected = vec![test_entry(1, true), test_entry(2, false)];
        assert_eq!(decode_reject_list_entries(&page).unwrap(), expected);
        // an empty page
        let empty = format!("0x{:064x}{:064x}", 32, 0);
        assert!(decode_reject_list_entries(&empty).unwrap().is_empty());
        // a bool word other than 0 or 1 is refused
        let bad_bool = format!(
            "0x{:064x}{:064x}{}{:064x}{:064x}{:064x}",
            32,
            1,
            "01".repeat(32),
            1,
            0,
            2
        );
        assert!(decode_reject_list_entries(&bad_bool).is_err());
        // an assignment type or output number not fitting a uint16 is refused
        for (ty, no) in [(1 << 16, 0), (0, 1 << 16)] {
            let bad_u16 = format!(
                "0x{:064x}{:064x}{}{:064x}{:064x}{:064x}",
                32,
                1,
                "01".repeat(32),
                ty,
                no,
                1
            );
            let result = decode_reject_list_entries(&bad_u16);
            assert!(
                matches!(result, Err(Error::Network { ref details }) if details.contains("bad uint16")),
                "{result:?}"
            );
        }
        // a truncated page is refused
        assert!(decode_reject_list_entries(&page[..page.len() - 64]).is_err());

        let mut server = mockito::Server::new();
        let block_number = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"method":"eth_blockNumber"}"#.to_string(),
            ))
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x10"}"#)
            .create();
        let finalized_block = mock_finalized_block(&mut server, 8);
        let finalized_length = mock_eth_call_at(
            &mut server,
            8,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 1),
        );
        let length = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(format!(
                r#"{{"method":"eth_call","params":[{{"data":"{REJECT_LIST_LENGTH_SELECTOR}"}},"0x10"]}}"#
            )))
            .with_body(format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":"0x{:064x}"}}"#,
                2
            ))
            .create();
        let entries = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(format!(
                r#"{{"method":"eth_call","params":[{{"data":"{REJECT_LIST_ENTRIES_SELECTOR}{:064x}{:064x}"}},"0x10"]}}"#,
                0, 2
            )))
            .with_body(format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{page}"}}"#))
            .create();
        let client = EvmClient::new(&server.url()).unwrap();
        assert_eq!(
            client.reject_list_entries(&EvmAddress::default()).unwrap(),
            RejectListLog {
                entries: expected,
                finalized: 1,
            }
        );
        block_number.assert();
        finalized_block.assert();
        finalized_length.assert();
        length.assert();
        entries.assert();
    }

    /// ABI-encode reject list entries as returned by `entries`, each entry being the byte its
    /// opout is derived from (see `test_opout`) and whether it is rejected.
    fn encode_entries(entries: &[(u8, bool)]) -> String {
        let mut data = format!("0x{:064x}{:064x}", 32, entries.len());
        for (b, reject) in entries {
            let opout = test_opout(*b);
            data.push_str(&hex::encode(opout.op.to_byte_array()));
            data.push_str(&format!("{:064x}", opout.ty.to_inner()));
            data.push_str(&format!("{:064x}", opout.no));
            data.push_str(&format!("{:064x}", *reject as u8));
        }
        data
    }

    /// Mock an `eth_call` at block 0x10 (the latest one) with the given call `data`, returning
    /// `result`.
    fn mock_eth_call(server: &mut mockito::Server, data: &str, result: &str) -> mockito::Mock {
        mock_eth_call_at(server, 0x10, data, result)
    }

    /// Mock an `eth_call` at `block` with the given call `data`, returning `result`.
    fn mock_eth_call_at(
        server: &mut mockito::Server,
        block: u64,
        data: &str,
        result: &str,
    ) -> mockito::Mock {
        mock_eth_call_hits(server, block, data, result, 1)
    }

    /// Mock an `eth_call` at `block` with the given call `data`, expected `hits` times, returning
    /// `result`.
    fn mock_eth_call_hits(
        server: &mut mockito::Server,
        block: u64,
        data: &str,
        result: &str,
        hits: usize,
    ) -> mockito::Mock {
        server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(format!(
                r#"{{"method":"eth_call","params":[{{"data":"{data}"}},"0x{block:x}"]}}"#
            )))
            .with_body(format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{result}"}}"#))
            .expect(hits)
            .create()
    }

    fn mock_block_number(server: &mut mockito::Server) -> mockito::Mock {
        server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"method":"eth_blockNumber"}"#.to_string(),
            ))
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x10"}"#)
            .create()
    }

    fn entries_call(start: u64, end: u64) -> String {
        format!("{REJECT_LIST_ENTRIES_SELECTOR}{start:064x}{end:064x}")
    }

    #[test]
    fn reject_list_entries_pages() {
        let all: Vec<(u8, bool)> = (1..=5).map(|i| (i, i % 2 == 0)).collect();
        let expected: Vec<RejectListEntry> = all
            .iter()
            .map(|(b, reject)| test_entry(*b, *reject))
            .collect();

        // 5 entries in pages of 2: [0, 2), [2, 4) and the last partial one [4, 5), all read as
        // of the block read first, the first 3 being finalized
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 8);
        let finalized_length = mock_eth_call_at(
            &mut server,
            8,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 3),
        );
        let length = mock_eth_call(
            &mut server,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 5),
        );
        let pages = [(0, 2), (2, 4), (4, 5)].map(|(start, end)| {
            mock_eth_call(
                &mut server,
                &entries_call(start, end),
                &encode_entries(&all[start as usize..end as usize]),
            )
        });
        let client = EvmClient::new(&server.url()).unwrap();
        assert_eq!(
            client
                .reject_list_entries_paged(&EvmAddress::default(), 2)
                .unwrap(),
            RejectListLog {
                entries: expected,
                finalized: 3,
            }
        );
        finalized_length.assert();
        length.assert();
        pages.iter().for_each(|p| p.assert());

        // a page with fewer entries than requested is refused instead of leaving a gap
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 8);
        let _finalized_length = mock_eth_call_at(
            &mut server,
            8,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 0),
        );
        let _length = mock_eth_call(
            &mut server,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 5),
        );
        let _page = mock_eth_call(&mut server, &entries_call(0, 2), &encode_entries(&all[..1]));
        let client = EvmClient::new(&server.url()).unwrap();
        let result = client.reject_list_entries_paged(&EvmAddress::default(), 2);
        assert!(
            matches!(result, Err(Error::Network { details }) if details.contains("unexpected reject list page size"))
        );

        // a finalized block past the latest one is taken as the latest one
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 0x20);
        let _length = mock_eth_call(
            &mut server,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 0),
        )
        .expect(2);
        let client = EvmClient::new(&server.url()).unwrap();
        assert_eq!(
            client
                .reject_list_entries_paged(&EvmAddress::default(), 2)
                .unwrap(),
            RejectListLog {
                entries: vec![],
                finalized: 0,
            }
        );

        // a list shorter at the latest block than at the finalized one is refused
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 8);
        let _finalized_length = mock_eth_call_at(
            &mut server,
            8,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 2),
        );
        let _length = mock_eth_call(
            &mut server,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 1),
        );
        let client = EvmClient::new(&server.url()).unwrap();
        let result = client.reject_list_entries_paged(&EvmAddress::default(), 2);
        assert!(
            matches!(result, Err(Error::Network { ref details }) if details.contains("reject list shorter at the latest block")),
            "{result:?}"
        );
    }

    #[test]
    fn reject_list_decisions() {
        let log = |entries: &[(u8, bool)], finalized: usize| RejectListLog {
            entries: entries
                .iter()
                .map(|(b, reject)| test_entry(*b, *reject))
                .collect(),
            finalized,
        };
        let set = |bytes: &[u8]| bytes.iter().map(|b| test_opout(*b)).collect::<HashSet<_>>();

        // finalized decisions hold, the latest entry for an opout winning
        let (reject, allow) = log(&[(1, true), (2, false), (3, false), (3, true)], 4).decisions();
        assert_eq!(reject, set(&[1, 3]));
        assert_eq!(allow, set(&[2]));

        // non-finalized rejects count right away, superseding finalized allows
        let (reject, allow) = log(&[(2, false), (1, true), (2, true)], 1).decisions();
        assert_eq!(reject, set(&[1, 2]));
        assert!(allow.is_empty());

        // non-finalized allows don't count: an opout allowed only by them is not listed, and
        // one they would allow again stays rejected
        let (reject, allow) = log(&[(1, true), (2, false), (1, false)], 1).decisions();
        assert_eq!(reject, set(&[1]));
        assert!(allow.is_empty());

        // a non-finalized reject counts even if a later non-finalized allow supersedes it, as a
        // reorg could drop the allow or move it before the reject
        let (reject, allow) = log(
            &[(1, false), (1, true), (1, false), (2, true), (2, false)],
            1,
        )
        .decisions();
        assert_eq!(reject, set(&[1, 2]));
        assert!(allow.is_empty());

        // once finalized, the latest entry wins again
        let (reject, allow) = log(
            &[(1, false), (1, true), (1, false), (2, true), (2, false)],
            5,
        )
        .decisions();
        assert!(reject.is_empty());
        assert_eq!(allow, set(&[1, 2]));

        // decisions are about single opouts: rejecting an output of an operation leaves its other
        // outputs alone
        let rejected = test_opout(1);
        let sibling = Opout {
            no: rejected.no + 1,
            ..rejected
        };
        let (reject, allow) = RejectListLog {
            entries: vec![RejectListEntry {
                opout: rejected,
                reject: true,
            }],
            finalized: 1,
        }
        .decisions();
        assert_eq!(reject, HashSet::from([rejected]));
        assert!(!reject.contains(&sibling));
        assert!(allow.is_empty());
    }

    #[test]
    fn reject_list_entries_too_long() {
        // a list longer than supported is refused before reading any page
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 8);
        let _finalized_length = mock_eth_call_at(&mut server, 8, REJECT_LIST_LENGTH_SELECTOR, "0x");
        let length = mock_eth_call(
            &mut server,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", MAX_REJECT_LIST_ENTRIES + 1),
        );
        let entries = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(format!(
                r#"{{"params":[{{"data":"{REJECT_LIST_ENTRIES_SELECTOR}"}}]}}"#
            )))
            .expect(0)
            .create();
        let client = EvmClient::new(&server.url()).unwrap();
        let result = client.reject_list_entries(&EvmAddress::default());
        assert!(
            matches!(result, Err(Error::Network { ref details }) if details.contains("reject list too long")),
            "{result:?}"
        );
        length.assert();
        entries.assert();
    }

    #[test]
    fn reject_list_entries_not_a_contract() {
        // calling an address with no code returns no data: refused, not taken as an empty list
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 8);
        let _finalized_length = mock_eth_call_at(&mut server, 8, REJECT_LIST_LENGTH_SELECTOR, "0x");
        let length = mock_eth_call(&mut server, REJECT_LIST_LENGTH_SELECTOR, "0x");
        let entries = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(format!(
                r#"{{"params":[{{"data":"{REJECT_LIST_ENTRIES_SELECTOR}"}}]}}"#
            )))
            .expect(0)
            .create();
        let client = EvmClient::new(&server.url()).unwrap();
        let result = client.reject_list_entries(&EvmAddress::default());
        assert!(
            matches!(result, Err(Error::Network { ref details }) if details.contains("no contract at the reject list address")),
            "{result:?}"
        );
        length.assert();
        entries.assert();

        // a contract deployed after the finalized block has no finalized entries
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 8);
        let _finalized_length = mock_eth_call_at(&mut server, 8, REJECT_LIST_LENGTH_SELECTOR, "0x");
        let _length = mock_eth_call(
            &mut server,
            REJECT_LIST_LENGTH_SELECTOR,
            &format!("0x{:064x}", 1),
        );
        let _page = mock_eth_call(
            &mut server,
            &entries_call(0, 1),
            &encode_entries(&[(1, true)]),
        );
        let client = EvmClient::new(&server.url()).unwrap();
        assert_eq!(
            client.reject_list_entries(&EvmAddress::default()).unwrap(),
            RejectListLog {
                entries: vec![test_entry(1, true)],
                finalized: 0,
            }
        );

        // a call reverting (e.g. a contract without `length()`) is refused too
        let mut server = mockito::Server::new();
        let _block_number = mock_block_number(&mut server);
        let _finalized_block = mock_finalized_block(&mut server, 8);
        let _length = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"method":"eth_call"}"#.to_string(),
            ))
            .with_body(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}"#,
            )
            .create();
        let client = EvmClient::new(&server.url()).unwrap();
        let result = client.reject_list_entries(&EvmAddress::default());
        assert!(
            matches!(result, Err(Error::Network { ref details }) if details.contains("execution reverted")),
            "{result:?}"
        );
    }

    #[test]
    fn finalized_block_number() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"method":"eth_getBlockByNumber","params":["finalized",false]}"#.to_string(),
            ))
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":{"number":"0x1a4","hash":"0x00"}}"#)
            .create();
        let client = EvmClient::new(&server.url()).unwrap();
        assert_eq!(client.finalized_block_number().unwrap(), 420);
        mock.assert();

        // a node with no finalized block (e.g. not supporting the tag) is reported, never
        // silently taken as "nothing finalized yet"
        let _mock = server
            .mock("POST", "/")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":null}"#)
            .create();
        let result = EvmClient::new(&server.url())
            .unwrap()
            .finalized_block_number();
        assert!(
            matches!(result, Err(Error::Network { details }) if details.contains("no finalized block"))
        );
    }

    #[test]
    fn chain_id() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"method":"eth_chainId"}"#.to_string(),
            ))
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x7a69"}"#)
            .expect(2)
            .create();
        let client = EvmClient::new(&server.url()).unwrap();
        assert_eq!(client.chain_id().unwrap(), 31337);
        assert_eq!(client.evm_chain_id().unwrap(), 31337);
        mock.assert();

        // an RPC error is reported as the resolver's issue, with its details
        let _mock = server
            .mock("POST", "/")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"not found"}}"#)
            .create();
        let result = EvmClient::new(&server.url()).unwrap().evm_chain_id();
        assert_eq!(
            result,
            Err(AnchorResolverError::ResolverIssue(s!(
                "eth_chainId error -32601: not found"
            )))
        );
    }

    #[test]
    fn post_retries() {
        let chain_id_mock = |server: &mut mockito::Server, status: usize, hits: usize| {
            server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJsonString(
                    r#"{"method":"eth_chainId"}"#.to_string(),
                ))
                .with_status(status)
                .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x7a69"}"#)
                .expect(hits)
                .create()
        };

        // a node temporarily unavailable is asked again
        for status in [502, 503, 504] {
            let mut server = mockito::Server::new();
            let unavailable = chain_id_mock(&mut server, status, RPC_RETRIES as usize);
            let available = chain_id_mock(&mut server, 200, 1);
            let client = EvmClient::new(&server.url()).unwrap();
            assert_eq!(client.chain_id().unwrap(), 31337);
            unavailable.assert();
            available.assert();
        }

        // up to RPC_RETRIES times, then its answer is handled as any other
        let mut server = mockito::Server::new();
        let unavailable = server
            .mock("POST", "/")
            .with_status(503)
            .with_body("<html>503 Service Temporarily Unavailable</html>")
            .expect(RPC_RETRIES as usize + 1)
            .create();
        let client = EvmClient::new(&server.url()).unwrap();
        assert!(matches!(client.chain_id(), Err(Error::Network { .. })));
        unavailable.assert();

        // other errors are not retried
        let mut server = mockito::Server::new();
        let refused = chain_id_mock(&mut server, 500, 1);
        let client = EvmClient::new(&server.url()).unwrap();
        client.chain_id().unwrap();
        refused.assert();

        // a request that cannot be sent is sent again, then reported
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = EvmClient::new(&url).unwrap();
        let start = std::time::Instant::now();
        assert!(matches!(client.chain_id(), Err(Error::Network { .. })));
        let pauses: u32 = (1..=RPC_RETRIES).sum();
        assert!(start.elapsed() >= RPC_RETRY_PAUSE * pauses);
    }

    /// The `getFundsInBlock` call data for the operation whose ID is all `opid_byte` and `amount`.
    fn funds_in_call(opid_byte: u8, amount: u64) -> String {
        format!(
            "{FUNDS_IN_BLOCK_SELECTOR}{}{amount:064x}",
            hex::encode([opid_byte; 32])
        )
    }

    /// Mock an `eth_getBlockByNumber` reporting `finalized` as the finalized block.
    fn mock_finalized_block(server: &mut mockito::Server, finalized: u64) -> mockito::Mock {
        server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"method":"eth_getBlockByNumber","params":["finalized",false]}"#.to_string(),
            ))
            .with_body(format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"number":"0x{finalized:x}"}}}}"#
            ))
            .create()
    }

    #[test]
    fn funds_in_block() {
        let contract = EvmAddress::default();
        let opid = OpId::from([0u8; 32]);
        let funds_in_block = |result: &str| {
            let mut server = mockito::Server::new();
            let call = mock_eth_call(&mut server, &funds_in_call(0, 7), result);
            let block = EvmClient::new(&server.url())
                .unwrap()
                .funds_in_block(&contract, &opid, 7, 0x10);
            call.assert();
            block
        };

        // the record is the block plus one
        assert_eq!(
            funds_in_block(&format!("0x{:064x}", 0x12)).unwrap(),
            Some(0x11)
        );
        assert_eq!(funds_in_block(&format!("0x{:064x}", 1)).unwrap(), Some(0));
        // zero means there's no record
        assert_eq!(funds_in_block(&format!("0x{:064x}", 0)).unwrap(), None);
        // an address with no code has no records
        assert_eq!(funds_in_block("0x").unwrap(), None);
        // nor a contract without the function, which reverts the call, while another error isn't
        // taken for a missing record
        let call_error = |error: &str| {
            let mut server = mockito::Server::new();
            let call = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJsonString(s!(
                    r#"{"method":"eth_call"}"#
                )))
                .with_body(format!(r#"{{"jsonrpc":"2.0","id":1,"error":{error}}}"#))
                .create();
            let block = EvmClient::new(&server.url())
                .unwrap()
                .funds_in_block(&contract, &opid, 7, 0x10);
            call.assert();
            block
        };
        assert_eq!(
            call_error(r#"{"code":3,"message":"execution reverted"}"#).unwrap(),
            None
        );
        assert_eq!(
            call_error(r#"{"code":-32000,"message":"execution reverted: paused"}"#).unwrap(),
            None
        );
        assert!(call_error(r#"{"code":-32000,"message":"missing trie node"}"#).is_err());
        // a result that isn't a single word is refused, whatever its content
        assert!(funds_in_block(&format!("0x{:062x}", 1)).is_err());
        assert!(funds_in_block(&format!("0x{:064x}{:064x}", 1, 0)).is_err());
        // a block that doesn't fit in a u64 is refused, not truncated
        assert!(funds_in_block(&format!("0x{}1{}", "0".repeat(47), "0".repeat(16))).is_err());
    }

    #[test]
    fn mint_lock_status() {
        let contract = EvmAddress::default();
        let opid = OpId::from([0u8; 32]);
        // the status of the lock, with the given record as of the finalized block 0x20
        let status = |record: u64, before_block: u64| {
            let mut server = mockito::Server::new();
            let _finalized = mock_finalized_block(&mut server, 0x20);
            let call = mock_eth_call_at(
                &mut server,
                0x20,
                &funds_in_call(0, 7),
                &format!("0x{record:064x}"),
            );
            let status = EvmClient::new(&server.url())
                .unwrap()
                .mint_lock_status(&contract, &opid, 7, before_block)
                .unwrap();
            call.assert();
            status
        };

        // a lock included in block 0x11 confirms the mint only if that's before the block
        assert_eq!(status(0x12, 0x12), MintLockStatus::Confirmed);
        assert_eq!(status(0x12, 0x11), MintLockStatus::Expired);
        // with no lock recorded as of block 0x20, one may only be included from block 0x21
        assert_eq!(status(0, 0x22), MintLockStatus::Pending);
        assert_eq!(status(0, 0x21), MintLockStatus::Expired);
        assert_eq!(status(0, 0x10), MintLockStatus::Expired);
    }

    #[test]
    fn is_confirmed_reads_finalized_record() {
        let location = BridgeLocation::Evm(EvmContract {
            chain_id: 31337,
            address: EvmAddress::default(),
        });
        let anchor = |amount: u64, before_block: u64| ExternalAnchor::Mint {
            opid: OpId::from([0u8; 32]),
            amount,
            before_block,
        };
        // the lock of 7 recorded in block 0x11, read as of the finalized block 0x20
        let mut server = mockito::Server::new();
        let _finalized = mock_finalized_block(&mut server, 0x20);
        let record = mock_eth_call_hits(
            &mut server,
            0x20,
            &funds_in_call(0, 7),
            &format!("0x{:064x}", 0x12),
            2,
        );
        let no_record = mock_eth_call_at(
            &mut server,
            0x20,
            &funds_in_call(0, 8),
            &format!("0x{:064x}", 0),
        );
        let client = EvmClient::new(&server.url()).unwrap();
        assert!(client.is_confirmed(&location, &anchor(7, 0x30)).unwrap());
        // the record is keyed by the amount too: another amount isn't confirmed
        assert!(!client.is_confirmed(&location, &anchor(8, 0x30)).unwrap());
        // the lock has to be included before the block the anchor commits to
        assert!(!client.is_confirmed(&location, &anchor(7, 0x11)).unwrap());
        record.assert();
        no_record.assert();
    }
}
