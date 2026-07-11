//! Cross-chain (BTC <-> Sequentia-asset) HTLC swap glue — the taker's (Alice's) side.
//!
//! Alice holds BTC and wants the SEQ asset: she funds the BTC HTLC, the maker funds
//! the SEQ HTLC, Alice verifies the SEQ leg is anchor-safe (the reveal gate), then
//! claims it, revealing the preimage. SEQ-leg crypto reuses the kit's `seqdex_htlc`
//! primitives; the BTC leg is [`super::htlc`]. This is the glue: HTLC spend-key
//! derivation, the swap secret, the reveal + claim-deadline gates, and the SEQ
//! claim + broadcast.
//!
//! THE REVEAL GATE (anchoring's whole point — no cross-chain buffer): Alice may
//! reveal the preimage only when, read from her OWN nodes (never the maker), the
//! SEQ funding's Bitcoin anchor height A satisfies A >= H_btc, `anchorstatus` is
//! "ok", and A is at least D Bitcoin-confirmations deep (D default 1, a TAKER dial
//! — the same security as accepting that much BTC at 1 conf). There is NO
//! value-scaled depth and NO reorg-protection timelock; the SEQ tx's finality IS
//! its anchor Bitcoin block's finality (the chain follows Bitcoin reorgs in real
//! time). The CLTV refund timelocks are LIVENESS only.
//!
//! Ported verbatim (logic-wise) from ambra_core's xchain.rs, swapping SwSigner for
//! the kit's [`super::core`] derivation and reqwest::blocking for the blocking +
//! async transport split (like [`super::esplora`]).

use std::str::FromStr;

use crate::bitcoin::bip32::DerivationPath;
use crate::bitcoin::hex::{DisplayHex, FromHex};
use crate::bitcoin::secp256k1::{Secp256k1, SecretKey};

use super::addr::ChainAddressParams;
use crate::error::Error;

fn map<E: std::fmt::Debug>(e: E) -> Error {
    Error::Generic(format!("{e:?}"))
}

fn hexdec(s: &str) -> Result<Vec<u8>, Error> {
    Vec::<u8>::from_hex(s).map_err(map)
}

/// Which HD path the SEQ-claim / BTC-refund keys derive from.
///
/// `Canonical` is the kit's one true derivation: absolute paths under the BIP84
/// account, deliberately OUTSIDE the receive(0)/change(1) branches so the wallet
/// never sweeps the HTLC keys as ordinary funds. `LegacyRelative` reproduces the
/// web wallet's older relative `m/3/0` SEQ-claim key, so a swap that wallet funded
/// before the port can still be claimed/recovered. The chosen mode MUST be
/// recorded in the persisted swap state so recovery derives the SAME key that
/// funded the leg. The daemon does not enforce the path (it rebuilds scripts from
/// the pubkeys the taker sends); the only constraint is claim==funding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PathMode {
    /// Absolute `m/84'/1'/0'/{3,2}/0` (new swaps).
    Canonical,
    /// The web wallet's legacy relative `m/3/0` SEQ-claim key (recovery only).
    LegacyRelative,
}

impl PathMode {
    fn seq_claim_path(self) -> &'static str {
        match self {
            PathMode::Canonical => "m/84h/1h/0h/3/0",
            PathMode::LegacyRelative => "m/3/0",
        }
    }
    fn btc_refund_path(self) -> &'static str {
        // The legacy web wallet never built a BTC refund, so canonical for both.
        "m/84h/1h/0h/2/0"
    }
    fn btc_claim_path(self) -> &'static str {
        // DISTINCT from btc_refund (…/2/0) and seq_claim (…/3/0): the CLAIM key
        // spends the HTLC's IF/preimage branch and MUST differ from the refund
        // key, so a single leaked key can never unlock both branches. Index 4 is
        // still outside the receive(0)/change(1) branches (never swept as funds).
        "m/84h/1h/0h/4/0"
    }
}

/// Derive `(secret, 33-byte compressed pubkey hex)` at `path`. Byte-identical to
/// ambra's SwSigner derivation: the kit's `master_xprv` is the same BIP39 seed("")
/// -> `Xpriv::new_master` -> `derive_priv` chain SwSigner uses.
fn derive_keypair(params: &ChainAddressParams, mnemonic: &str, path: &str) -> Result<(SecretKey, String), Error> {
    let secp = Secp256k1::new();
    let master = super::core::master_xprv(mnemonic, params)?;
    let xprv = master.derive_priv(&secp, &DerivationPath::from_str(path).map_err(map)?).map_err(map)?;
    let sk = xprv.private_key;
    let pubkey = sk.public_key(&secp).serialize().to_lower_hex_string();
    Ok((sk, pubkey))
}

/// The taker's SEQ-claim keypair (spends the IF/redeem branch, revealing the preimage).
pub fn seq_claim_keypair(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
) -> Result<(SecretKey, String), Error> {
    derive_keypair(params, mnemonic, mode.seq_claim_path())
}

/// The taker's BTC-refund keypair (spends the BTC HTLC's ELSE/CLTV branch).
pub fn btc_refund_keypair(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
) -> Result<(SecretKey, String), Error> {
    derive_keypair(params, mnemonic, mode.btc_refund_path())
}

/// The taker's BTC-CLAIM keypair (spends the BTC HTLC's IF/preimage branch). This
/// is the money key for a sub-asset SELL: the pubkey is the `btc_claim_pub` sent to
/// the LSP `/swap`, and the secret signs the on-chain claim once the preimage is
/// learned. Its path is distinct from the refund key's (see `btc_claim_path`).
pub fn btc_claim_keypair(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
) -> Result<(SecretKey, String), Error> {
    derive_keypair(params, mnemonic, mode.btc_claim_path())
}

/// A fresh swap preimage + its SHA256 hashlock, as `(secret_hex, hash_hex)`. The
/// secret is NOT HD-derivable; the caller MUST persist it (sealed) before any
/// money moves — it is unrecoverable if lost and it gates the BTC claim.
pub fn new_secret() -> (String, String) {
    let s = crate::generate_swap_secret();
    (s.secret_hex, s.hash_hex)
}

/// Evidence + verdict of the reveal gate.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorEvidence {
    /// SEQ funding block's Bitcoin anchor height, or `-1` if the block carries none.
    pub seq_anchor_height: i64,
    /// `H_btc` — the BTC funding confirmation height.
    pub btc_leg_height: i64,
    /// The taker's OWN testnet4 tip height.
    pub btc_tip: i64,
    /// `getanchorstatus` from the taker's own SEQ node.
    pub anchor_status: String,
    /// `btc_tip - seq_anchor_height + 1`, or `-1` when there is no anchor.
    pub depth: i64,
    /// Whether it is safe to reveal (all conditions met).
    pub ok: bool,
}

/// The pure reveal-gate arithmetic (the I/O-free heart of `verify_seq_leg_safe`),
/// shared by both transports so they share one truth table.
///
/// `ok` iff the SEQ funding is anchored (`seq_anchor_height >= 0`), its anchor is at
/// or above the BTC funding (`>= btc_leg_height`), the chain's anchor status is
/// "ok", and the anchor is at least `min_depth` (D, default 1) Bitcoin-confs deep.
pub fn evaluate_gate(
    seq_anchor_height: i64,
    anchor_status: &str,
    btc_tip: i64,
    btc_leg_height: i64,
    min_depth: i64,
) -> AnchorEvidence {
    let depth = if seq_anchor_height >= 0 { btc_tip - seq_anchor_height + 1 } else { -1 };
    let ok = seq_anchor_height >= 0
        && seq_anchor_height >= btc_leg_height
        && anchor_status == "ok"
        && depth >= min_depth;
    AnchorEvidence {
        seq_anchor_height,
        btc_leg_height,
        btc_tip,
        anchor_status: anchor_status.to_string(),
        depth,
        ok,
    }
}

/// Pure claim-deadline check: there must be `margin` SEQ blocks of headroom before
/// the SEQ-leg CLTV refund height. `seq_locktime` is a SEQUENTIA block height, so
/// it is compared to the SEQ chain tip (NOT the Bitcoin tip). If this fails the
/// taker must NOT reveal: a claim that can't confirm before `seq_locktime` lets the
/// maker refund the SEQ leg via CLTV and then claim the BTC with the now-public
/// preimage.
pub fn deadline_ok(seq_tip: i64, seq_locktime: u32, margin: i64) -> bool {
    seq_tip >= 0 && seq_tip + margin < seq_locktime as i64
}

/// A sane default SEQ-chain native feerate (atoms per vByte) for the claim, well
/// above the node's ~0.1-atom/vByte min-relay floor so a rate-derived claim fee
/// always clears relay. This is a SEQUENTIA feerate, NOT a Bitcoin sat/vB.
pub const DEFAULT_SEQ_CLAIM_FEERATE: u64 = 1;

/// Conservative vbyte estimate for the single-input SEQ HTLC claim tx: 1 P2SH
/// HTLC input (72B max DER sig + 32B preimage + 1B OP_1 selector + ~114B
/// OP_PUSHDATA1 redeemScript) + 2 explicit Elements outputs (recipient + fee).
/// Deliberately OVER-estimates so the rate-derived fee never undershoots the
/// node's own vsize-based relay floor. (Refine against an actual built claim.)
pub fn claim_tx_vsize() -> u64 {
    400
}

/// The SEQ-leg claim fee, in atoms of the CLAIMED asset: the native-equivalent of
/// `seq_feerate_native * claim_tx_vsize()`, converted at the claimed asset's
/// published acceptance rate. Replaces the old flat 100000-atom fee.
///
/// `rate` is the CLAIMED asset's acceptance rate (atoms per 1e8 native). It MUST
/// be non-zero: a `rate == 0` asset is NOT fee-accepted by producers, so any claim
/// in it is unrelayable — this returns `Err` rather than emitting a stuck claim
/// (the rate==0 ⇒ 1:1 fallback of `convert_value_to_amount` is wrong here and is
/// deliberately NOT used). `seq_feerate_native` is a SEQUENTIA native feerate
/// (atoms/vByte), never a Bitcoin sat/vB. The result is still bounded by the
/// `fee < seq_amount` guard in [`seq_claim`].
pub fn seq_claim_fee_atoms(rate: u64, seq_feerate_native: u64) -> Result<u64, Error> {
    if rate == 0 {
        return Err(Error::Generic(
            "claimed asset is not currently fee-accepted by producers; cannot build a relayable SEQ claim".into(),
        ));
    }
    let native_value = seq_feerate_native.saturating_mul(claim_tx_vsize());
    Ok(crate::seqdex_swap::convert_value_to_amount(native_value, rate))
}

/// The SEQ-leg redeemScript the taker rebuilds (claim = her SEQ-claim key, refund =
/// the maker's SEQ-refund pubkey), as hex, so the caller can byte-compare it to the
/// daemon-reported `seqLeg.redeemScript` (value-binding) before trusting the leg.
pub fn seq_redeem_script_hex(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
    hash_hex: &str,
    maker_seq_refund_pub_hex: &str,
    seq_locktime: u32,
) -> Result<String, Error> {
    let (_sk, claim_pub_hex) = seq_claim_keypair(params, mnemonic, mode)?;
    let script = crate::build_htlc_redeem_script(
        &hexdec(hash_hex)?,
        &hexdec(&claim_pub_hex)?,
        &hexdec(maker_seq_refund_pub_hex)?,
        seq_locktime,
    )?;
    Ok(script.as_bytes().to_lower_hex_string())
}

/// Build the SEQ claim tx (reveals the preimage). Rebuilds the redeemScript from its
/// components (so it is exactly the verified script) and pays `amount - fee` to the
/// taker's own SEQ `dest_address` plus an explicit Elements fee output in the
/// claimed asset. `fee` must be `< seq_amount`. Returns the raw Elements tx hex.
#[allow(clippy::too_many_arguments)]
pub fn seq_claim(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
    seq_txid: &str,
    seq_vout: u32,
    seq_amount: u64,
    seq_asset_id: &str,
    dest_address: &str,
    hash_hex: &str,
    maker_seq_refund_pub_hex: &str,
    seq_locktime: u32,
    fee: u64,
    preimage_hex: &str,
) -> Result<String, Error> {
    let (sk, claim_pub_hex) = seq_claim_keypair(params, mnemonic, mode)?;
    let redeem = crate::build_htlc_redeem_script(
        &hexdec(hash_hex)?,
        &hexdec(&claim_pub_hex)?,
        &hexdec(maker_seq_refund_pub_hex)?,
        seq_locktime,
    )?;
    let dest = crate::elements::Address::parse_with_params(
        dest_address,
        lwk_common::Network::sequentia_testnet().address_params(),
    )
    .map_err(map)?;
    if fee >= seq_amount {
        return Err(Error::Generic("SEQ claim fee exceeds the leg amount".into()));
    }
    let spend = crate::SeqHtlcSpend {
        txid: seq_txid.to_string(),
        vout: seq_vout,
        amount: seq_amount,
        asset_id: seq_asset_id.to_string(),
        dest_spk: dest.script_pubkey().as_bytes().to_vec(),
        fee,
    };
    crate::build_claim_tx(&spend, &redeem, &sk, &hexdec(preimage_hex)?)
}

// --- transport: the reveal gate + broadcast over the taker's OWN nodes ---------
//
// Each submodule mirrors `super::esplora`'s split and reuses its esplora clients.

/// Blocking transport (Ambra / native): the 3 reveal-gate GETs, the SEQ broadcast,
/// and the SEQ tip for the claim-deadline gate.
#[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]
pub mod blocking {
    use super::*;

    fn client() -> Result<reqwest::blocking::Client, Error> {
        super::super::esplora::blocking::client()
    }

    fn post(client: &reqwest::blocking::Client, daemon: &str, path: &str, body: String) -> Result<String, Error> {
        let resp = client
            .post(format!("{}/v1/xchain/{path}", daemon.trim_end_matches('/')))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(map)?;
        resp.text().map_err(map)
    }

    /// List the maker's cross-chain markets.
    pub fn xchain_markets(daemon: &str) -> Result<Vec<XchainMarket>, Error> {
        let body = post(&client()?, daemon, "markets", "{}".into())?;
        Ok(parse_resp::<MarketsResp>(&body)?.markets)
    }

    /// Quote buying `seq_amount` of `seq_asset` with BTC.
    pub fn xchain_quote(daemon: &str, seq_asset: &str, seq_amount: u64) -> Result<XQuote, Error> {
        let req = QuoteReq { seq_asset, seq_amount: seq_amount.to_string() };
        let body = post(&client()?, daemon, "quote", serde_json::to_string(&req).map_err(map)?)?;
        parse_resp(&body)
    }

    /// Propose the swap (single-use quote; NEVER auto-retry on a transient error —
    /// re-quote instead while the BTC leg stays locked). Persist `swapId` from the
    /// result before doing anything else.
    pub fn xchain_propose(
        daemon: &str,
        quote_id: &str,
        hash: &str,
        btc_leg: &BtcLeg,
        taker_seq_claim_pub: &str,
        taker_btc_refund_pub: &str,
    ) -> Result<ProposeAccepted, Error> {
        let req = ProposeReq { quote_id, hash, btc_leg, taker_seq_claim_pub, taker_btc_refund_pub };
        let body = post(&client()?, daemon, "propose", serde_json::to_string(&req).map_err(map)?)?;
        parse_resp::<ProposeResp>(&body)?
            .accepted
            .ok_or_else(|| Error::Generic("propose returned neither accepted nor fail".into()))
    }

    /// Poll a swap's status by id. A 404/NotFound (the maker's state is in-memory
    /// and dies on restart; there is no by-hash lookup) is NOT swap failure — fall
    /// back to the taker's own sealed state + on-chain watch.
    pub fn xchain_swap_status(daemon: &str, swap_id: &str) -> Result<XSwapStatus, Error> {
        let req = SwapReq { swap_id };
        let body = post(&client()?, daemon, "swap", serde_json::to_string(&req).map_err(map)?)?;
        parse_resp(&body)
    }

    /// Evaluate the reveal gate from the taker's OWN SEQ esplora + testnet4 view,
    /// NEVER the maker. `min_depth` = D (default 1).
    pub fn verify_seq_leg_safe(
        seq_esplora: &str,
        seq_block_hash: &str,
        btc_leg_height: i64,
        t4_api: &str,
        min_depth: i64,
    ) -> Result<AnchorEvidence, Error> {
        let client = client()?;
        let seq = seq_esplora.trim_end_matches('/');
        let t4 = t4_api.trim_end_matches('/');

        let block: serde_json::Value =
            client.get(format!("{seq}/block/{seq_block_hash}")).send().map_err(map)?.json().map_err(map)?;
        let seq_anchor_height = block
            .get("bitcoin_anchor")
            .and_then(|a| a.get("height"))
            .and_then(|h| h.as_i64())
            .unwrap_or(-1);

        let status_v: serde_json::Value =
            client.get(format!("{seq}/sequentia/anchorstatus")).send().map_err(map)?.json().map_err(map)?;
        let anchor_status = status_v.get("anchorstatus").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();

        let btc_tip = client
            .get(format!("{t4}/blocks/tip/height"))
            .send()
            .map_err(map)?
            .text()
            .map_err(map)?
            .trim()
            .parse::<i64>()
            .map_err(map)?;

        Ok(evaluate_gate(seq_anchor_height, &anchor_status, btc_tip, btc_leg_height, min_depth))
    }

    /// The taker's own SEQ chain tip height (for the claim-deadline gate), or `-1`.
    pub fn seq_tip_height(seq_esplora: &str) -> i64 {
        let Ok(client) = client() else { return -1 };
        let base = seq_esplora.trim_end_matches('/');
        client
            .get(format!("{base}/blocks/tip/height"))
            .send()
            .ok()
            .and_then(|r| r.text().ok())
            .and_then(|t| t.trim().parse::<i64>().ok())
            .unwrap_or(-1)
    }

    /// Whether there is safe margin before the SEQ-leg CLTV refund height, read
    /// from the taker's own SEQ tip. Refuse to reveal when this is false.
    pub fn claim_deadline_ok(seq_esplora: &str, seq_locktime: u32, margin: i64) -> bool {
        deadline_ok(seq_tip_height(seq_esplora), seq_locktime, margin)
    }

    /// Broadcast a raw Elements (SEQ) tx hex to the SEQ esplora; returns the txid.
    pub fn seq_broadcast(seq_esplora: &str, tx_hex: &str) -> Result<String, Error> {
        let client = client()?;
        let base = seq_esplora.trim_end_matches('/');
        let resp = client.post(format!("{base}/tx")).body(tx_hex.to_string()).send().map_err(map)?;
        let ok = resp.status().is_success();
        let body = resp.text().map_err(map)?;
        super::super::core::parse_broadcast(ok, &body)
    }
}

/// Async transport (wasm / web): the same reveal gate + broadcast + SEQ tip.
#[cfg(feature = "btc-async")]
pub mod asyncr {
    use super::*;

    fn client() -> Result<reqwest::Client, Error> {
        super::super::esplora::asyncr::client()
    }

    async fn post(client: &reqwest::Client, daemon: &str, path: &str, body: String) -> Result<String, Error> {
        let resp = client
            .post(format!("{}/v1/xchain/{path}", daemon.trim_end_matches('/')))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(map)?;
        resp.text().await.map_err(map)
    }

    /// List the maker's cross-chain markets (async).
    pub async fn xchain_markets(daemon: &str) -> Result<Vec<XchainMarket>, Error> {
        let body = post(&client()?, daemon, "markets", "{}".into()).await?;
        Ok(parse_resp::<MarketsResp>(&body)?.markets)
    }

    /// Quote buying `seq_amount` of `seq_asset` with BTC (async).
    pub async fn xchain_quote(daemon: &str, seq_asset: &str, seq_amount: u64) -> Result<XQuote, Error> {
        let req = QuoteReq { seq_asset, seq_amount: seq_amount.to_string() };
        let body = post(&client()?, daemon, "quote", serde_json::to_string(&req).map_err(map)?).await?;
        parse_resp(&body)
    }

    /// Propose the swap (async; single-use quote, never auto-retry).
    pub async fn xchain_propose(
        daemon: &str,
        quote_id: &str,
        hash: &str,
        btc_leg: &BtcLeg,
        taker_seq_claim_pub: &str,
        taker_btc_refund_pub: &str,
    ) -> Result<ProposeAccepted, Error> {
        let req = ProposeReq { quote_id, hash, btc_leg, taker_seq_claim_pub, taker_btc_refund_pub };
        let body = post(&client()?, daemon, "propose", serde_json::to_string(&req).map_err(map)?).await?;
        parse_resp::<ProposeResp>(&body)?
            .accepted
            .ok_or_else(|| Error::Generic("propose returned neither accepted nor fail".into()))
    }

    /// Poll a swap's status by id (async). Treat a 404 as "daemon forgot", not failure.
    pub async fn xchain_swap_status(daemon: &str, swap_id: &str) -> Result<XSwapStatus, Error> {
        let req = SwapReq { swap_id };
        let body = post(&client()?, daemon, "swap", serde_json::to_string(&req).map_err(map)?).await?;
        parse_resp(&body)
    }

    /// Evaluate the reveal gate from the taker's OWN nodes (async). See the
    /// blocking analogue.
    pub async fn verify_seq_leg_safe(
        seq_esplora: &str,
        seq_block_hash: &str,
        btc_leg_height: i64,
        t4_api: &str,
        min_depth: i64,
    ) -> Result<AnchorEvidence, Error> {
        let client = client()?;
        let seq = seq_esplora.trim_end_matches('/');
        let t4 = t4_api.trim_end_matches('/');

        let block: serde_json::Value = client
            .get(format!("{seq}/block/{seq_block_hash}"))
            .send()
            .await
            .map_err(map)?
            .json()
            .await
            .map_err(map)?;
        let seq_anchor_height = block
            .get("bitcoin_anchor")
            .and_then(|a| a.get("height"))
            .and_then(|h| h.as_i64())
            .unwrap_or(-1);

        let status_v: serde_json::Value = client
            .get(format!("{seq}/sequentia/anchorstatus"))
            .send()
            .await
            .map_err(map)?
            .json()
            .await
            .map_err(map)?;
        let anchor_status = status_v.get("anchorstatus").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();

        let btc_tip = client
            .get(format!("{t4}/blocks/tip/height"))
            .send()
            .await
            .map_err(map)?
            .text()
            .await
            .map_err(map)?
            .trim()
            .parse::<i64>()
            .map_err(map)?;

        Ok(evaluate_gate(seq_anchor_height, &anchor_status, btc_tip, btc_leg_height, min_depth))
    }

    /// The taker's own SEQ chain tip height (async), or `-1`.
    pub async fn seq_tip_height(seq_esplora: &str) -> i64 {
        let Ok(client) = client() else { return -1 };
        let base = seq_esplora.trim_end_matches('/');
        match client.get(format!("{base}/blocks/tip/height")).send().await {
            Ok(r) => r.text().await.ok().and_then(|t| t.trim().parse::<i64>().ok()).unwrap_or(-1),
            Err(_) => -1,
        }
    }

    /// Whether there is safe margin before the SEQ-leg CLTV refund height (async).
    pub async fn claim_deadline_ok(seq_esplora: &str, seq_locktime: u32, margin: i64) -> bool {
        deadline_ok(seq_tip_height(seq_esplora).await, seq_locktime, margin)
    }

    /// Broadcast a raw Elements (SEQ) tx hex to the SEQ esplora (async); returns the txid.
    pub async fn seq_broadcast(seq_esplora: &str, tx_hex: &str) -> Result<String, Error> {
        let client = client()?;
        let base = seq_esplora.trim_end_matches('/');
        let resp = client.post(format!("{base}/tx")).body(tx_hex.to_string()).send().await.map_err(map)?;
        let ok = resp.status().is_success();
        let body = resp.text().await.map_err(map)?;
        super::super::core::parse_broadcast(ok, &body)
    }
}

// --- daemon XchainService REST client -----------------------------------------
//
// POST JSON under /v1/xchain/{markets,quote,propose,swap} (grpc-gateway protojson):
// lowerCamelCase keys, EVERY uint64/int64 a JSON STRING, uint32/double numbers,
// zero-valued fields OMITTED, and in-band failures as {"fail":{code,message}} at
// HTTP 200. propose is NOT idempotent (the quote is single-use) and there is no
// lookup-by-hash, so the caller must persist swapId before propose, never auto-retry
// propose, and tolerate a 404 from /swap by falling back to its own sealed state.

use serde::{Deserialize, Serialize};

/// Deserialize a grpc-gateway string-encoded uint64 (present => parse the string).
fn de_u64_str<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
}
/// Deserialize a grpc-gateway string-encoded int64.
fn de_i64_str<'de, D: serde::Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
}

/// A cross-chain market the maker makes (BTC <-> a Sequentia asset).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XchainMarket {
    /// The BTC side asset id, display hex.
    #[serde(default)]
    pub btc_asset: String,
    /// The Sequentia asset id, display hex.
    #[serde(default)]
    pub seq_asset: String,
    /// Market name.
    #[serde(default)]
    pub name: String,
    /// Maker's SEQ-asset reserve, atoms.
    #[serde(default, deserialize_with = "de_u64_str")]
    pub seq_reserve: u64,
    /// Maker's BTC reserve, sats.
    #[serde(default, deserialize_with = "de_u64_str")]
    pub btc_reserve: u64,
    /// Price: SEQ-asset units per BTC.
    #[serde(default)]
    pub price_seq_per_btc: f64,
}

/// A maker quote for buying `seq_amount` of an asset with BTC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XQuote {
    /// Single-use quote id to pass to propose.
    #[serde(default)]
    pub quote_id: String,
    /// SEQ-asset amount quoted, atoms.
    #[serde(default, deserialize_with = "de_u64_str")]
    pub seq_amount: u64,
    /// BTC amount required, sats.
    #[serde(default, deserialize_with = "de_u64_str")]
    pub btc_amount: u64,
    /// Price: SEQ-asset units per BTC.
    #[serde(default)]
    pub price_seq_per_btc: f64,
    /// Maker commission, sats.
    #[serde(default, deserialize_with = "de_u64_str")]
    pub fee_btc: u64,
    /// Maker's BTC-leg claim pubkey, hex.
    #[serde(default)]
    pub maker_btc_claim_pub: String,
    /// Maker's SEQ-leg refund pubkey, hex.
    #[serde(default)]
    pub maker_seq_refund_pub: String,
    /// BTC HTLC CLTV locktime the taker must use (Bitcoin height).
    #[serde(default)]
    pub btc_locktime: u32,
    /// SEQ HTLC CLTV locktime (Sequentia height).
    #[serde(default)]
    pub seq_locktime: u32,
    /// Quote expiry, unix seconds.
    #[serde(default, deserialize_with = "de_i64_str")]
    pub expires_at_unix: i64,
}

/// The maker's SEQ-leg HTLC funding the taker independently anchor-verifies + claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XSeqLeg {
    /// SEQ-leg HTLC funding txid.
    #[serde(default)]
    pub txid: String,
    /// SEQ-leg HTLC funding vout.
    #[serde(default)]
    pub vout: u32,
    /// SEQ block hash the funding landed in (for the taker's anchor lookup).
    #[serde(default)]
    pub block_hash: String,
    /// Maker-REPORTED anchor height — informational only; the taker re-derives it
    /// from its OWN SEQ esplora in the reveal gate and NEVER trusts this for safety.
    #[serde(default, deserialize_with = "de_i64_str")]
    pub anchor_height: i64,
    /// SEQ-leg redeemScript hex (value-binding compared vs the rebuilt script).
    #[serde(default)]
    pub redeem_script: String,
    /// SEQ-leg amount, atoms.
    #[serde(default, deserialize_with = "de_u64_str")]
    pub amount: u64,
    /// SEQ-leg asset id, display hex.
    #[serde(default)]
    pub asset_id: String,
}

/// Live status of a cross-chain swap by id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XSwapStatus {
    /// The swap id.
    #[serde(default)]
    pub swap_id: String,
    /// Enum name (grpc-gateway serializes enums by name): PENDING_BTC_LOCK,
    /// SEQ_LOCKED, SEQ_CLAIMED, BTC_CLAIMED, REFUNDED, FAILED.
    #[serde(default)]
    pub state: String,
    /// The maker's SEQ leg, if locked.
    #[serde(default)]
    pub seq_leg: Option<XSeqLeg>,
    /// The SEQ claim txid, once the taker revealed.
    #[serde(default)]
    pub seq_claim_txid: String,
    /// The maker's BTC claim txid, once settled.
    #[serde(default)]
    pub btc_claim_txid: String,
    /// The revealed preimage, once on-chain (the maker reads it to claim BTC).
    #[serde(default)]
    pub preimage: String,
    /// Free-text detail / failure reason.
    #[serde(default)]
    pub detail: String,
}

/// The taker's BTC-leg HTLC details sent in a propose.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BtcLeg {
    /// BTC HTLC funding txid.
    pub txid: String,
    /// BTC HTLC funding vout.
    pub vout: u32,
    /// BTC funding confirmation height (int64 over the wire).
    pub height: String,
    /// BTC HTLC redeemScript hex.
    pub redeem_script: String,
    /// BTC HTLC funding amount, sats (uint64 over the wire).
    pub amount: String,
    /// BTC asset id, display hex.
    pub asset_id: String,
}

impl BtcLeg {
    /// Build from native values, formatting the wire string-ints.
    pub fn new(txid: &str, vout: u32, height: i64, redeem_script: &str, amount: u64, asset_id: &str) -> Self {
        Self {
            txid: txid.to_string(),
            vout,
            height: height.to_string(),
            redeem_script: redeem_script.to_string(),
            amount: amount.to_string(),
            asset_id: asset_id.to_string(),
        }
    }
}

/// Accepted propose: the swap id + the maker's SEQ leg to verify and claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposeAccepted {
    /// The daemon's swap id — persist this immediately (before anything else).
    #[serde(default)]
    pub swap_id: String,
    /// The maker's SEQ leg to anchor-verify + claim.
    #[serde(default)]
    pub seq_leg: Option<XSeqLeg>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XFail {
    #[serde(default)]
    #[allow(dead_code)]
    code: String,
    #[serde(default)]
    message: String,
}

/// Parse a daemon response body, surfacing an in-band `{fail:{...}}` (HTTP 200) as
/// an error before deserializing the success arm `T`.
fn parse_resp<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, Error> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(map)?;
    if let Some(fail) = v.get("fail") {
        let f: XFail = serde_json::from_value(fail.clone()).map_err(map)?;
        return Err(Error::Generic(format!("daemon rejected the cross-chain request: {}", f.message)));
    }
    serde_json::from_value(v).map_err(map)
}

#[derive(Deserialize)]
struct MarketsResp {
    #[serde(default)]
    markets: Vec<XchainMarket>,
}

#[derive(Deserialize)]
struct ProposeResp {
    #[serde(default)]
    accepted: Option<ProposeAccepted>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuoteReq<'a> {
    seq_asset: &'a str,
    seq_amount: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposeReq<'a> {
    quote_id: &'a str,
    hash: &'a str,
    btc_leg: &'a BtcLeg,
    taker_seq_claim_pub: &'a str,
    taker_btc_refund_pub: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwapReq<'a> {
    swap_id: &'a str,
}

// --- persisted swap state + at-rest seal --------------------------------------
//
// The taker's wallet is the source of truth: the daemon's swap state is in-memory
// and dies on restart, and there is no lookup-by-hash. So the full swap is
// persisted (sealed) BEFORE any money moves and re-sealed after every transition.

/// The step a cross-chain swap has reached. `SeqClaimed` is the point of no return
/// (the preimage is public); before it the swap is still refundable via the BTC leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XStep {
    /// Secret + keys generated, BTC HTLC built — nothing broadcast yet.
    SecretReady,
    /// The BTC funding tx is broadcast (in mempool).
    BtcFunding,
    /// The BTC funding is confirmed at `H_btc`.
    BtcLocked,
    /// The maker's SEQ leg is locked (proposed/accepted).
    SeqLocked,
    /// The SEQ leg passed the anchor + value-binding gates.
    SeqVerified,
    /// The taker revealed the preimage + claimed the SEQ leg (point of no return).
    SeqClaimed,
    /// The maker claimed the BTC leg with the revealed preimage (settled).
    BtcClaimed,
    /// The taker refunded the BTC leg via CLTV.
    Refunded,
    /// The swap failed/aborted.
    Failed,
}

/// The maker's SEQ leg, in the persisted state (plain serde, distinct from the
/// daemon-wire [`XSeqLeg`] whose ints are string-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XSeqLegState {
    /// SEQ-leg HTLC funding txid.
    pub txid: String,
    /// SEQ-leg HTLC funding vout.
    pub vout: u32,
    /// SEQ block hash the funding landed in (for the anchor lookup).
    pub block_hash: String,
    /// Maker-reported anchor height (informational; the gate re-derives it).
    pub anchor_height: i64,
    /// SEQ-leg redeemScript hex (value-binding compared vs the daemon).
    pub redeem_script: String,
    /// SEQ-leg amount, atoms.
    pub amount: u64,
    /// SEQ-leg asset id, display hex.
    pub asset_id: String,
}

impl From<&XSeqLeg> for XSeqLegState {
    fn from(l: &XSeqLeg) -> Self {
        Self {
            txid: l.txid.clone(),
            vout: l.vout,
            block_hash: l.block_hash.clone(),
            anchor_height: l.anchor_height,
            redeem_script: l.redeem_script.clone(),
            amount: l.amount,
            asset_id: l.asset_id.clone(),
        }
    }
}

/// The full state of one cross-chain swap — everything needed to claim, refund, or
/// recover it without the daemon. `secret_hex` is the non-HD preimage: it gates the
/// BTC claim and is unrecoverable if lost, so this whole record is sealed at rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XchainSwapState {
    /// The step reached (drives recovery + refundability).
    pub step: XStep,
    /// The Sequentia asset being bought, display hex.
    pub seq_asset: String,
    /// Amount of `seq_asset` bought, atoms.
    pub seq_amount: u64,
    /// Amount of BTC paid, sats.
    pub btc_amount: u64,
    /// Maker commission, sats.
    pub fee_btc: u64,
    /// SEAL — the non-HD swap preimage (gates the BTC claim).
    pub secret_hex: String,
    /// `H = sha256(secret)`, hex.
    pub hash_hex: String,
    /// Alice's SEQ-leg claim pubkey, hex.
    pub seq_claim_pub: String,
    /// Alice's BTC-leg refund pubkey, hex.
    pub btc_refund_pub: String,
    /// Which HD path funded the leg keys — recovery must derive the SAME key.
    pub key_path: PathMode,
    /// Maker's BTC-leg claim pubkey, hex.
    pub maker_btc_claim_pub: String,
    /// Maker's SEQ-leg refund pubkey, hex.
    pub maker_seq_refund_pub: String,
    /// BTC HTLC CLTV locktime (Bitcoin height).
    pub btc_locktime: u32,
    /// SEQ HTLC CLTV locktime (Sequentia height).
    pub seq_locktime: u32,
    /// The maker's quote id (single-use).
    pub quote_id: String,
    /// The daemon's swap id (persist from the propose response).
    pub swap_id: String,
    /// The BTC HTLC redeemScript hex.
    pub btc_redeem_script: String,
    /// The BTC HTLC P2SH address.
    pub btc_p2sh_address: String,
    /// The BTC HTLC P2SH scriptPubKey hex (to locate the funding output).
    pub btc_p2sh_spk_hex: String,
    /// The BTC funding txid, once broadcast.
    pub btc_funding_txid: Option<String>,
    /// The BTC funding vout.
    pub btc_vout: Option<u32>,
    /// The BTC funding confirmation height (`H_btc`).
    pub btc_height: Option<i64>,
    /// The maker's SEQ leg, once proposed/accepted.
    pub seq_leg: Option<XSeqLegState>,
    /// The SEQ claim txid, once revealed/claimed.
    pub seq_claim_txid: Option<String>,
    /// The BTC refund txid, if refunded.
    pub btc_refund_txid: Option<String>,
}

impl XchainSwapState {
    /// Refundable iff the BTC leg was funded and the swap hasn't passed the point
    /// of no return (or already settled/refunded).
    pub fn refundable(&self) -> bool {
        self.btc_funding_txid.is_some()
            && !matches!(self.step, XStep::SeqClaimed | XStep::BtcClaimed | XStep::Refunded)
    }
}

/// Seal a swap state under `passphrase` (age scrypt), returning base64. The
/// plaintext (incl. the non-HD secret) must never hit disk nor cross an FFI/JS
/// boundary unsealed; key `passphrase` off the wallet unlock.
pub fn seal_state(state: &XchainSwapState, passphrase: &str) -> Result<String, Error> {
    use base64::prelude::*;
    use std::io::Write;

    let json = serde_json::to_vec(state).map_err(map)?;
    let recipient = age::scrypt::Recipient::new(age::secrecy::SecretString::from(passphrase.to_owned()));
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient)).map_err(map)?;
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted).map_err(map)?;
    writer.write_all(&json).map_err(map)?;
    writer.finish().map_err(map)?;
    Ok(BASE64_STANDARD_NO_PAD.encode(encrypted))
}

/// Open a sealed swap state with `passphrase`.
pub fn open_state(sealed: &str, passphrase: &str) -> Result<XchainSwapState, Error> {
    use base64::prelude::*;
    use std::io::Read;

    let encrypted = BASE64_STANDARD_NO_PAD.decode(sealed).map_err(map)?;
    let identity = age::scrypt::Identity::new(age::secrecy::SecretString::from(passphrase.to_owned()));
    let mut reader = age::Decryptor::new(&encrypted[..])
        .map_err(map)?
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(map)?;
    let mut json = vec![];
    reader.read_to_end(&mut json).map_err(map)?;
    serde_json::from_slice(&json).map_err(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_encoded_uint64_and_omitted_zero() {
        // grpc-gateway: uint64 as strings, zero fields omitted.
        let q: XQuote = serde_json::from_str(
            r#"{"quoteId":"abc","seqAmount":"172409","btcAmount":"5000","feeBtc":"50","btcLocktime":900000,"seqLocktime":12345,"expiresAtUnix":"1700000000","makerBtcClaimPub":"02aa"}"#,
        )
        .unwrap();
        assert_eq!(q.seq_amount, 172409);
        assert_eq!(q.btc_amount, 5000);
        assert_eq!(q.fee_btc, 50);
        assert_eq!(q.btc_locktime, 900000);
        assert_eq!(q.expires_at_unix, 1700000000);
        assert_eq!(q.price_seq_per_btc, 0.0); // omitted -> default
        assert_eq!(q.maker_seq_refund_pub, ""); // omitted -> default
    }

    #[test]
    fn in_band_fail_is_an_error() {
        // An in-band {fail} at HTTP 200 is surfaced as an error before the success arm.
        let r: Result<ProposeResp, _> =
            parse_resp(r#"{"fail":{"code":"UNKNOWN_QUOTE","message":"unknown or expired quote_id"}}"#);
        assert!(r.is_err());
        // propose success is under "accepted".
        let ok: ProposeResp = parse_resp(r#"{"accepted":{"swapId":"s1","seqLeg":{"amount":"172409"}}}"#).unwrap();
        let acc = ok.accepted.expect("accepted present");
        assert_eq!(acc.swap_id, "s1");
        assert_eq!(acc.seq_leg.unwrap().amount, 172409);
    }

    // The reveal gate's truth table — the load-bearing safety predicate.
    #[test]
    fn gate_predicate() {
        // anchored, A >= H_btc, status ok, depth >= 1 -> safe.
        let e = evaluate_gate(100, "ok", 100, 100, 1);
        assert!(e.ok && e.depth == 1);
        // anchor below the BTC funding -> NOT safe (can't bind the legs).
        assert!(!evaluate_gate(99, "ok", 200, 100, 1).ok);
        // not anchored -> NOT safe.
        assert!(!evaluate_gate(-1, "ok", 200, 100, 1).ok);
        // status not ok -> NOT safe.
        assert!(!evaluate_gate(100, "stalled", 200, 100, 1).ok);
        // depth below the taker's dial -> NOT safe (anchor not buried enough).
        assert!(!evaluate_gate(200, "ok", 200, 100, 3).ok); // depth 1 < 3
        assert!(evaluate_gate(198, "ok", 200, 100, 3).ok); // depth 3 >= 3
    }

    #[test]
    fn deadline_predicate() {
        assert!(deadline_ok(100, 200, 10)); // 100 + 10 < 200
        assert!(!deadline_ok(195, 200, 10)); // 195 + 10 >= 200 -> too close
        assert!(!deadline_ok(-1, 200, 10)); // no tip -> refuse
    }

    #[test]
    fn claim_fee_sizing() {
        // rate 0 (asset not fee-accepted) -> refuse, never emit an unrelayable claim.
        assert!(seq_claim_fee_atoms(0, DEFAULT_SEQ_CLAIM_FEERATE).is_err());
        // native (rate 1e8) -> fee == native_value == feerate * vsize.
        let native = seq_claim_fee_atoms(100_000_000, 1).unwrap();
        assert_eq!(native, claim_tx_vsize()); // 1 atom/vB * 400 vB
        // a high-unit-value asset pays FEWER atoms (granularity), per first-principle 4.
        let gold = seq_claim_fee_atoms(4_377_615_194_112, 1).unwrap();
        assert!(gold >= 1 && gold < native, "a valuable asset pays fewer atoms (not a bug)");
    }

    // Legacy and canonical SEQ-claim keys differ (the web shim must record which).
    #[test]
    fn pathmode_keys_differ() {
        let p = ChainAddressParams::testnet();
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (_, canon) = seq_claim_keypair(&p, m, PathMode::Canonical).unwrap();
        let (_, legacy) = seq_claim_keypair(&p, m, PathMode::LegacyRelative).unwrap();
        assert_ne!(canon, legacy, "m/84'/1'/0'/3/0 and m/3/0 must derive different keys");
        assert_eq!(canon.len(), 66); // 33-byte compressed pubkey hex
    }

    fn sample_state() -> XchainSwapState {
        XchainSwapState {
            step: XStep::BtcLocked,
            seq_asset: "gold".into(),
            seq_amount: 172409,
            btc_amount: 5000,
            fee_btc: 50,
            secret_hex: "11".repeat(32),
            hash_hex: "22".repeat(32),
            seq_claim_pub: "02aa".into(),
            btc_refund_pub: "02bb".into(),
            key_path: PathMode::Canonical,
            maker_btc_claim_pub: "02cc".into(),
            maker_seq_refund_pub: "02dd".into(),
            btc_locktime: 900000,
            seq_locktime: 12345,
            quote_id: "q1".into(),
            swap_id: "s1".into(),
            btc_redeem_script: "63a8".into(),
            btc_p2sh_address: "2N...".into(),
            btc_p2sh_spk_hex: "a914".into(),
            btc_funding_txid: Some("ff".repeat(32)),
            btc_vout: Some(1),
            btc_height: Some(800000),
            seq_leg: None,
            seq_claim_txid: None,
            btc_refund_txid: None,
        }
    }

    // Live read-only validation of the REST client + the anchor gate against the
    // running infra. Ignored by default (needs network); run with:
    //   cargo test -p lwk_wollet --features btc-blocking --lib \
    //     btc::xchain::tests::live_markets_and_gate -- --ignored --nocapture
    #[test]
    #[ignore = "hits the live Sequentia testnet infra"]
    fn live_markets_and_gate() {
        let daemon = "http://159.195.15.140/dex";
        let seq = "http://159.195.15.140/api";
        let t4 = "http://159.195.15.140/testnet4/api";

        // (1) the XchainClient parses the live daemon's markets.
        let markets = blocking::xchain_markets(daemon).expect("markets");
        assert!(!markets.is_empty(), "expected live xchain markets");
        eprintln!("LIVE markets: {} (e.g. {} seqReserve={})", markets.len(), markets[0].name, markets[0].seq_reserve);

        // (2) the anchor gate, evaluated against the real SEQ tip block + the live
        //     testnet4 view. btc_leg_height=0 so only the anchored+depth conditions
        //     decide; this exercises the 3 live GETs + the parsing + the predicate.
        let client = reqwest::blocking::Client::new();
        let tip_hash = client.get(format!("{seq}/blocks/tip/hash")).send().unwrap().text().unwrap();
        let tip_hash = tip_hash.trim();
        let ev = blocking::verify_seq_leg_safe(seq, tip_hash, 0, t4, 1).expect("gate");
        eprintln!(
            "LIVE gate: seq_anchor_height={} btc_tip={} status={} depth={} ok={}",
            ev.seq_anchor_height, ev.btc_tip, ev.anchor_status, ev.depth, ev.ok
        );
        // The tip block must be anchored to a real Bitcoin block and the chain's
        // anchor status healthy — the safety-critical live behavior.
        assert!(ev.seq_anchor_height >= 0, "SEQ tip must carry a Bitcoin anchor");
        assert!(ev.btc_tip > 0, "must read the taker's own testnet4 tip");
        assert_eq!(ev.anchor_status, "ok", "anchor status must be ok");
    }

    // The non-HD secret must round-trip through the at-rest seal and never appear
    // in the sealed blob; a wrong passphrase must fail.
    #[test]
    fn seal_roundtrips_and_hides_the_secret() {
        let st = sample_state();
        let sealed = seal_state(&st, "unlock-pass").unwrap();
        assert!(!sealed.contains(&st.secret_hex), "the secret must not appear in the sealed blob");
        let opened = open_state(&sealed, "unlock-pass").unwrap();
        assert_eq!(opened.secret_hex, st.secret_hex);
        assert_eq!(opened.swap_id, "s1");
        assert_eq!(opened.key_path, PathMode::Canonical);
        assert!(opened.refundable()); // funded + not past the point of no return
        assert!(open_state(&sealed, "wrong-pass").is_err());
    }
}
