//! Cross-chain (BTC <-> Sequentia-asset) HTLC swap — wasm bindings for the web wallet.
//!
//! Exposes the kit's cross-chain glue ([`lwk_wollet::btc::xchain`]): the swap
//! secret, the HTLC spend-key derivation, the BTC HTLC and the Sequentia-leg
//! redeemScript, the Sequentia-leg claim, and the BTC claim/refund. Most of it is pure
//! crypto (no I/O); the four OWN-NODE reads at the end of this file are the
//! exception, and they are the fund-safety surface — see the section header
//! there. The recovery phrase is passed per signing call, as elsewhere in the web
//! wallet.

use lwk_wollet::bitcoin::hex::FromHex;
use lwk_wollet::bitcoin::ScriptBuf;
use lwk_wollet::btc::addr::ChainAddressParams;
use lwk_wollet::btc::{htlc, xchain};
use wasm_bindgen::prelude::*;

use crate::Error;

fn params() -> ChainAddressParams {
    ChainAddressParams::testnet()
}
fn to_err(e: lwk_wollet::Error) -> Error {
    Error::Generic(e.to_string())
}
fn hexbytes(s: &str) -> Result<Vec<u8>, Error> {
    Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(e.to_string()))
}
fn js<T: serde::Serialize>(v: &T) -> Result<JsValue, Error> {
    Ok(serde_wasm_bindgen::to_value(v)?)
}

// --- pure crypto (no I/O) ------------------------------------------------------

/// `{ secretHex, hashHex }` — a fresh preimage + its hashlock. Persist (sealed)
/// before any money moves; the secret is non-HD and gates the BTC claim.
#[wasm_bindgen(js_name = xchainNewSecret)]
pub fn xchain_new_secret() -> Result<JsValue, Error> {
    let (secret_hex, hash_hex) = xchain::new_secret();
    js(&serde_json::json!({ "secretHex": secret_hex, "hashHex": hash_hex }))
}

/// Alice's SEQ-leg claim pubkey (the secret key stays in the wallet).
#[wasm_bindgen(js_name = xchainSeqClaimPubkey)]
pub fn xchain_seq_claim_pubkey(mnemonic: &str) -> Result<String, Error> {
    xchain::seq_claim_keypair(&params(), mnemonic, xchain::PathMode::Canonical).map(|(_, p)| p).map_err(to_err)
}

/// Alice's BTC-leg refund pubkey.
#[wasm_bindgen(js_name = xchainBtcRefundPubkey)]
pub fn xchain_btc_refund_pubkey(mnemonic: &str) -> Result<String, Error> {
    xchain::btc_refund_keypair(&params(), mnemonic, xchain::PathMode::Canonical).map(|(_, p)| p).map_err(to_err)
}

/// The device's BTC-leg CLAIM pubkey (33-byte compressed hex). This is the
/// `btc_claim_pub` the wallet sends to the LSP `/swap {side:sell}`; the LSP puts it
/// in the HTLC's IF branch, and `xchainBtcClaim` signs the on-chain claim with the
/// matching key. Derived at a DISTINCT path from `xchainBtcRefundPubkey`.
#[wasm_bindgen(js_name = xchainBtcClaimPubkey)]
pub fn xchain_btc_claim_pubkey(mnemonic: &str) -> Result<String, Error> {
    xchain::btc_claim_keypair(&params(), mnemonic, xchain::PathMode::Canonical).map(|(_, p)| p).map_err(to_err)
}

/// Build the BTC HTLC the wallet funds: `{ redeemScriptHex, p2shAddress, p2shSpkHex }`.
#[wasm_bindgen(js_name = xchainBtcHtlc)]
pub fn xchain_btc_htlc(hash_hex: &str, claim_pub_hex: &str, refund_pub_hex: &str, locktime: u32) -> Result<JsValue, Error> {
    let redeem = htlc::build_htlc_redeem_script(&hexbytes(hash_hex)?, &hexbytes(claim_pub_hex)?, &hexbytes(refund_pub_hex)?, locktime)
        .map_err(to_err)?;
    let (address, spk) = htlc::htlc_p2sh(&redeem).map_err(to_err)?;
    js(&serde_json::json!({
        "redeemScriptHex": redeem.to_hex_string(),
        "p2shAddress": address.to_string(),
        "p2shSpkHex": spk.to_hex_string(),
    }))
}

/// The SEQ-leg redeemScript hex Alice rebuilds — byte-compare it to the daemon's
/// reported `seqLeg.redeemScript` (value-binding) before trusting the leg.
#[wasm_bindgen(js_name = xchainSeqRedeemScript)]
pub fn xchain_seq_redeem_script(mnemonic: &str, hash_hex: &str, maker_seq_refund_pub_hex: &str, seq_locktime: u32) -> Result<String, Error> {
    xchain::seq_redeem_script_hex(&params(), mnemonic, xchain::PathMode::Canonical, hash_hex, maker_seq_refund_pub_hex, seq_locktime)
        .map_err(to_err)
}

/// The SEQ-leg claim fee in atoms of the claimed asset, from `rate` (the asset's
/// published acceptance rate) and a SEQ-native feerate. Errors if `rate == 0`
/// (the asset is not fee-accepted, so the claim would be unrelayable).
#[wasm_bindgen(js_name = xchainSeqClaimFee)]
pub fn xchain_seq_claim_fee(rate: u64, seq_feerate_native: u64) -> Result<u64, Error> {
    xchain::seq_claim_fee_atoms(rate, seq_feerate_native).map_err(to_err)
}

/// Build the Sequentia-leg claim tx (reveals the preimage). Only after the reveal gate
/// passes. Returns the raw Elements tx hex; broadcasting it is the caller's job
/// (`lwk_wollet::btc::xchain::asyncr::seq_broadcast` on the Rust side).
#[wasm_bindgen(js_name = xchainSeqClaim)]
#[allow(clippy::too_many_arguments)]
pub fn xchain_seq_claim(
    mnemonic: &str,
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
    xchain::seq_claim(
        &params(),
        mnemonic,
        xchain::PathMode::Canonical,
        seq_txid,
        seq_vout,
        seq_amount,
        seq_asset_id,
        dest_address,
        hash_hex,
        maker_seq_refund_pub_hex,
        seq_locktime,
        fee,
        preimage_hex,
    )
    .map_err(to_err)
}

/// Build + sign the BTC HTLC refund (CLTV/ELSE branch), valid once the tip reaches
/// `locktime`. Returns raw tx hex to broadcast via the BTC wallet.
#[wasm_bindgen(js_name = xchainBtcRefund)]
#[allow(clippy::too_many_arguments)]
pub fn xchain_btc_refund(
    mnemonic: &str,
    redeem_script_hex: &str,
    dest_spk_hex: &str,
    btc_txid: &str,
    btc_vout: u32,
    btc_amount_sats: u64,
    fee_sats: u64,
    locktime: u32,
) -> Result<String, Error> {
    let (sk, _) = xchain::btc_refund_keypair(&params(), mnemonic, xchain::PathMode::Canonical).map_err(to_err)?;
    let redeem = ScriptBuf::from_hex(redeem_script_hex).map_err(|e| Error::Generic(e.to_string()))?;
    let spend = htlc::BtcHtlcSpend {
        txid: btc_txid.to_string(),
        vout: btc_vout,
        amount_sats: btc_amount_sats,
        dest_spk: ScriptBuf::from_hex(dest_spk_hex).map_err(|e| Error::Generic(e.to_string()))?,
        fee_sats,
    };
    htlc::build_refund_tx(&redeem, &spend, locktime, &sk).map_err(to_err)
}

/// Build + sign the BTC HTLC CLAIM (IF/preimage branch) for a sub-asset SELL. The
/// exact mirror of `xchainBtcRefund` but the CLAIM key + IF-branch items: scriptSig
/// `<sig> <preimage> OP_1 <redeemScript>`, `nSequence = 0xffffffff`, `nLockTime = 0`.
/// Same proven legacy `CalcSignatureHash` + low-S DER || 0x01 signing. Returns raw tx
/// hex to broadcast. Pass `redeem_script_hex` = the `btc_htlc.redeem_script` from the
/// `/swap` response (rebuild + byte-compare it via `xchainBtcHtlc` first),
/// `dest_spk_hex` = the scriptPubKey the claimed BTC pays to, and `preimage_hex` = the
/// `preimage` the LSP returned.
#[wasm_bindgen(js_name = xchainBtcClaim)]
#[allow(clippy::too_many_arguments)]
pub fn xchain_btc_claim(
    mnemonic: &str,
    redeem_script_hex: &str,
    dest_spk_hex: &str,
    btc_txid: &str,
    btc_vout: u32,
    btc_amount_sats: u64,
    fee_sats: u64,
    preimage_hex: &str,
) -> Result<String, Error> {
    let (sk, _) = xchain::btc_claim_keypair(&params(), mnemonic, xchain::PathMode::Canonical).map_err(to_err)?;
    let redeem = ScriptBuf::from_hex(redeem_script_hex).map_err(|e| Error::Generic(e.to_string()))?;
    let preimage = hexbytes(preimage_hex)?;
    let spend = htlc::BtcHtlcSpend {
        txid: btc_txid.to_string(),
        vout: btc_vout,
        amount_sats: btc_amount_sats,
        dest_spk: ScriptBuf::from_hex(dest_spk_hex).map_err(|e| Error::Generic(e.to_string()))?,
        fee_sats,
    };
    htlc::build_claim_tx(&redeem, &spend, &preimage, &sk).map_err(to_err)
}

// --- OWN-NODE reads: THE FUND-SAFETY SURFACE ----------------------------------
//
// ⚠ THESE FOUR ARE NOT RFQ CODE. DO NOT SWEEP THEM.
//
// They were previously methods on a `XchainSwap` wasm class that ALSO carried the
// retired RFQ rail's markets/quote/propose/swap_status. Deleting the RFQ rail by
// CONTAINER took these with it, which left `lwk_wollet::btc::xchain::asyncr` —
// including verify_seq_leg_safe, the anchor reveal gate — reachable from no
// consumer at all, and the browser taker with no way to reach the audited Rust
// gate. Removal must be decided by reachability from a live entry point, never by
// which struct a function happened to live in.
//
// They are free functions now precisely so no future container deletion can take
// them again. Each takes the endpoint it reads explicitly: these are the WALLET'S
// OWN nodes, and the whole point of the gate is that it never consults the
// counterparty.

/// THE ANCHOR REVEAL GATE, evaluated from the wallet's OWN nodes. Returns
/// `AnchorEvidence` (`{ ok, depth, seqAnchorHeight, ... }`). Reveal only when ok:
/// the Sequentia block holding the asset leg must anchor at or above the
/// Bitcoin-leg height, so a Bitcoin reorg that could undo the BTC lock also undoes
/// the asset leg. This is the browser taker's entry to the audited Rust gate.
#[wasm_bindgen(js_name = xchainVerifySeqLeg)]
pub async fn xchain_verify_seq_leg(
    seq_esplora: String,
    t4_api: String,
    seq_block_hash: String,
    btc_leg_height: i64,
    min_depth: i64,
) -> Result<JsValue, Error> {
    let e = xchain::asyncr::verify_seq_leg_safe(
        &seq_esplora,
        &seq_block_hash,
        btc_leg_height,
        &t4_api,
        min_depth,
    )
    .await
    .map_err(to_err)?;
    js(&e)
}

/// Whether there is safe margin left before the Sequentia-leg CLTV refund height,
/// read from the wallet's own Sequentia tip. Refuse to reveal the preimage when
/// this is false: claiming inside the margin races the counterparty's refund.
#[wasm_bindgen(js_name = xchainClaimDeadlineOk)]
pub async fn xchain_claim_deadline_ok(seq_esplora: String, seq_locktime: u32, margin: i64) -> bool {
    xchain::asyncr::claim_deadline_ok(&seq_esplora, seq_locktime, margin).await
}

/// Broadcast a raw Sequentia-leg (Elements) claim tx hex; returns the txid.
#[wasm_bindgen(js_name = xchainSeqBroadcast)]
pub async fn xchain_seq_broadcast(seq_esplora: String, tx_hex: String) -> Result<String, Error> {
    xchain::asyncr::seq_broadcast(&seq_esplora, &tx_hex)
        .await
        .map_err(to_err)
}

/// Locate the BTC HTLC funding output by its P2SH scriptPubKey on testnet4:
/// `{ vout, valueSats, height, confirmations }`.
#[wasm_bindgen(js_name = xchainFindBtcFunding)]
pub async fn xchain_find_btc_funding(
    t4_api: String,
    txid: String,
    p2sh_spk_hex: String,
) -> Result<JsValue, Error> {
    let f = lwk_wollet::btc::wallet_async::find_htlc_funding(&t4_api, &txid, &p2sh_spk_hex)
        .await
        .map_err(to_err)?;
    js(&serde_json::json!({
        "vout": f.vout,
        "valueSats": f.value_sats,
        "height": f.height,
        "confirmations": f.confirmations,
    }))
}
