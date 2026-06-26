//! Cross-chain (BTC <-> Sequentia-asset) HTLC swap — wasm bindings for the web wallet.
//!
//! Exposes the kit's cross-chain glue ([`lwk_wollet::btc::xchain`]) so the web
//! wallet's `xswap.js` can be retired. The taker (Alice) holds BTC, wants the SEQ
//! asset: fund the BTC HTLC, quote+propose to the maker, independently anchor-verify
//! the SEQ leg from the wallet's OWN node, then claim it (revealing the preimage).
//! The recovery phrase is passed per signing call (as elsewhere in the web wallet);
//! the non-HD swap secret is sealed at rest via `sealState`/`openState`.

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

/// Build the SEQ claim tx (reveals the preimage). Only after the reveal gate
/// passes. Returns the raw Elements tx hex for [`Self::seq_broadcast`].
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

/// Seal the swap-state JSON (incl. the non-HD secret) under a passphrase; base64.
#[wasm_bindgen(js_name = xchainSealState)]
pub fn xchain_seal_state(state_json: &str, passphrase: &str) -> Result<String, Error> {
    let state: xchain::XchainSwapState = serde_json::from_str(state_json).map_err(|e| Error::Generic(e.to_string()))?;
    xchain::seal_state(&state, passphrase).map_err(to_err)
}

/// Open a sealed swap state; returns the state JSON.
#[wasm_bindgen(js_name = xchainOpenState)]
pub fn xchain_open_state(sealed: &str, passphrase: &str) -> Result<String, Error> {
    let state = xchain::open_state(sealed, passphrase).map_err(to_err)?;
    serde_json::to_string(&state).map_err(|e| Error::Generic(e.to_string()))
}

// --- the daemon + node interactions (async) ------------------------------------

/// A configured cross-chain session: the daemon (XchainService), the wallet's OWN
/// Sequentia esplora, and its OWN testnet4 esplora (the anchor gate reads only
/// these — never the maker).
#[wasm_bindgen]
pub struct XchainSwap {
    daemon: String,
    seq_esplora: String,
    t4_api: String,
}

#[wasm_bindgen]
impl XchainSwap {
    #[wasm_bindgen(constructor)]
    pub fn new(daemon: String, seq_esplora: String, t4_api: String) -> XchainSwap {
        XchainSwap { daemon, seq_esplora, t4_api }
    }

    /// The maker's cross-chain markets (array of `{btcAsset, seqAsset, name, ...}`).
    pub async fn markets(&self) -> Result<JsValue, Error> {
        let m = xchain::asyncr::xchain_markets(&self.daemon).await.map_err(to_err)?;
        js(&m)
    }

    /// Quote buying `seq_amount` of `seq_asset` with BTC.
    pub async fn quote(&self, seq_asset: String, seq_amount: u64) -> Result<JsValue, Error> {
        let q = xchain::asyncr::xchain_quote(&self.daemon, &seq_asset, seq_amount).await.map_err(to_err)?;
        js(&q)
    }

    /// Propose the swap with the funded BTC leg. Persist `swapId` from the result
    /// BEFORE anything else; never auto-retry (the quote is single-use).
    #[allow(clippy::too_many_arguments)]
    pub async fn propose(
        &self,
        quote_id: String,
        hash: String,
        btc_txid: String,
        btc_vout: u32,
        btc_height: i64,
        btc_redeem_script: String,
        btc_amount: u64,
        btc_asset_id: String,
        taker_seq_claim_pub: String,
        taker_btc_refund_pub: String,
    ) -> Result<JsValue, Error> {
        let leg = xchain::BtcLeg::new(&btc_txid, btc_vout, btc_height, &btc_redeem_script, btc_amount, &btc_asset_id);
        let accepted =
            xchain::asyncr::xchain_propose(&self.daemon, &quote_id, &hash, &leg, &taker_seq_claim_pub, &taker_btc_refund_pub)
                .await
                .map_err(to_err)?;
        js(&accepted)
    }

    /// Poll a swap's status by id (tolerates a 404: the maker's state is in-memory).
    pub async fn swap_status(&self, swap_id: String) -> Result<JsValue, Error> {
        let s = xchain::asyncr::xchain_swap_status(&self.daemon, &swap_id).await.map_err(to_err)?;
        js(&s)
    }

    /// THE REVEAL GATE, evaluated from the wallet's OWN nodes. Returns
    /// `AnchorEvidence` (`{ ok, depth, seqAnchorHeight, ... }`). Only reveal when ok.
    pub async fn verify_seq_leg(&self, seq_block_hash: String, btc_leg_height: i64, min_depth: i64) -> Result<JsValue, Error> {
        let e = xchain::asyncr::verify_seq_leg_safe(&self.seq_esplora, &seq_block_hash, btc_leg_height, &self.t4_api, min_depth)
            .await
            .map_err(to_err)?;
        js(&e)
    }

    /// Whether there is safe margin before the SEQ-leg CLTV refund height (read from
    /// the wallet's own SEQ tip). Refuse to reveal when false.
    pub async fn claim_deadline_ok(&self, seq_locktime: u32, margin: i64) -> bool {
        xchain::asyncr::claim_deadline_ok(&self.seq_esplora, seq_locktime, margin).await
    }

    /// Broadcast a raw SEQ (Elements) claim tx hex; returns the txid.
    pub async fn seq_broadcast(&self, tx_hex: String) -> Result<String, Error> {
        xchain::asyncr::seq_broadcast(&self.seq_esplora, &tx_hex).await.map_err(to_err)
    }

    /// Locate the BTC HTLC funding output by its P2SH spk on testnet4:
    /// `{ vout, valueSats, height, confirmations }`.
    pub async fn find_btc_funding(&self, txid: String, p2sh_spk_hex: String) -> Result<JsValue, Error> {
        let f = lwk_wollet::btc::wallet_async::find_htlc_funding(&self.t4_api, &txid, &p2sh_spk_hex).await.map_err(to_err)?;
        js(&serde_json::json!({
            "vout": f.vout,
            "valueSats": f.value_sats,
            "height": f.height,
            "confirmations": f.confirmations,
        }))
    }
}
