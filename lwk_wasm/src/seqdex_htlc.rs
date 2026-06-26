//! Sequentia (SeqDEX) cross-chain HTLC — Sequentia-leg wasm bindings for the browser taker.
//!
//! Phase 6c-2. This is the Sequentia-side counterpart to the same-chain swap binding in
//! [`crate::seqdex_swap`]. It exposes, to JS, exactly the pieces the web wallet needs
//! to do its half of a cross-chain BTC↔Sequentia swap where the **taker BUYS a Sequentia asset
//! with BTC**:
//!
//!   1. [`generateSwapSecret`] — make the 32-byte secret `s` and `H = sha256(s)`.
//!   2. [`Signer::htlcKeypair`] — derive the taker's Sequentia-claim key (pubkey for the
//!      daemon's `ProposeXchainSwap`; the private scalar stays in the wallet for
//!      signing the claim).
//!   3. [`buildSeqHtlcRedeemScript`] — the HTLC redeemScript (byte-identical to the
//!      daemon's `LockScript`).
//!   4. [`buildSeqHtlcClaimTx`] — the signed Sequentia-leg claim tx (IF/redeem branch),
//!      revealing `s` on-chain. This is the step that lets the daemon then extract
//!      `s` and claim the BTC leg.
//!   5. [`buildSeqHtlcRefundTx`] — the signed Sequentia-leg refund tx (ELSE/CLTV branch),
//!      built for completeness/symmetry (the Sequentia refund is the maker's in the MVP).
//!
//! The BTC-leg lock + BTC refund are NOT here — they are the wallet's existing
//! `btc.js`. All core logic lives in `lwk_wollet::seqdex_htlc`; this is the thin
//! wasm layer, mirroring how `seqdex_swap.rs` wraps `lwk_wollet::seqdex_swap`.

use lwk_wollet::{
    build_claim_tx, build_htlc_redeem_script, build_refund_tx, generate_swap_secret,
    pubkey_for_secret, secret_from_hex, SeqHtlcSpend,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{Error, Signer};

/// A freshly generated swap secret + hashlock, the taker-initiator's starting point.
///
/// JS shape: `{ secret_hex: string, hash_hex: string }`.
#[derive(Serialize)]
struct SwapSecretJson {
    secret_hex: String,
    hash_hex: String,
}

/// Generate a fresh 32-byte swap secret `s` and its `H = sha256(s)`.
///
/// Returns `{ secret_hex, hash_hex }`. The taker hands `hash_hex` (H) to the daemon
/// (BTC-leg lock + `ProposeXchainSwap`) and keeps `secret_hex` (s) to claim the Sequentia
/// leg. Mirrors the Go taker's `rand.Read(secret)` + `sha256.Sum256`.
#[wasm_bindgen(js_name = generateSwapSecret)]
pub fn generate_swap_secret_js() -> Result<JsValue, Error> {
    let s = generate_swap_secret();
    Ok(serde_wasm_bindgen::to_value(&SwapSecretJson {
        secret_hex: s.secret_hex,
        hash_hex: s.hash_hex,
    })?)
}

/// The taker's Sequentia-leg HTLC claim keypair.
///
/// JS shape: `{ public_key: string (33-byte compressed hex), secret_hex: string }`.
/// `public_key` goes to the daemon as `taker_seq_claim_pub`; `secret_hex` is the
/// scalar the wallet keeps to sign the Sequentia-leg claim ([`buildSeqHtlcClaimTx`]).
#[derive(Serialize)]
struct HtlcKeypairJson {
    public_key: String,
    secret_hex: String,
}

#[wasm_bindgen]
impl Signer {
    /// Derive the taker's dedicated Sequentia cross-chain HTLC claim keypair at m/3/0.
    ///
    /// Deterministic and recoverable from the wallet seed (distinct from staking's
    /// m/2/0). Returns `{ public_key, secret_hex }`: give `public_key` to the daemon
    /// as the Sequentia claim pubkey in `ProposeXchainSwap`, and pass `secret_hex` to
    /// [`buildSeqHtlcClaimTx`] to sign the claim. The matching BTC-refund pubkey the
    /// daemon also needs is produced by the wallet's BTC side (`btc.js`).
    #[wasm_bindgen(js_name = htlcKeypair)]
    pub fn htlc_keypair(&self) -> Result<JsValue, Error> {
        use lwk_wollet::bitcoin::bip32;
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Normal { index: 3 },
            bip32::ChildNumber::Normal { index: 0 },
        ]);
        let xprv = self
            .inner
            .derive_xprv(&path)
            .map_err(|e| Error::Generic(e.to_string()))?;
        let secret_hex = xprv.private_key.secret_bytes();
        let secret_hex = secret_hex
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let public_key = pubkey_for_secret(&secret_hex)?;
        Ok(serde_wasm_bindgen::to_value(&HtlcKeypairJson {
            public_key,
            secret_hex,
        })?)
    }
}

/// Build the Design-A HTLC redeemScript for the Sequentia leg.
///
/// `hash` is `H` (hex), `claim_pub` / `refund_pub` are 33-byte compressed pubkeys
/// (hex), `locktime` the CLTV value. Returns the redeemScript as hex. Byte-identical
/// to the daemon's `LockScript`, so the browser can independently verify the Sequentia leg
/// the daemon locked.
#[wasm_bindgen(js_name = buildSeqHtlcRedeemScript)]
pub fn build_seq_htlc_redeem_script(
    hash: &str,
    claim_pub: &str,
    refund_pub: &str,
    locktime: u32,
) -> Result<String, Error> {
    let hash = hex_bytes(hash, "hash")?;
    let claim = hex_bytes(claim_pub, "claim_pub")?;
    let refund = hex_bytes(refund_pub, "refund_pub")?;
    let script = build_htlc_redeem_script(&hash, &claim, &refund, locktime)?;
    Ok(hex_of(script.as_bytes()))
}

/// The Sequentia HTLC output a claim/refund spends, as a JS object.
///
/// JS shape:
/// `{ txid, vout, amount, asset_id, dest_spk (hex scriptPubKey), fee }`.
/// `amount`/`fee` are in atoms; `txid`/`asset_id` are display hex. `dest_spk` is the
/// destination scriptPubKey hex (a fresh wallet address' SPK).
#[derive(Deserialize)]
struct SeqHtlcSpendJson {
    txid: String,
    vout: u32,
    amount: u64,
    asset_id: String,
    dest_spk: String,
    fee: u64,
}

fn parse_spend(spend: JsValue) -> Result<SeqHtlcSpend, Error> {
    let s: SeqHtlcSpendJson = serde_wasm_bindgen::from_value(spend)?;
    Ok(SeqHtlcSpend {
        txid: s.txid,
        vout: s.vout,
        amount: s.amount,
        asset_id: s.asset_id,
        dest_spk: hex_bytes(&s.dest_spk, "dest_spk")?,
        fee: s.fee,
    })
}

/// Build the signed Sequentia-leg **claim** (IF/redeem branch) tx, revealing the preimage.
///
/// - `spend`: `{ txid, vout, amount, asset_id, dest_spk, fee }` of the Sequentia HTLC the
///   daemon locked (from the `ProposeXchainSwap` accept's `seq_leg`).
/// - `redeem_script`: the HTLC redeemScript hex (from [`buildSeqHtlcRedeemScript`]).
/// - `claim_secret`: the taker's Sequentia-claim private scalar hex (from
///   [`Signer::htlcKeypair`]).
/// - `preimage`: the 32-byte swap secret `s` hex (from [`generateSwapSecret`]).
///
/// Returns the signed Elements tx hex for `sendrawtransaction`. Broadcasting it
/// reveals `s` on-chain; the daemon's watcher then extracts `s` and claims the BTC
/// leg (the swap reaches BTC_CLAIMED).
#[wasm_bindgen(js_name = buildSeqHtlcClaimTx)]
pub fn build_seq_htlc_claim_tx(
    spend: JsValue,
    redeem_script: &str,
    claim_secret: &str,
    preimage: &str,
) -> Result<String, Error> {
    let spend = parse_spend(spend)?;
    let script = parse_script(redeem_script)?;
    let key = secret_from_hex(claim_secret)?;
    let preimage = hex_bytes(preimage, "preimage")?;
    Ok(build_claim_tx(&spend, &script, &key, &preimage)?)
}

/// Build the signed Sequentia-leg **refund** (ELSE/CLTV branch) tx, valid once nLockTime
/// reaches `locktime`.
///
/// `refund_secret` is the scalar (hex) of the refund key embedded in the script.
/// Built for symmetry/completeness; in the MVP the Sequentia refund is the maker's.
#[wasm_bindgen(js_name = buildSeqHtlcRefundTx)]
pub fn build_seq_htlc_refund_tx(
    spend: JsValue,
    redeem_script: &str,
    refund_secret: &str,
    locktime: u32,
) -> Result<String, Error> {
    let spend = parse_spend(spend)?;
    let script = parse_script(redeem_script)?;
    let key = secret_from_hex(refund_secret)?;
    Ok(build_refund_tx(&spend, &script, &key, locktime)?)
}

fn parse_script(hex: &str) -> Result<lwk_wollet::elements::Script, Error> {
    Ok(lwk_wollet::elements::Script::from(hex_bytes(hex, "redeem_script")?))
}

fn hex_bytes(s: &str, what: &str) -> Result<Vec<u8>, Error> {
    use lwk_wollet::elements::hex::FromHex;
    Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("invalid {what} hex: {e}")))
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
