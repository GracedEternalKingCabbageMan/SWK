//! OpenAMP restricted-asset wasm bindings.
//!
//! Thin `#[wasm_bindgen]` layer over `lwk_wollet::openamp` (SWK-2/SWK-6),
//! mirroring the shape of the existing [`crate::Amp2`] wrapper. It exposes to the
//! browser wallet:
//!
//! - the MANDATORY safety mechanism (spec 0.4(3)): [`enclave_sighash`] recomputes
//!   the Elements taproot enclave sighash the wallet must sign, and
//!   [`decode_enclave_spend`] returns the human-readable effects to display first;
//! - [`compute_aid`] for the local-AID assertion (spec 1.3);
//! - [`Openamp`], a typed client for the 0.3 endpoints and the 1.6 hosted-transfer
//!   state machine.
//!
//! Enclave-spend SIGNING is not here: it lives on [`crate::Signer`] (SWK-1,
//! `openampSignSighash`), which signs the digest this module recomputed and never
//! sees the secret.

use std::collections::BTreeMap;

use lwk_wollet::elements;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use wasm_bindgen::prelude::*;

use crate::Error;

/// Compute the OpenAMP AID locally from a set of 64-hex x-only pubkeys (spec 0.2),
/// identical to Go `store.AID`. Wallets MUST call this and assert equality with the
/// server's AID after registration (spec 1.3).
#[wasm_bindgen(js_name = openampComputeAid)]
pub fn compute_aid(pubkeys: JsValue) -> Result<String, Error> {
    let keys: Vec<String> = serde_wasm_bindgen::from_value(pubkeys)?;
    Ok(lwk_wollet::compute_aid(&keys))
}

/// The OpenAMP tagged hash (spec 0.4(2)) over a hex message, returned as 32-byte
/// hex. Exposed for cross-checking / testing; signing uses
/// `Signer.openampSignTagged`.
#[wasm_bindgen(js_name = openampTaggedHash)]
pub fn tagged_hash(tag: &str, message_hex: &str) -> Result<String, Error> {
    let message = Vec::<u8>::from_hex(message_hex)
        .map_err(|e| Error::Generic(format!("invalid message hex: {e}")))?;
    Ok(lwk_wollet::tagged_hash(tag, &message).to_hex())
}

fn parse_tx(tx_hex: &str) -> Result<elements::Transaction, Error> {
    let bytes = Vec::<u8>::from_hex(tx_hex)
        .map_err(|e| Error::Generic(format!("invalid tx hex: {e}")))?;
    elements::encode::deserialize(&bytes)
        .map_err(|e| Error::Generic(format!("tx decode: {e}")))
}

fn parse_prevouts(prevouts: JsValue) -> Result<Vec<elements::TxOut>, Error> {
    let records: Vec<lwk_wollet::EnclavePrevout> = serde_wasm_bindgen::from_value(prevouts)?;
    Ok(lwk_wollet::prevouts_to_txouts(&records)?)
}

/// Recompute the Elements taproot enclave sighash (SIGHASH_DEFAULT,
/// genesis-committed) for a foreign NUMS script-path input (SWK-6, spec 0.4(3)).
///
/// - `tx_hex`: the FULL transaction the wallet is asked to sign.
/// - `input_index`: which input this enclave spend is.
/// - `prevouts`: array of `{asset, value, script}` aligned with the tx inputs.
/// - `leaf_script_hex`: the enclave transfer leaf (`<K_user> CSV <K_policy> CS`).
/// - `control_block_hex`: the leaf control block (its first byte is the leaf
///   version `0xc4` with the parity bit).
/// - `genesis_hex`: the network genesis block hash (the taproot sighash domain
///   separator; the wallet supplies its own network's genesis).
///
/// Returns the 32-byte sighash as hex. The wallet MUST sign THIS value, refusing
/// if it differs from the server's `to_sign` digest.
#[wasm_bindgen(js_name = enclaveSighash)]
pub fn enclave_sighash(
    tx_hex: &str,
    input_index: u32,
    prevouts: JsValue,
    leaf_script_hex: &str,
    control_block_hex: &str,
    genesis_hex: &str,
) -> Result<String, Error> {
    use std::str::FromStr;
    let tx = parse_tx(tx_hex)?;
    let prevouts = parse_prevouts(prevouts)?;
    let leaf = elements::Script::from(
        Vec::<u8>::from_hex(leaf_script_hex)
            .map_err(|e| Error::Generic(format!("invalid leaf hex: {e}")))?,
    );
    let control_block = Vec::<u8>::from_hex(control_block_hex)
        .map_err(|e| Error::Generic(format!("invalid control block hex: {e}")))?;
    let genesis = elements::BlockHash::from_str(genesis_hex)
        .map_err(|e| Error::Generic(format!("invalid genesis hash: {e}")))?;
    let sighash = lwk_wollet::enclave_sighash(
        &tx,
        input_index as usize,
        &prevouts,
        &leaf,
        &control_block,
        genesis,
    )?;
    Ok(sighash.to_hex())
}

/// Decode a candidate enclave-spend transaction into the effects to display before
/// signing (SWK-6, spec 0.4(3)): which of my UTXOs are spent, every output's
/// asset/amount/recipient, which outputs are receipts to me, and whether anything
/// is confidential. `my_scripts` is an array of MY enclave scriptPubKeys (hex).
///
/// Returns a JS object `{ txid, inputs[], outputs[], my_inputs_spent[],
/// any_confidential }`.
#[wasm_bindgen(js_name = decodeEnclaveSpend)]
pub fn decode_enclave_spend(
    tx_hex: &str,
    prevouts: JsValue,
    my_scripts: JsValue,
) -> Result<JsValue, Error> {
    let tx = parse_tx(tx_hex)?;
    let prevouts = parse_prevouts(prevouts)?;
    let scripts: Vec<String> = serde_wasm_bindgen::from_value(my_scripts)?;
    let effects = lwk_wollet::decode_enclave_spend(&tx, &prevouts, &scripts)?;
    Ok(serde_wasm_bindgen::to_value(&effects)?)
}

/// A typed OpenAMP client (SWK-3), mirroring the [`crate::Amp2`] wrapper shape over
/// `lwk_wollet::openamp::OpenampClient`. All calls are async and return plain JS
/// objects.
#[wasm_bindgen]
pub struct Openamp {
    inner: lwk_wollet::OpenampClient,
}

#[wasm_bindgen]
impl Openamp {
    /// Create a client for a base URL, for example
    /// `https://sequentiatestnet.com/openamp` or `location.origin + "/openamp"`.
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: &str) -> Openamp {
        Openamp {
            inner: lwk_wollet::OpenampClient::new(base_url),
        }
    }

    /// Compute the local AID for a set of pubkeys (spec 0.2). Sync; no network.
    #[wasm_bindgen(js_name = computeLocalAid)]
    pub fn compute_local_aid(&self, pubkeys: JsValue) -> Result<String, Error> {
        let keys: Vec<String> = serde_wasm_bindgen::from_value(pubkeys)?;
        Ok(lwk_wollet::compute_aid(&keys))
    }

    /// Register (idempotent) a set of pubkeys and return the AID, ASSERTING the
    /// server AID equals the locally computed one (spec 1.3). Errors on mismatch.
    #[wasm_bindgen(js_name = registerUser)]
    pub async fn register_user(&self, pubkeys: JsValue) -> Result<String, Error> {
        let keys: Vec<String> = serde_wasm_bindgen::from_value(pubkeys)?;
        let local = lwk_wollet::compute_aid(&keys);
        let server = self.inner.register_user(keys).await?;
        if server != local {
            return Err(Error::Generic(format!(
                "server AID {server} != local AID {local} (registration integrity failure)"
            )));
        }
        Ok(server)
    }

    /// Fetch a user record `{aid, pubkeys, categories, frozen}` (defaults applied).
    #[wasm_bindgen(js_name = getUser)]
    pub async fn get_user(&self, aid: String) -> Result<JsValue, Error> {
        let u = self.inner.get_user(&aid).await?;
        Ok(serde_wasm_bindgen::to_value(&u)?)
    }

    /// Fetch the per-asset enclave deposit address.
    #[wasm_bindgen(js_name = enclaveAddress)]
    pub async fn enclave_address(&self, aid: String, asset: String) -> Result<JsValue, Error> {
        let a = self.inner.get_address(&aid, &asset).await?;
        Ok(serde_wasm_bindgen::to_value(&a)?)
    }

    /// Fetch the confirmed enclave balance for one asset.
    pub async fn balance(&self, aid: String, asset: String) -> Result<JsValue, Error> {
        let b = self.inner.get_balance(&aid, &asset).await?;
        Ok(serde_wasm_bindgen::to_value(&b)?)
    }

    /// Fetch the full asset record (rules + contract with the openamp block).
    #[wasm_bindgen(js_name = assetInfo)]
    pub async fn asset_info(&self, asset: String) -> Result<JsValue, Error> {
        let v = self.inner.get_asset(&asset).await?;
        Ok(serde_wasm_bindgen::to_value(&v)?)
    }

    /// Fetch all asset records.
    pub async fn assets(&self) -> Result<JsValue, Error> {
        let v = self.inner.get_assets().await?;
        Ok(serde_wasm_bindgen::to_value(&v)?)
    }

    /// Create a hosted-transfer draft (spec 1.6). `atoms` is a JS number (u64);
    /// it is sent as a JSON NUMBER, never a string (WW-8 / spec 0.4(5)).
    #[wasm_bindgen(js_name = createTransfer)]
    pub async fn create_transfer(
        &self,
        asset: String,
        sender_aid: String,
        recipient_aid: String,
        atoms: u64,
        fee_mode: String,
    ) -> Result<JsValue, Error> {
        let d = self
            .inner
            .create_transfer(&asset, &sender_aid, &recipient_aid, atoms, &fee_mode)
            .await?;
        Ok(serde_wasm_bindgen::to_value(&d)?)
    }

    /// Complete a hosted transfer with signatures keyed by decimal input index
    /// (spec 1.6). `sigs` is a JS object `{"0":"<128hex>", ...}`. Returns `{txid}`;
    /// a 403 refusal reason and a 404 (expired draft) surface in the error string.
    #[wasm_bindgen(js_name = completeTransfer)]
    pub async fn complete_transfer(&self, id: String, sigs: JsValue) -> Result<JsValue, Error> {
        let sigs: BTreeMap<String, String> = serde_wasm_bindgen::from_value(sigs)?;
        let r = self.inner.complete_transfer(&id, sigs).await?;
        Ok(serde_wasm_bindgen::to_value(&r)?)
    }

    /// Fetch the transparency log.
    pub async fn log(&self) -> Result<JsValue, Error> {
        let v = self.inner.get_log().await?;
        Ok(serde_wasm_bindgen::to_value(&v)?)
    }
}
