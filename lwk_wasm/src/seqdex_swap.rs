//! Sequentia (SeqDEX / TDEX-fork) same-chain SwapRequest builder — wasm binding.
//!
//! Exposes [`TxBuilder::swapRequest`]-style construction of the *taker* half of a
//! same-chain atomic swap that the SeqDEX daemon's `ProposeTrade`
//! (seqdex.v1, `POST /v1/trade/propose`) consumes.
//!
//! The output is an unsigned, unblinded PSETv2 (base64) plus the
//! `unblinded_inputs` list revealing the taker's input blinders, exactly as the
//! daemon's `SwapRequest` proto requires:
//! `{ id, amount_p, asset_p, amount_r, asset_r, transaction, unblinded_inputs[] }`
//! with each `UnblindedInput { index, asset, amount, asset_blinder, amount_blinder }`.
//!
//! Blinder byte order (the decisive correctness detail) is handled in
//! `lwk_wollet::seqdex_swap`: the wire `asset_blinder`/`amount_blinder` are
//! emitted as display-order (txid-style) hex, matching the Elements node's
//! `listunspent` output and the daemon's expectation. See that module's docs.
//!
//! Completing the swap needs no new binding: the taker signs the returned
//! `SwapAccept` PSET with the existing `Signer.sign(pset)`, then the daemon
//! finalizes + broadcasts it via `CompleteTrade`.

use lwk_wollet::SeqdexSwapRequestOpts;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::{Address, AssetId, Error, Wollet};

/// The taker half of a SeqDEX same-chain swap, ready to POST to the daemon's
/// `/v1/trade/propose` as a `SwapRequest`.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct SwapRequest {
    inner: lwk_wollet::SeqdexSwapRequest,
}

impl From<lwk_wollet::SeqdexSwapRequest> for SwapRequest {
    fn from(inner: lwk_wollet::SeqdexSwapRequest) -> Self {
        Self { inner }
    }
}

/// Serde shape of a single revealed input, matching the `seqdex.v1.UnblindedInput`
/// proto field names (camelCase isn't needed since the proto JSON uses snake_case
/// for these fields via grpc-gateway).
#[derive(Serialize)]
struct UnblindedInputJson {
    index: u32,
    asset: String,
    amount: u64,
    asset_blinder: String,
    amount_blinder: String,
}

#[wasm_bindgen]
impl SwapRequest {
    /// The random swap id (16 hex chars), matching the daemon's `randstr.Hex(8)`.
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// Proposer's amount: the amount of `assetP` the taker sends (fee-exclusive).
    #[wasm_bindgen(js_name = amountP)]
    pub fn amount_p(&self) -> u64 {
        self.inner.amount_p
    }

    /// Proposer's asset (display hex): what the taker sends.
    #[wasm_bindgen(js_name = assetP)]
    pub fn asset_p(&self) -> String {
        self.inner.asset_p.clone()
    }

    /// Responder's amount: the amount of `assetR` the taker receives.
    #[wasm_bindgen(js_name = amountR)]
    pub fn amount_r(&self) -> u64 {
        self.inner.amount_r
    }

    /// Responder's asset (display hex): what the taker receives.
    #[wasm_bindgen(js_name = assetR)]
    pub fn asset_r(&self) -> String {
        self.inner.asset_r.clone()
    }

    /// The unsigned, unblinded PSETv2 (base64).
    pub fn transaction(&self) -> String {
        self.inner.transaction.clone()
    }

    /// The taker's revealed input blinders as a JS array of
    /// `{ index, asset, amount, asset_blinder, amount_blinder }`.
    #[wasm_bindgen(js_name = unblindedInputs)]
    pub fn unblinded_inputs(&self) -> Result<JsValue, Error> {
        let list: Vec<UnblindedInputJson> = self
            .inner
            .unblinded_inputs
            .iter()
            .map(|u| UnblindedInputJson {
                index: u.index,
                asset: u.asset.clone(),
                amount: u.amount,
                asset_blinder: u.asset_blinder.clone(),
                amount_blinder: u.amount_blinder.clone(),
            })
            .collect();
        Ok(serde_wasm_bindgen::to_value(&list)?)
    }

    /// The whole SwapRequest as a single JS object matching the daemon's
    /// `seqdex.v1.SwapRequest` JSON shape (amounts are JS_STRING in the proto,
    /// so they are emitted as strings here for the grpc-gateway).
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<JsValue, Error> {
        #[derive(Serialize)]
        struct SwapRequestJson {
            id: String,
            // JS_STRING-typed uint64 fields are string-encoded over the gateway.
            amount_p: String,
            asset_p: String,
            amount_r: String,
            asset_r: String,
            transaction: String,
            unblinded_inputs: Vec<UnblindedInputJson>,
        }
        let json = SwapRequestJson {
            id: self.inner.id.clone(),
            amount_p: self.inner.amount_p.to_string(),
            asset_p: self.inner.asset_p.clone(),
            amount_r: self.inner.amount_r.to_string(),
            asset_r: self.inner.asset_r.clone(),
            transaction: self.inner.transaction.clone(),
            unblinded_inputs: self
                .inner
                .unblinded_inputs
                .iter()
                .map(|u| UnblindedInputJson {
                    index: u.index,
                    asset: u.asset.clone(),
                    amount: u.amount,
                    asset_blinder: u.asset_blinder.clone(),
                    amount_blinder: u.amount_blinder.clone(),
                })
                .collect(),
        };
        Ok(serde_wasm_bindgen::to_value(&json)?)
    }
}

#[wasm_bindgen]
impl Wollet {
    /// Build a SeqDEX same-chain SwapRequest (the taker / proposer half).
    ///
    /// - `asset_p` / `amount_p`: the asset and amount the taker sends (fee-exclusive).
    /// - `asset_r` / `amount_r`: the asset and amount the taker receives.
    /// - `receive_address`: the taker's own confidential address that receives
    ///   `asset_r` and any `asset_p` change.
    /// - `fee_asset` / `fee_amount`: the fee; folded into the funded `asset_p`
    ///   amount when `fee_asset == asset_p`.
    ///
    /// Returns a [`SwapRequest`] carrying the unsigned/unblinded PSETv2 + the
    /// revealed `unblinded_inputs`. POST it to the daemon's `ProposeTrade`
    /// (`/v1/trade/propose`). To complete: the daemon returns a SwapAccept whose
    /// PSET contains the taker's input but, being a bare PSET, no bip32
    /// derivation — so before `Signer.sign` works on it, re-attach the taker
    /// input's keypath locally with `Wollet.psetDetails`/`add_details` (the lwk
    /// signer signs via the PSET bip32 derivation). After signing, the extra
    /// bip32/global-xpub fields must be removed again (the daemon's go-elements
    /// parser rejects them) before POSTing to `CompleteTrade`
    /// (`/v1/trade/complete`); the partial signature itself is preserved.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = seqdexSwapRequest)]
    pub fn seqdex_swap_request(
        &self,
        asset_p: &AssetId,
        amount_p: u64,
        asset_r: &AssetId,
        amount_r: u64,
        receive_address: &Address,
        fee_asset: &AssetId,
        fee_amount: u64,
    ) -> Result<SwapRequest, Error> {
        let opts = SeqdexSwapRequestOpts {
            asset_p: (*asset_p).into(),
            amount_p,
            asset_r: (*asset_r).into(),
            amount_r,
            receive_address: receive_address.into(),
            fee_asset: (*fee_asset).into(),
            fee_amount,
        };
        Ok(self.inner().seqdex_swap_request(&opts)?.into())
    }
}
