//! Bitcoin parent-chain (testnet4) wallet — wasm binding.
//!
//! Every standard Sequentia wallet is Bitcoin + Sequentia from one seed; this
//! exposes the kit's async BTC wallet ([`lwk_wollet::btc`]) to the web wallet so
//! `btc.js` can be retired. The unconfidential receive address is shared with the
//! Sequentia side (same BIP84 keychain, same `tb` HRP), so a single address holds
//! on both chains.

use lwk_wollet::btc::{self, addr::ChainAddressParams, BtcPrepared as CoreBtcPrepared, BtcScan as CoreBtcScan};
use wasm_bindgen::prelude::*;

use crate::Error;

fn to_err(e: lwk_wollet::Error) -> Error {
    Error::Generic(e.to_string())
}

/// The result of a gap-limit scan of the Bitcoin keychain.
#[wasm_bindgen]
pub struct BtcScan {
    inner: CoreBtcScan,
}

impl From<CoreBtcScan> for BtcScan {
    fn from(inner: CoreBtcScan) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl BtcScan {
    /// Confirmed + mempool balance, in sats.
    #[wasm_bindgen(getter, js_name = balanceSats)]
    pub fn balance_sats(&self) -> u64 {
        self.inner.balance_sats
    }

    /// Next unused external index (receive normally reuses the shared address).
    #[wasm_bindgen(getter, js_name = externalNext)]
    pub fn external_next(&self) -> u32 {
        self.inner.external_next
    }

    /// Next change index to use for a new transaction.
    #[wasm_bindgen(getter, js_name = changeNext)]
    pub fn change_next(&self) -> u32 {
        self.inner.change_next
    }
}

/// A built, signed (but not yet broadcast) Bitcoin transaction.
#[wasm_bindgen]
pub struct BtcPrepared {
    inner: CoreBtcPrepared,
}

impl From<CoreBtcPrepared> for BtcPrepared {
    fn from(inner: CoreBtcPrepared) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl BtcPrepared {
    /// Raw transaction hex, ready to broadcast.
    #[wasm_bindgen(getter)]
    pub fn hex(&self) -> String {
        self.inner.hex.clone()
    }

    /// The transaction id.
    #[wasm_bindgen(getter)]
    pub fn txid(&self) -> String {
        self.inner.txid.clone()
    }

    /// Fee paid, in sats.
    #[wasm_bindgen(getter, js_name = feeSats)]
    pub fn fee_sats(&self) -> u64 {
        self.inner.fee_sats
    }

    /// Virtual size (vbytes) of the signed transaction.
    #[wasm_bindgen(getter)]
    pub fn vsize(&self) -> u64 {
        self.inner.vsize
    }

    /// Number of inputs selected.
    #[wasm_bindgen(getter)]
    pub fn inputs(&self) -> u32 {
        self.inner.inputs
    }
}

/// The Bitcoin parent-chain (testnet4) wallet served by a same-origin esplora
/// (`/testnet4/api`). Holds no secret: the recovery phrase is passed per signing
/// call (the web wallet keeps it as it does for the Sequentia signer).
#[wasm_bindgen]
pub struct BtcWallet {
    params: ChainAddressParams,
    t4_api: String,
}

#[wasm_bindgen]
impl BtcWallet {
    /// A testnet4 BTC wallet served by `t4_api` (e.g. same-origin `/testnet4/api`).
    #[wasm_bindgen(constructor)]
    pub fn new(t4_api: String) -> BtcWallet {
        BtcWallet { params: ChainAddressParams::testnet(), t4_api }
    }

    /// The `tb1` address at `index` (external/internal). Normal receive reuses the
    /// shared Sequentia address; this is for BTC-specific flows + alignment checks.
    pub fn address(&self, mnemonic: &str, internal: bool, index: u32) -> Result<String, Error> {
        btc::address(&self.params, mnemonic, internal, index).map_err(to_err)
    }

    /// Gap-scan the keychain; returns the testnet4 balance + next indices.
    pub async fn scan(&self, mnemonic: String) -> Result<BtcScan, Error> {
        let params = self.params;
        let base = self.t4_api.clone();
        let s = btc::wallet_async::scan(&params, &mnemonic, &base).await.map_err(to_err)?;
        Ok(s.into())
    }

    /// Build + sign a P2WPKH send (NOT broadcast). `amount` is sats, `feeRate` is
    /// sat/vB; the wallet rescans so the UTXO set + change index are current.
    pub async fn prepare(
        &self,
        mnemonic: String,
        dest: String,
        amount: u64,
        fee_rate: f64,
    ) -> Result<BtcPrepared, Error> {
        let params = self.params;
        let base = self.t4_api.clone();
        let p = btc::wallet_async::prepare(&params, &mnemonic, &base, &dest, amount, fee_rate).await.map_err(to_err)?;
        Ok(p.into())
    }

    /// Broadcast a signed transaction hex to testnet4; returns the txid.
    pub async fn broadcast(&self, tx_hex: String) -> Result<String, Error> {
        let base = self.t4_api.clone();
        btc::wallet_async::broadcast(&base, &tx_hex).await.map_err(to_err)
    }
}
