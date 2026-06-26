//! Bitcoin parent-chain (testnet4) support for the dual-chain Sequentia kit.
//!
//! Every standard Sequentia wallet is Bitcoin + Sequentia from one seed, sharing
//! the unconfidential address (the SEQ testnet HRP `tb` == Bitcoin testnet `tb`,
//! same BIP84 keychain). This module brings the parent-chain wallet + HTLC leg
//! into the kit so consuming wallets don't each reimplement them.
//!
//! - [`addr`] — the shared `(coin_type, HRP, Bitcoin network)` address model.
//! - [`htlc`] — the BTC-leg HTLC, whose redeemScript delegates to the kit's single
//!   source [`crate::build_htlc_redeem_script`] (byte-identical to the SEQ leg).
//! - [`esplora`] / [`wallet`] — the blocking testnet4 esplora client + wallet
//!   (scan, coin selection, P2WPKH build/sign/broadcast, HTLC funding lookup).
//!
//! Phase 0 ships the blocking transport (Ambra). The async transport (wasm) and
//! the watch-only / `DualChainWallet` split land in later phases.

// `btc-blocking` must never be unified into a wasm build: `reqwest::blocking` is
// absent on wasm32, and additive feature unification could otherwise pull it in.
// Fail loudly rather than emit a broken wasm artifact.
#[cfg(all(feature = "btc-blocking", target_arch = "wasm32"))]
compile_error!(
    "feature `btc-blocking` cannot target wasm32 (reqwest::blocking is unavailable); use `btc-async`"
);

pub mod addr;
pub mod htlc;

#[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]
pub mod esplora;
#[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]
pub mod wallet;
