//! Sequentia (SeqDEX / TDEX-fork) same-chain SwapRequest builder.
//!
//! This builds the *taker* (proposer) half of a same-chain atomic swap that the
//! SeqDEX daemon's `ProposeTrade` (seqdex.v1, `/v1/trade/propose`) consumes: an
//! unsigned, unblinded PSETv2 plus the list of `UnblindedInput`s revealing the
//! taker's input blinders so the maker (responder) can balance the confidential
//! transaction with `BlindLast`.
//!
//! This is a faithful Rust port of the Go daemon's taker SDK:
//! `daemon/pkg/trade/buy.go::marketOrderRequest` + `daemon/pkg/trade/wallet.go::NewSwapTx`,
//! and the wire shape in `daemon/pkg/swap/request.go`.
//!
//! ## Blinder byte order — the critical correctness detail
//!
//! The daemon hit `bad-txns-in-ne-out` from a blinder byte-order flip (fixed in
//! commit b9f63c8). The net effect of the daemon's code is that the wire
//! `asset_blinder` / `amount_blinder` of each `UnblindedInput` are the Elements
//! node's `listunspent` `assetblinder` / `amountblinder` hex **verbatim** —
//! i.e. transaction-id-style *display* order, which is **byte-reversed** relative
//! to the secp256k1 internal little-endian representation. In go-elements the
//! explorer reverses node-hex → internal-LE and then `utxosToUnblindedIns`
//! reverses internal-LE → display-hex via `elementsutil.TxIDFromBytes`, so the
//! two reversals cancel and the wire carries display-order hex.
//!
//! In the Rust `elements` crate the blinding factor's `Display`/`to_string()`
//! (and serde human-readable form) is exactly this **display / big-endian** hex
//! (`hex::format_hex_reverse` over the internal bytes), while `.into_inner().
//! serialize()` / `to_bytes()` is the internal little-endian order. So the wire
//! hex is produced with `to_string()`, NOT the raw bytes. Using the raw bytes
//! would reproduce the b9f63c8 bug.

use std::collections::HashMap;

use crate::bitcoin::PublicKey as BitcoinPublicKey;
use crate::elements::pset::{Output, PartiallySignedTransaction};
use crate::elements::{Address, AssetId, Script};
use crate::error::Error;
use crate::wollet::Wollet;
use lwk_common::set_genesis_hash;

/// One revealed taker input of a [`SeqdexSwapRequest`].
///
/// Mirrors `daemon/pkg/swap` `UnblindedInput` and the `seqdex.v1.UnblindedInput`
/// proto. `asset` is display-hex asset id; `asset_blinder` / `amount_blinder`
/// are display-order (txid-style) hex — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqdexUnblindedInput {
    /// Index of the input in the PSET.
    pub index: u32,
    /// Unblinded asset id, display hex.
    pub asset: String,
    /// Unblinded amount in satoshi.
    pub amount: u64,
    /// Asset blinder, display-order hex (byte-reversed vs internal LE).
    pub asset_blinder: String,
    /// Amount (value) blinder, display-order hex (byte-reversed vs internal LE).
    pub amount_blinder: String,
}

/// The taker half of a SeqDEX same-chain swap, ready to be sent to the daemon's
/// `ProposeTrade` as a `SwapRequest`.
#[derive(Debug, Clone)]
pub struct SeqdexSwapRequest {
    /// Random swap id (8 bytes hex = 16 hex chars), matching `randstr.Hex(8)`.
    pub id: String,
    /// Proposer's amount (the amount of `asset_p` the taker sends, fee-exclusive).
    pub amount_p: u64,
    /// Proposer's asset (display hex) — what the taker sends.
    pub asset_p: String,
    /// Responder's amount (the amount of `asset_r` the taker receives).
    pub amount_r: u64,
    /// Responder's asset (display hex) — what the taker receives.
    pub asset_r: String,
    /// The unsigned, unblinded PSETv2, base64.
    pub transaction: String,
    /// The taker's revealed input blinders.
    pub unblinded_inputs: Vec<SeqdexUnblindedInput>,
}

/// Options for [`Wollet::seqdex_swap_request`].
#[derive(Debug, Clone)]
pub struct SeqdexSwapRequestOpts {
    /// Asset the taker sends (display hex).
    pub asset_p: AssetId,
    /// Amount of `asset_p` the taker sends (fee-exclusive, the `amount_p` on the wire).
    pub amount_p: u64,
    /// Asset the taker receives (display hex).
    pub asset_r: AssetId,
    /// Amount of `asset_r` the taker receives (the `amount_r` on the wire).
    pub amount_r: u64,
    /// The taker's own confidential address that receives `asset_r` and the change.
    pub receive_address: Address,
    /// Fee asset (display hex) — the asset the taker funds the on-chain network
    /// fee in (open fee market). May be `asset_p` or any other held, fee-eligible
    /// asset, but NOT `asset_r` (a fee output in the received asset would inflate
    /// the `amount_r` the maker validates). When `fee_amount == 0` the taker funds
    /// nothing and the maker funds the fee in `asset_r` (the legacy default path).
    pub fee_asset: AssetId,
    /// Fee amount, in atoms of `fee_asset`. `0` ⇒ maker-funded (default); `> 0` ⇒
    /// the taker funds the fee itself, adding a `fee_asset` input + an explicit
    /// fee output (+ blinded `fee_asset` change) to the swap.
    pub fee_amount: u64,
    /// `fee_asset`'s open-fee-market rate: atoms of `fee_asset` per
    /// `exchange_rate_scale` (1e8) native atoms, as published by the node. Used
    /// only to compute the `fee_asset` dust threshold so a sub-dust change is
    /// folded into the fee output rather than emitted (and rejected by node
    /// policy). `0` is treated as native (1:1). Ignored when `fee_amount == 0`.
    pub fee_rate: u64,
}

impl Wollet {
    /// Build a SeqDEX same-chain SwapRequest (taker half).
    ///
    /// Selects the wallet's `asset_p` UTXOs to fund `amount_p`, builds an
    /// unsigned/unblinded PSETv2 with a receive output of `amount_r` `asset_r` to
    /// `receive_address` (blinded by the maker) and an `asset_p` change output
    /// (blinded by the taker), and reveals the selected inputs' blinders.
    ///
    /// Open fee market — the taker may fund the on-chain network fee in ANY held,
    /// fee-eligible asset (the user picks; default = the asset being sent), not
    /// just a swap leg. When `opts.fee_amount > 0`:
    ///   * if `fee_asset == asset_p`, the single `asset_p` selection funds both
    ///     the send leg and the fee, and an explicit `asset_p` fee output is added;
    ///   * otherwise (`fee_asset` is a third asset) a SECOND coin-selection over
    ///     `fee_asset` UTXOs is added BEFORE the receive output (so the receive
    ///     output's blinder index still equals the total taker input count and
    ///     thus points at the maker's first input), plus a blinded `fee_asset`
    ///     change and an explicit `fee_asset` fee output.
    /// A fee in `asset_r` is rejected (it would inflate the `amount_r` the maker
    /// validates). When `fee_amount == 0`, the function emits NO fee output and
    /// the maker funds the fee in `asset_r` (the legacy default), byte-for-byte
    /// as before.
    ///
    /// The explicit fee output is empty-script + unblinded (an Elements `IsFee`
    /// output) so the maker's last-blinder skips it; the maker (CompleteSwap)
    /// detects this taker-supplied fee output, validates its native-equivalent
    /// value, and does not add its own.
    ///
    /// Faithful to `daemon/pkg/trade/buy.go::marketOrderRequest` +
    /// `wallet.go::NewSwapTx`.
    pub fn seqdex_swap_request(
        &self,
        opts: &SeqdexSwapRequestOpts,
    ) -> Result<SeqdexSwapRequest, Error> {
        // A fee in the RECEIVED asset is not representable here: the explicit fee
        // output would add to the asset_r sum the maker/validator compares to
        // amount_r. "Fee in the received asset" is exactly the maker-funded
        // default, reached with fee_amount == 0.
        if opts.fee_amount > 0 && opts.fee_asset == opts.asset_r {
            return Err(Error::Generic(
                "swap fee cannot be paid in the received asset; \
                 use the maker-funded default (fee_amount = 0) or pick another asset"
                    .into(),
            ));
        }
        let taker_funds_fee = opts.fee_amount > 0;
        let fee_in_asset_p = taker_funds_fee && opts.fee_asset == opts.asset_p;

        // asset_p the taker must fund: amount_p, plus the fee when (and only when)
        // the fee is denominated in asset_p (one selection covers both).
        let fund_amount = if fee_in_asset_p {
            opts.amount_p
                .checked_add(opts.fee_amount)
                .ok_or_else(|| Error::Generic("amount_p + fee_amount overflow".into()))?
        } else {
            opts.amount_p
        };

        // The receive address must be confidential — the maker blinds the
        // receive output to its blinding pubkey, and the change goes there too.
        let blinding_pubkey = opts
            .receive_address
            .blinding_pubkey
            .ok_or(Error::NotConfidentialAddress)?;
        let out_script = opts.receive_address.script_pubkey();

        // Init the PSETv2 with the network genesis hash, like TxBuilder::finish.
        let mut pset = PartiallySignedTransaction::new_v2();
        set_genesis_hash(&mut pset, &self.network());

        let mut inp_txout_sec = HashMap::new();
        let mut inp_weight = 0usize;
        let mut n_inputs: u32 = 0;
        let mut unblinded_inputs = Vec::new();

        let utxos = self.utxos_map()?;

        // Greedy largest-first coin-selection of `asset`'s UTXOs covering
        // `target`. Adds each as an input (with the real confidential prevout +
        // input rangeproof the maker's stateless blinder consumes), reveals its
        // blinders in DISPLAY-order hex (see module docs; raw bytes would
        // reproduce the b9f63c8 bad-txns-in-ne-out bug), and bumps `n_inputs`.
        // Returns the total selected; the caller checks it covers `target`.
        let select = |pset: &mut PartiallySignedTransaction,
                          inp_txout_sec: &mut HashMap<usize, crate::elements::TxOutSecrets>,
                          inp_weight: &mut usize,
                          n_inputs: &mut u32,
                          unblinded_inputs: &mut Vec<SeqdexUnblindedInput>,
                          asset: AssetId,
                          target: u64|
         -> Result<u64, Error> {
            let mut candidates: Vec<_> = utxos
                .values()
                .filter(|u| u.unblinded.asset == asset)
                .cloned()
                .collect();
            candidates.sort_by(|a, b| b.unblinded.value.cmp(&a.unblinded.value));

            let mut selected: u64 = 0;
            for utxo in &candidates {
                if selected >= target {
                    break;
                }
                let idx = self.add_input(pset, inp_txout_sec, inp_weight, utxo, true)?;
                let secrets = &utxo.unblinded;
                unblinded_inputs.push(SeqdexUnblindedInput {
                    index: idx as u32,
                    asset: secrets.asset.to_string(),
                    amount: secrets.value,
                    asset_blinder: secrets.asset_bf.to_string(),
                    amount_blinder: secrets.value_bf.to_string(),
                });
                selected = selected
                    .checked_add(secrets.value)
                    .ok_or_else(|| Error::Generic("selected total overflow".into()))?;
                *n_inputs += 1;
            }
            Ok(selected)
        };

        // Fund the send leg (asset_p), plus the fee when it's in asset_p.
        let selected_p = select(
            &mut pset,
            &mut inp_txout_sec,
            &mut inp_weight,
            &mut n_inputs,
            &mut unblinded_inputs,
            opts.asset_p,
            fund_amount,
        )?;
        if selected_p < fund_amount {
            return Err(Error::InsufficientFunds {
                missing_sats: fund_amount - selected_p,
                asset_id: opts.asset_p,
                is_token: false,
            });
        }
        let asset_p_change = selected_p - fund_amount;

        // Fund the fee in a THIRD asset, if any. Done BEFORE the receive output so
        // the receive output's blinder index counts all taker inputs.
        let mut fee_selected: u64 = 0;
        if taker_funds_fee && !fee_in_asset_p {
            fee_selected = select(
                &mut pset,
                &mut inp_txout_sec,
                &mut inp_weight,
                &mut n_inputs,
                &mut unblinded_inputs,
                opts.fee_asset,
                opts.fee_amount,
            )?;
            if fee_selected < opts.fee_amount {
                return Err(Error::InsufficientFunds {
                    missing_sats: opts.fee_amount - fee_selected,
                    asset_id: opts.fee_asset,
                    is_token: false,
                });
            }
        }

        // Receive output: amount_r of asset_r to the taker's address. The maker
        // is responsible for blinding it (its input comes after every taker
        // input), so BlinderIndex = total taker input count.
        let receive_output = Output {
            script_pubkey: out_script.clone(),
            amount: Some(opts.amount_r),
            asset: Some(opts.asset_r),
            blinding_key: Some(BitcoinPublicKey::new(blinding_pubkey)),
            blinder_index: Some(n_inputs),
            ..Default::default()
        };
        pset.add_output(receive_output);

        // A blinded change output back to the taker. BlinderIndex 0 (the taker's
        // first, always-revealed input); the maker blinds it via the revealed
        // unblinded_inputs.
        let add_change = |pset: &mut PartiallySignedTransaction, amount: u64, asset: AssetId| {
            pset.add_output(Output {
                script_pubkey: out_script.clone(),
                amount: Some(amount),
                asset: Some(asset),
                blinding_key: Some(BitcoinPublicKey::new(blinding_pubkey)),
                blinder_index: Some(0),
                ..Default::default()
            });
        };

        // The explicit (unblinded, empty-script) Elements fee output value. A
        // sub-dust fee-asset change is folded in (overpay) below rather than
        // emitted as a change the node would reject by dust policy.
        let mut fee_out_amount = opts.fee_amount;

        if fee_in_asset_p {
            // One asset: the asset_p selection covers amount_p + fee. Both the
            // change and the fee output are asset_p.
            let dust = dust_threshold(opts.fee_rate);
            if asset_p_change as u128 > dust as u128 {
                add_change(&mut pset, asset_p_change, opts.asset_p);
            } else {
                fee_out_amount += asset_p_change;
            }
            pset.add_output(Output::new_explicit(
                Script::default(),
                fee_out_amount,
                opts.fee_asset,
                None,
            ));
        } else {
            // asset_p change, blinded by the taker — unchanged from the default.
            if asset_p_change > 0 {
                add_change(&mut pset, asset_p_change, opts.asset_p);
            }
            if taker_funds_fee {
                // Third-asset fee: a blinded fee_asset change + explicit fee out.
                let fee_change = fee_selected - opts.fee_amount;
                let dust = dust_threshold(opts.fee_rate);
                if fee_change as u128 > dust as u128 {
                    add_change(&mut pset, fee_change, opts.fee_asset);
                } else {
                    fee_out_amount += fee_change;
                }
                pset.add_output(Output::new_explicit(
                    Script::default(),
                    fee_out_amount,
                    opts.fee_asset,
                    None,
                ));
            }
        }

        // When taker_funds_fee is false there is NO fee output: the maker's
        // CompleteSwap selects its own asset_r inputs, adds the native-equivalent
        // fee output in asset_r, blinds (BlindLast) and signs its inputs.
        //
        // NB: we deliberately do NOT add bip32 derivations / key origins to the
        // request PSET. The Go daemon parses it with go-elements' psetv2, which
        // rejects the extra elements-rs global-xpub / input-bip32 fields with
        // "invalid swap request transaction". Instead the taker, on receiving the
        // SwapAccept, injects those derivations locally (`Wollet::add_details` on
        // the accept PSET) just before signing, then strips them again before
        // returning the signed PSET to the daemon — they never go on the wire.
        // This matches the Go taker, whose NewSwapTx likewise emits a bare PSET
        // and whose Wallet.Sign signs by matching the witness script directly.

        let transaction = pset.to_string();

        let id = random_swap_id();

        Ok(SeqdexSwapRequest {
            id,
            amount_p: opts.amount_p,
            asset_p: opts.asset_p.to_string(),
            amount_r: opts.amount_r,
            asset_r: opts.asset_r.to_string(),
            transaction,
            unblinded_inputs,
        })
    }
}

/// The `fee_asset` dust threshold, mirroring the node's
/// `ConvertValueToAmount(294, asset)` = `ceil(294 * exchange_rate_scale / rate)`.
/// A confidential change at/below this is rejected by node dust policy, so the
/// builder folds it into the (explicit) fee output instead. `rate == 0` is the
/// native asset (1:1), giving the native 294-atom dust.
fn dust_threshold(rate: u64) -> u64 {
    convert_value_to_amount(294, rate)
}

/// The node's fee-market conversion `ExchangeRateMap::ConvertValueToAmount`:
/// atoms of an asset whose published rate is `rate` (atoms per 1e8 native) that
/// carry `value` native atoms of fee value — `ceil(value * 1e8 / rate)`.
///
/// `rate == 0` is treated as the native asset (1:1), which is correct for the
/// dust threshold (the native asset legitimately values 1:1). CAUTION: for a
/// NON-native asset, `rate == 0` means "not fee-accepted by producers" — callers
/// that must distinguish that (e.g. the cross-chain SEQ-claim fee) MUST check
/// `rate != 0` themselves rather than relying on the 1:1 fallback here.
pub(crate) fn convert_value_to_amount(value: u64, rate: u64) -> u64 {
    const SCALE: u128 = 100_000_000;
    if rate == 0 {
        return value; // native 1:1
    }
    ((value as u128 * SCALE + rate as u128 - 1) / rate as u128) as u64
}

/// 8 random bytes as hex (16 chars), matching the daemon's `randstr.Hex(8)`.
fn random_swap_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
