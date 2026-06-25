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
use crate::elements::{Address, AssetId};
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
    /// Fee asset (display hex). The fee is folded into the funded amount of the
    /// leg carrying this asset (only the `asset_p` leg can be funded by the taker
    /// here — same as the daemon's same-chain path).
    pub fee_asset: AssetId,
    /// Fee amount in satoshi.
    pub fee_amount: u64,
}

impl Wollet {
    /// Build a SeqDEX same-chain SwapRequest (taker half).
    ///
    /// Selects the wallet's `asset_p` UTXOs to fund `amount_p` (plus the fee if
    /// the fee asset is `asset_p`), builds an unsigned/unblinded PSETv2 with a
    /// receive output of `amount_r` `asset_r` to `receive_address` (blinded by
    /// the maker) and an `asset_p` change output (blinded by the taker), and
    /// reveals the selected inputs' blinders.
    ///
    /// Faithful to `daemon/pkg/trade/buy.go::marketOrderRequest` +
    /// `wallet.go::NewSwapTx`.
    pub fn seqdex_swap_request(
        &self,
        opts: &SeqdexSwapRequestOpts,
    ) -> Result<SeqdexSwapRequest, Error> {
        // Amount of asset_p the taker must actually fund: amount_p plus the fee
        // if (and only if) the fee is denominated in asset_p. Mirrors the
        // daemon's `amounts[AssetToSend]` fold in marketOrderRequest.
        let fund_amount = if opts.fee_asset == opts.asset_p {
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

        // Coin-select the taker's asset_p UTXOs (greedy, largest-first) until we
        // cover `fund_amount`. The maker funds the receive leg, so we only fund
        // the send leg here.
        let utxos = self.utxos_map()?;
        let mut candidates: Vec<_> = utxos
            .values()
            .filter(|u| u.unblinded.asset == opts.asset_p)
            .cloned()
            .collect();
        candidates.sort_by(|a, b| b.unblinded.value.cmp(&a.unblinded.value));

        let mut selected_total: u64 = 0;
        let mut n_inputs: u32 = 0;
        let mut unblinded_inputs = Vec::new();
        for utxo in &candidates {
            if selected_total >= fund_amount {
                break;
            }
            // Adds the input with witness_utxo (real confidential prevout, with
            // its commitments and rangeproof), blind asset/value proofs and the
            // in_utxo_rangeproof — exactly what the maker's blinder consumes.
            let idx = self.add_input(
                &mut pset,
                &mut inp_txout_sec,
                &mut inp_weight,
                utxo,
                // add input rangeproofs: gives the maker's stateless blinder the
                // input rangeproof, matching the daemon's AddInUtxoRangeProof.
                true,
            )?;

            let secrets = &utxo.unblinded;
            unblinded_inputs.push(SeqdexUnblindedInput {
                index: idx as u32,
                asset: secrets.asset.to_string(),
                amount: secrets.value,
                // DISPLAY-order hex (see module docs): the elements blinding
                // factor's Display is the byte-reversed (txid-style) form, which
                // is what the daemon expects on the wire.
                asset_blinder: secrets.asset_bf.to_string(),
                amount_blinder: secrets.value_bf.to_string(),
            });

            selected_total = selected_total
                .checked_add(secrets.value)
                .ok_or_else(|| Error::Generic("selected total overflow".into()))?;
            n_inputs += 1;
        }

        if selected_total < fund_amount {
            return Err(Error::InsufficientFunds {
                missing_sats: fund_amount - selected_total,
                asset_id: opts.asset_p,
                is_token: false,
            });
        }
        let change = selected_total - fund_amount;

        // Receive output: amount_r of asset_r to the taker's address. The maker
        // is responsible for blinding it (its input comes after the taker's), so
        // BlinderIndex = number of taker inputs.
        let receive_output = Output {
            script_pubkey: out_script.clone(),
            amount: Some(opts.amount_r),
            asset: Some(opts.asset_r),
            blinding_key: Some(BitcoinPublicKey::new(blinding_pubkey)),
            blinder_index: Some(n_inputs),
            ..Default::default()
        };
        pset.add_output(receive_output);

        // Change output: asset_p change back to the taker, blinded by the taker
        // (BlinderIndex defaults to 0, i.e. against the taker's own inputs).
        if change > 0 {
            let change_output = Output {
                script_pubkey: out_script,
                amount: Some(change),
                asset: Some(opts.asset_p),
                blinding_key: Some(BitcoinPublicKey::new(blinding_pubkey)),
                blinder_index: Some(0),
                ..Default::default()
            };
            pset.add_output(change_output);
        }

        // No fee output and no blinding here: the maker's CompleteSwap selects
        // its own asset_r inputs, adds the network-fee output, blinds (BlindLast)
        // and signs its inputs.
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

/// 8 random bytes as hex (16 chars), matching the daemon's `randstr.Hex(8)`.
fn random_swap_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
