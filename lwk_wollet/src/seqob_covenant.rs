//! Sequentia SeqOB passive-CLOB covenant — the raw-Elements FILL transaction
//! assembler the browser taker needs.
//!
//! This is the one terminal piece the web wallet could not build from JS. The
//! covenant scriptPubKey, the FILL `[leaf, control_block]` witness, and the fill
//! recipe (`planFill`) are all produced, and byte-verified, by the wallet's pure
//! JS (`covenant.js` / `covenant-order.js`), which is itself pinned byte-for-byte
//! to the Go production module (`seqdex/daemon/pkg/covenant`) and the
//! regtest-proven Python builders (`test/functional/seqob_covenant.py`, exercised
//! by `feature_seqob_covenant_fill.py`). What JS cannot do is assemble the raw
//! Elements transaction that carries that witness: a taproot **script-path**
//! covenant input (custom final witness, NO key signature) at index 0, plus the
//! taker's own **key-path** (p2wpkh) funding inputs signed from the wallet seed,
//! plus the explicit (unblinded) maker-credit / remainder / receipt / change / fee
//! outputs in the consensus-fixed order. This module builds exactly that.
//!
//! ## The FILL transaction layout (single taker fill, covenant input index k=0)
//!
//! The FILL leaf reads everything it enforces from transaction introspection and
//! binds the covenant input at consensus index `k` to output `2k` (the maker
//! credit) and output `2k+1` (the remainder slot). For a single taker fill k=0:
//!
//! ```text
//!   input  0 : the resting covenant UTXO (asset A, explicit)         witness = [FILL_leaf, control_block]  (NO sig)
//!   input  1.: the taker's own asset-B (and fee-asset) funding UTXOs  p2wpkh, key-path signed from the seed
//!
//!   output 0 : maker credit   — asset B, value >= ceil price, spk = OP_1 <maker_prog>   (2k)
//!   output 1 : PARTIAL  -> remainder covenant (asset A, self-replicating spk, >= min_lot)  (2k+1)
//!              FULL     -> a non-asset-A "gap" output (taker change / fee). The leaf
//!                          inspects 2k+1: only an asset-A output there is read as an
//!                          underpaid remainder, so a full fill MUST place a non-A
//!                          explicit output at slot 1 (matches feature_seqob_covenant_fill.py).
//!   output 2.: the taker's asset-A receipt (the filled coins), then any remaining
//!              change outputs, then the explicit Elements fee output (empty spk).
//! ```
//!
//! This reproduces, byte-for-byte, the output ordering the regtest FILL scenarios
//! use: PARTIAL `[credit, remainder(A), receipt(A), B-change, …, fee]`, and FULL
//! `[credit, B-change(non-A gap), receipt(A), …, fee]`.
//!
//! ## Explicit-only
//!
//! Every output is EXPLICIT (unconfidential). The covenant rejects a blinded
//! credit it cannot introspect, and an all-explicit transaction keeps the value
//! balance trivially checkable, so the taker funds from explicit (transparent,
//! Sequentia-default) asset-B coins. Passing a confidential receive/change address
//! is tolerated — only its scriptPubKey is used and the output is emitted explicit.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::{hash160, Hash};
use elements::hex::{FromHex, ToHex};
use elements::script::Builder;
use elements::{
    confidential, opcodes, Address, AssetId, EcdsaSighashType, LockTime, OutPoint, Script,
    Sequence, Transaction, TxIn, TxInWitness, TxOut, Txid,
};

use crate::bitcoin::secp256k1::{self, Message, Secp256k1, SecretKey};
use crate::error::Error;

/// SIGHASH_ALL, appended to the DER signature of each taker (p2wpkh) input.
const SIGHASH_ALL_BYTE: u8 = 0x01;

/// The resting covenant UTXO being filled — the taproot script-path input at
/// index 0. `asset`/`locked` are the (explicit) asset id and value the maker
/// locked; `fill_leaf` + `control_block` are the introspection-only witness the
/// wallet already derived (`covenant.js` `planFill`).
#[derive(Debug, Clone)]
pub struct CovenantInput {
    /// Funding txid of the covenant UTXO (display/big-endian hex).
    pub txid: String,
    /// Funding vout of the covenant UTXO.
    pub vout: u32,
    /// The covenant's locked asset (asset A), display hex.
    pub asset: AssetId,
    /// The covenant's locked value (atoms of asset A).
    pub locked: u64,
    /// FILL leaf script bytes (witness item 0).
    pub fill_leaf: Vec<u8>,
    /// FILL control block bytes (witness item 1).
    pub control_block: Vec<u8>,
}

/// The maker credit forced at output 0: asset B paid to the maker's v1-taproot
/// payout (`maker_prog`). `value` is the covenant's ceil price (`required_B`); the
/// covenant enforces the emitted value is `>= value`.
#[derive(Debug, Clone)]
pub struct FillCredit {
    /// Asset the maker is paid (asset B), display hex.
    pub asset: AssetId,
    /// The 32-byte v1-taproot maker payout program.
    pub program: Vec<u8>,
    /// Witness version of the maker payout (1 for the pinned v1 taproot payout).
    pub version: u8,
    /// Atoms of asset B credited to the maker (ceil price).
    pub value: u64,
}

/// The self-replicating remainder forced at output 1 on a PARTIAL fill: asset A
/// re-paid to the SAME covenant scriptPubKey (`spk`), value `>= min_lot`.
#[derive(Debug, Clone)]
pub struct FillRemainder {
    /// Asset re-paid to the covenant (asset A), display hex.
    pub asset: AssetId,
    /// Atoms of asset A re-paid to the covenant.
    pub value: u64,
    /// The covenant scriptPubKey (== the funded UTXO's spk); self-replication.
    pub spk: Vec<u8>,
}

/// One taker-owned funding UTXO (asset B, and/or the fee asset), spent key-path.
///
/// These are the wallet's own coins; the covenant tx signs them from the seed.
/// `chain` (0 external / 1 internal) + `index` are the wallet derivation
/// coordinates (BIP84 `m/84'/coin'/0'/chain/index`), as reported by the wollet's
/// UTXO list (`wildcardIndex` / `extInt`). `spk` MUST be the input's p2wpkh
/// scriptPubKey and is re-derived-and-checked against the signing key.
#[derive(Debug, Clone)]
pub struct TakerFundingInput {
    /// Funding txid (display/big-endian hex).
    pub txid: String,
    /// Funding vout.
    pub vout: u32,
    /// Explicit value of the UTXO, in atoms.
    pub value: u64,
    /// Explicit asset id of the UTXO, display hex.
    pub asset: AssetId,
    /// The input's p2wpkh scriptPubKey (`0014<pkh>`).
    pub spk: Vec<u8>,
    /// The secp256k1 secret key controlling this UTXO (derived from the seed).
    pub secret_key: SecretKey,
}

/// The full FILL recipe the taker assembles + broadcasts.
#[derive(Debug, Clone)]
pub struct CovenantFillPlan {
    /// The resting covenant UTXO (input 0).
    pub covenant: CovenantInput,
    /// Output 0: the maker credit.
    pub credit: FillCredit,
    /// Output 1 on a partial fill: the self-replicating remainder covenant.
    /// `None` for a full fill (a non-A gap output is placed at slot 1 instead).
    pub remainder: Option<FillRemainder>,
    /// The taker's funding UTXOs (asset B, and the fee asset if distinct).
    pub taker_inputs: Vec<TakerFundingInput>,
    /// Where the taker's asset-A receipt (the filled coins) is paid.
    pub receipt_addr: Address,
    /// Where the taker's change (per funded asset) is paid.
    pub change_addr: Address,
    /// The on-chain network fee, in atoms of `fee_asset`.
    pub fee_atoms: u64,
    /// The asset the fee is denominated in (open fee market).
    pub fee_asset: AssetId,
}

/// Build one explicit (unconfidential) Elements output.
fn explicit_out(asset: AssetId, value: u64, spk: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey: spk,
        witness: Default::default(),
    }
}

/// The maker credit scriptPubKey `OP_<version> <program>` (a witness program).
/// For the pinned v1 taproot payout this is `OP_1 <32-byte prog>` = `5120<prog>`.
fn witness_program_spk(version: u8, program: &[u8]) -> Result<Script, Error> {
    if version > 16 {
        return Err(Error::Generic(format!(
            "witness version {version} out of range (0..=16)"
        )));
    }
    if program.len() < 2 || program.len() > 40 {
        return Err(Error::Generic(format!(
            "witness program must be 2..=40 bytes, got {}",
            program.len()
        )));
    }
    // OP_0 is 0x00; OP_1..OP_16 are 0x51..0x60 (i.e. 0x50 + version).
    let op = if version == 0 { 0x00 } else { 0x50 + version };
    let mut bytes = Vec::with_capacity(2 + program.len());
    bytes.push(op);
    bytes.push(program.len() as u8);
    bytes.extend_from_slice(program);
    Ok(Script::from(bytes))
}

/// The p2wpkh scriptCode `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`,
/// used as the BIP143 script_code for the segwit-v0 sighash.
fn p2wpkh_script_code(pkh: &[u8; 20]) -> Script {
    Builder::new()
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(pkh)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

/// The p2wpkh scriptPubKey `OP_0 <pkh>` = `0014<pkh>`.
fn p2wpkh_spk(pkh: &[u8; 20]) -> Vec<u8> {
    let mut v = Vec::with_capacity(22);
    v.push(0x00);
    v.push(0x14);
    v.extend_from_slice(pkh);
    v
}

/// Assemble, sign, and serialize the raw Elements FILL transaction.
///
/// Returns `(raw_tx_hex, txid)`. The covenant input at index 0 carries the
/// introspection-only `[leaf, control_block]` witness (no signature); every taker
/// funding input is signed key-path (p2wpkh, segwit-v0 SIGHASH_ALL) from its
/// secret key. Outputs are placed in the consensus-fixed order (credit at 0,
/// remainder/gap at 1) and are all explicit.
pub fn build_covenant_fill_tx(plan: &CovenantFillPlan) -> Result<(String, Txid), Error> {
    let a_asset = plan.covenant.asset;

    // ---- inputs -----------------------------------------------------------
    let cov_txid = Txid::from_str(&plan.covenant.txid)
        .map_err(|e| Error::Generic(format!("invalid covenant txid {}: {e}", plan.covenant.txid)))?;
    let cov_input = TxIn {
        previous_output: OutPoint::new(cov_txid, plan.covenant.vout),
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: Default::default(),
        witness: TxInWitness::default(),
    };
    let mut inputs = vec![cov_input];
    for ti in &plan.taker_inputs {
        let txid = Txid::from_str(&ti.txid)
            .map_err(|e| Error::Generic(format!("invalid taker input txid {}: {e}", ti.txid)))?;
        inputs.push(TxIn {
            previous_output: OutPoint::new(txid, ti.vout),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        });
    }

    // ---- taker funding accounting (per asset) -----------------------------
    let mut funded: BTreeMap<AssetId, u64> = BTreeMap::new();
    for ti in &plan.taker_inputs {
        // Reject a confidential/non-p2wpkh funding input up front: this builder
        // signs only key-path p2wpkh coins and emits an all-explicit tx.
        if ti.spk.len() != 22 || ti.spk[0] != 0x00 || ti.spk[1] != 0x14 {
            return Err(Error::Generic(format!(
                "taker funding input {}:{} is not p2wpkh (spk {})",
                ti.txid,
                ti.vout,
                ti.spk.to_hex()
            )));
        }
        let e = funded.entry(ti.asset).or_insert(0);
        *e = e
            .checked_add(ti.value)
            .ok_or_else(|| Error::Generic("taker funding overflow".into()))?;
    }

    // Amount of each funded asset consumed by the fixed outputs: the maker credit
    // (asset B) and the explicit fee output (fee asset). The taker funds no asset
    // A — asset A comes entirely from the covenant input (filled + remainder).
    let mut consumed: BTreeMap<AssetId, u64> = BTreeMap::new();
    *consumed.entry(plan.credit.asset).or_insert(0) = consumed
        .get(&plan.credit.asset)
        .copied()
        .unwrap_or(0)
        .checked_add(plan.credit.value)
        .ok_or_else(|| Error::Generic("credit value overflow".into()))?;
    *consumed.entry(plan.fee_asset).or_insert(0) = consumed
        .get(&plan.fee_asset)
        .copied()
        .unwrap_or(0)
        .checked_add(plan.fee_atoms)
        .ok_or_else(|| Error::Generic("fee value overflow".into()))?;

    // The taker must not be funding asset A (the sold asset comes from the
    // covenant); an asset-A funding input would double-count the receipt.
    if funded.contains_key(&a_asset) {
        return Err(Error::Generic(
            "taker must not fund the covenant's sold asset (asset A comes from the covenant input)"
                .into(),
        ));
    }

    // ---- fixed outputs ----------------------------------------------------
    let credit_spk = witness_program_spk(plan.credit.version, &plan.credit.program)?;
    let credit_out = explicit_out(plan.credit.asset, plan.credit.value, credit_spk);

    // filled = locked - remainder (0 for a full fill).
    let remainder_value = plan.remainder.as_ref().map(|r| r.value).unwrap_or(0);
    let filled = plan
        .covenant
        .locked
        .checked_sub(remainder_value)
        .ok_or_else(|| Error::Generic("remainder exceeds locked value".into()))?;
    if filled == 0 {
        return Err(Error::Generic("filled amount is zero".into()));
    }
    let receipt_out = explicit_out(a_asset, filled, plan.receipt_addr.script_pubkey());

    let fee_out = TxOut::new_fee(plan.fee_atoms, plan.fee_asset);

    // Per-asset change back to the taker (change_addr), for every funded asset
    // whose selected total exceeds what the fixed outputs consume. The change in
    // the CREDIT asset (asset B) is kept separate because it is the preferred
    // non-asset-A "gap" output at slot 1 on a full fill (this reproduces the
    // regtest layout `[credit, B-change, receipt, …]`).
    let mut b_change: Option<TxOut> = None;
    let mut other_changes: Vec<TxOut> = Vec::new();
    for (asset, total) in &funded {
        let used = consumed.get(asset).copied().unwrap_or(0);
        let change = total.checked_sub(used).ok_or_else(|| {
            Error::Generic(format!(
                "taker funding of {asset} ({total}) is below the {used} it must cover"
            ))
        })?;
        if change > 0 {
            let out = explicit_out(*asset, change, plan.change_addr.script_pubkey());
            if *asset == plan.credit.asset {
                b_change = Some(out);
            } else {
                other_changes.push(out);
            }
        }
    }

    // ---- ordered output vector (credit at 0, remainder/gap at 1) ----------
    let mut outputs: Vec<TxOut> = Vec::with_capacity(4 + other_changes.len());
    outputs.push(credit_out);

    if let Some(rem) = &plan.remainder {
        // PARTIAL: the self-replicating remainder covenant occupies slot 1 (2k+1).
        if rem.asset != a_asset {
            return Err(Error::Generic(
                "remainder asset must equal the covenant's sold asset A".into(),
            ));
        }
        outputs.push(explicit_out(rem.asset, rem.value, Script::from(rem.spk.clone()))); // 1
        outputs.push(receipt_out); // 2 (asset A)
        if let Some(bc) = b_change {
            outputs.push(bc);
        }
        outputs.extend(other_changes);
        outputs.push(fee_out);
    } else {
        // FULL fill: slot 1 must be a NON-asset-A explicit output so the leaf reads
        // a zero remainder. Prefer the asset-B change; else any other-asset change;
        // else the fee output (only valid when the fee asset is not asset A).
        if let Some(bc) = b_change {
            outputs.push(bc); // 1 (asset B, gap)
            outputs.push(receipt_out); // 2 (asset A)
            outputs.extend(other_changes);
            outputs.push(fee_out);
        } else if !other_changes.is_empty() {
            let mut rest = other_changes;
            outputs.push(rest.remove(0)); // 1 (non-A change, gap)
            outputs.push(receipt_out); // 2
            outputs.extend(rest);
            outputs.push(fee_out);
        } else if plan.fee_asset != a_asset {
            outputs.push(fee_out); // 1 (fee output, non-A gap)
            outputs.push(receipt_out); // 2
        } else {
            return Err(Error::Generic(
                "full fill has no non-asset-A output to occupy the remainder slot (output 1); \
                 pick a fee asset that is not the covenant's sold asset, or leave change"
                    .into(),
            ));
        }
    }

    // ---- build + sign -----------------------------------------------------
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // Covenant input 0: introspection-only witness [leaf, control_block], no sig.
    tx.input[0].witness.script_witness =
        vec![plan.covenant.fill_leaf.clone(), plan.covenant.control_block.clone()];

    // Taker inputs: key-path p2wpkh, segwit-v0 SIGHASH_ALL.
    let secp = Secp256k1::signing_only();
    for (i, ti) in plan.taker_inputs.iter().enumerate() {
        let input_index = 1 + i; // input 0 is the covenant
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &ti.secret_key);
        let compressed = pk.serialize();
        let pkh = hash160::Hash::hash(&compressed).to_byte_array();
        // The signing key must actually control this UTXO.
        if p2wpkh_spk(&pkh) != ti.spk {
            return Err(Error::Generic(format!(
                "taker input {}:{} p2wpkh(key) != its scriptPubKey — wrong derivation",
                ti.txid, ti.vout
            )));
        }
        let script_code = p2wpkh_script_code(&pkh);
        let sighash = {
            let mut cache = elements::sighash::SighashCache::new(&tx);
            cache.segwitv0_sighash(
                input_index,
                &script_code,
                confidential::Value::Explicit(ti.value),
                EcdsaSighashType::All,
            )
        };
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &ti.secret_key);
        let mut der = sig.serialize_der().to_vec();
        der.push(SIGHASH_ALL_BYTE);
        tx.input[input_index].witness.script_witness = vec![der, compressed.to_vec()];
    }

    let txid = tx.txid();
    Ok((elements::encode::serialize_hex(&tx), txid))
}

/// Parse a 32-byte secp256k1 secret scalar from hex (helper for the wasm layer).
pub fn covenant_secret_from_hex(secret_hex: &str) -> Result<SecretKey, Error> {
    let bytes = Vec::<u8>::from_hex(secret_hex)
        .map_err(|e| Error::Generic(format!("invalid secret hex: {e}")))?;
    SecretKey::from_slice(&bytes).map_err(|e| Error::Generic(format!("invalid secret key: {e}")))
}

/// The 32-byte v1-taproot maker-payout program + its scriptPubKey for a BIP86
/// internal key, using the ELEMENTS TapTweak (so it matches an `eltr`/BIP86 LWK
/// wallet and the covenant's own `TapTweak/elements` output-key derivation).
///
/// `internal` is the BIP86-derived x-only internal key
/// (`m/86'/coin'/0'/chain/index`). Returns `(program32, spk)` where the maker
/// credit output pays `OP_1 <program32>` and `program32` is the `maker_prog` baked
/// into the FILL leaf.
pub fn maker_payout_program(
    internal: secp256k1::XOnlyPublicKey,
) -> Result<([u8; 32], Vec<u8>), Error> {
    // Bridge the bitcoin `secp256k1` x-only key to the `secp256k1_zkp` type the
    // elements taproot API uses (same curve/serialization, distinct Rust types).
    let internal_zkp = elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&internal.serialize())
        .map_err(|e| Error::Generic(format!("internal key: {e}")))?;
    let secp = elements::secp256k1_zkp::Secp256k1::verification_only();
    // Elements key-spend taproot output key (empty script tree, TapTweak/elements).
    let spend_info = elements::taproot::TaprootSpendInfo::new_key_spend(&secp, internal_zkp, None);
    let out_key = spend_info.output_key();
    let program = out_key.into_inner().serialize();
    let spk = witness_program_spk(1, &program)?.into_bytes();
    Ok((program, spk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
    use crate::bitcoin::Network as BtcNetwork;

    // The exact fixed order from seqdex/daemon/pkg/covenant/leaf_test.go, which is
    // itself pinned to the proven Python builders. asset_a = 0..31, asset_b =
    // 32..63, rate 3/7, min_lot 5e8, maker_prog = 0x11*32, expiry 400,
    // maker_x = 0x22*32, internal_key = NUMS.
    const GOLD_FILL_LEAF: &str = "cdc95188cd76938bd59f63cd76938bce518820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f8763cd76938bd1cdca7b8888cd76938bcf518876080065cd1d00000000df6967080000000000000000686708000000000000000068d86976080065cd1d00000000df69080300000000000000d969080600000000000000d769080700000000000000da6977cd7693ce518820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f88cd7693d1518820111111111111111111111111111111111111111111111111111111111111111188cd7693cf51887cdf";
    const GOLD_CTRL_BLOCK: &str = "c550929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0b36045e27b7a5812d8d7339811db86ef98751c7e382a84a1d34949a83b4ae920";
    // OP_1 <maker_prog=0x11*32>  == the covenant's own scriptPubKey / remainder dest.
    const GOLD_ORDER_SPK: &str =
        "5120b22544534c99090050a06eece12231a2321f4144661ab3964408d5780821afaa";
    const MAKER_PROG_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn asset_a() -> AssetId {
        // bytes(range(0,32)) in internal order == display hex reversed. AssetId
        // parses display hex, so feed the reversed bytes.
        let mut b: Vec<u8> = (0u8..32).collect();
        b.reverse();
        AssetId::from_slice(&b).unwrap()
    }
    fn asset_b() -> AssetId {
        let mut b: Vec<u8> = (32u8..64).collect();
        b.reverse();
        AssetId::from_slice(&b).unwrap()
    }
    fn asset_fee() -> AssetId {
        // A third distinct asset for the network fee (all-0x33).
        AssetId::from_slice(&[0x33u8; 32]).unwrap()
    }

    // Derive a BIP84 m/84'/1'/0'/0/index p2wpkh key + spk from a test seed.
    fn taker_key(seed_byte: u8, index: u32) -> (SecretKey, Vec<u8>) {
        let seed = [seed_byte; 32];
        let master = Xpriv::new_master(BtcNetwork::Testnet, &seed).unwrap();
        let secp = Secp256k1::new();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ]);
        let child = master.derive_priv(&secp, &path).unwrap();
        let sk = child.private_key;
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pkh = hash160::Hash::hash(&pk.serialize()).to_byte_array();
        (sk, p2wpkh_spk(&pkh))
    }

    fn dummy_addr() -> Address {
        // A valid explicit p2wpkh address (only its scriptPubKey is used by the
        // builder); constructed from a fixed pkh so the test needs no network.
        let spk = Script::from(p2wpkh_spk(&[0x11u8; 20]));
        Address::from_script(&spk, None, &elements::AddressParams::ELEMENTS).unwrap()
    }

    fn base_covenant(locked: u64) -> CovenantInput {
        CovenantInput {
            txid: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            vout: 0,
            asset: asset_a(),
            locked,
            fill_leaf: Vec::<u8>::from_hex(GOLD_FILL_LEAF).unwrap(),
            control_block: Vec::<u8>::from_hex(GOLD_CTRL_BLOCK).unwrap(),
        }
    }

    fn credit(value: u64) -> FillCredit {
        FillCredit {
            asset: asset_b(),
            program: Vec::<u8>::from_hex(MAKER_PROG_HEX).unwrap(),
            version: 1,
            value,
        }
    }

    // ceil(filled * 3 / 7)
    fn required_b(filled: u64) -> u64 {
        ((filled as u128 * 3 + 6) / 7) as u64
    }

    #[test]
    fn credit_spk_matches_order_spk_form() {
        // The maker credit spk OP_1 <maker_prog> and the covenant/remainder spk
        // share the OP_1<32> witness-program form; the golden order spk is exactly
        // OP_1 <output_key>. Here we only assert the credit spk builder shape.
        let spk = witness_program_spk(1, &Vec::<u8>::from_hex(MAKER_PROG_HEX).unwrap()).unwrap();
        assert_eq!(
            spk.as_bytes().to_hex(),
            "5120".to_string() + MAKER_PROG_HEX
        );
    }

    #[test]
    fn full_fill_bytes_match_golden() {
        // locked == filled (full fill). min_lot 5e8; pick locked >= min_lot.
        let locked: u64 = 1_000_000_000;
        let req = required_b(locked);
        // Taker funds asset B (covers credit) + a fee asset (covers fee).
        let (skb, spkb) = taker_key(0xAA, 0);
        let (skf, spkf) = taker_key(0xBB, 0);
        let fee: u64 = 5000;
        let b_in = req + 250_000; // leaves a B change
        let fee_in = fee + 111; // leaves a fee-asset change
        let plan = CovenantFillPlan {
            covenant: base_covenant(locked),
            credit: credit(req),
            remainder: None,
            taker_inputs: vec![
                TakerFundingInput {
                    txid: "2222222222222222222222222222222222222222222222222222222222222222".into(),
                    vout: 0,
                    value: b_in,
                    asset: asset_b(),
                    spk: spkb,
                    secret_key: skb,
                },
                TakerFundingInput {
                    txid: "3333333333333333333333333333333333333333333333333333333333333333".into(),
                    vout: 1,
                    value: fee_in,
                    asset: asset_fee(),
                    spk: spkf,
                    secret_key: skf,
                },
            ],
            receipt_addr: dummy_addr(),
            change_addr: dummy_addr(),
            fee_atoms: fee,
            fee_asset: asset_fee(),
        };
        let (hex, _txid) = build_covenant_fill_tx(&plan).unwrap();
        let tx: Transaction = elements::encode::deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap();

        // Covenant input 0 witness == [FILL leaf, control block] (byte-for-byte).
        let w = &tx.input[0].witness.script_witness;
        assert_eq!(w.len(), 2, "covenant witness stack size");
        assert_eq!(w[0].to_hex(), GOLD_FILL_LEAF, "FILL leaf");
        assert_eq!(w[1].to_hex(), GOLD_CTRL_BLOCK, "control block");

        // Output 0 == maker credit (asset B, value == required, spk OP_1<maker_prog>).
        let o0 = &tx.output[0];
        assert_eq!(o0.value, confidential::Value::Explicit(req));
        assert_eq!(o0.asset, confidential::Asset::Explicit(asset_b()));
        assert_eq!(o0.script_pubkey.as_bytes().to_hex(), "5120".to_string() + MAKER_PROG_HEX);

        // Output 1 (full fill) == a NON-asset-A gap output (the taker's B change).
        let o1 = &tx.output[1];
        assert_eq!(o1.asset, confidential::Asset::Explicit(asset_b()));
        assert_ne!(o1.asset, confidential::Asset::Explicit(asset_a()));

        // Output 2 == the taker's asset-A receipt (the full locked amount).
        let o2 = &tx.output[2];
        assert_eq!(o2.asset, confidential::Asset::Explicit(asset_a()));
        assert_eq!(o2.value, confidential::Value::Explicit(locked));

        // A fee output exists in the fee asset.
        assert!(tx.output.iter().any(|o| o.is_fee()
            && o.asset == confidential::Asset::Explicit(asset_fee())
            && o.value == confidential::Value::Explicit(fee)));
    }

    #[test]
    fn partial_fill_layout_and_witness() {
        // locked 1e9, remainder 4e8 (>= min_lot 5e8? no — pick remainder 6e8 so
        // both filled(4e8<min_lot) ... choose filled 6e8, remainder 4e8 -> both
        // must be >= 5e8. Use locked 2e9, filled 1e9, remainder 1e9.
        let locked: u64 = 2_000_000_000;
        let remainder: u64 = 1_000_000_000;
        let filled = locked - remainder;
        let req = required_b(filled);
        let (skb, spkb) = taker_key(0xCC, 0);
        let fee: u64 = 5000;
        let b_in = req + 300_000;
        let plan = CovenantFillPlan {
            covenant: base_covenant(locked),
            credit: credit(req),
            remainder: Some(FillRemainder {
                asset: asset_a(),
                value: remainder,
                spk: Vec::<u8>::from_hex(GOLD_ORDER_SPK).unwrap(),
            }),
            taker_inputs: vec![TakerFundingInput {
                txid: "4444444444444444444444444444444444444444444444444444444444444444".into(),
                vout: 0,
                value: b_in,
                asset: asset_b(),
                spk: spkb,
                secret_key: skb,
            }],
            receipt_addr: dummy_addr(),
            change_addr: dummy_addr(),
            fee_atoms: fee,
            fee_asset: asset_b(), // fee paid in asset B (folded into the B selection)
        };
        let (hex, _txid) = build_covenant_fill_tx(&plan).unwrap();
        let tx: Transaction = elements::encode::deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap();

        // Covenant witness intact.
        assert_eq!(tx.input[0].witness.script_witness[0].to_hex(), GOLD_FILL_LEAF);
        // Output 0 credit (B); Output 1 remainder (A) to the SAME covenant spk.
        assert_eq!(tx.output[0].asset, confidential::Asset::Explicit(asset_b()));
        let o1 = &tx.output[1];
        assert_eq!(o1.asset, confidential::Asset::Explicit(asset_a()));
        assert_eq!(o1.value, confidential::Value::Explicit(remainder));
        assert_eq!(o1.script_pubkey.as_bytes().to_hex(), GOLD_ORDER_SPK);
        // Output 2 receipt (A) == filled.
        assert_eq!(tx.output[2].asset, confidential::Asset::Explicit(asset_a()));
        assert_eq!(tx.output[2].value, confidential::Value::Explicit(filled));
    }

    #[test]
    fn rejects_confidential_taker_input() {
        let locked: u64 = 1_000_000_000;
        let req = required_b(locked);
        let (skb, _spkb) = taker_key(0xDD, 0);
        // A confidential (32-byte program v1) spk masquerading as a funding input.
        let bad_spk = vec![0x51u8, 0x20]
            .into_iter()
            .chain(std::iter::repeat(0xEE).take(32))
            .collect::<Vec<u8>>();
        let plan = CovenantFillPlan {
            covenant: base_covenant(locked),
            credit: credit(req),
            remainder: None,
            taker_inputs: vec![TakerFundingInput {
                txid: "5555555555555555555555555555555555555555555555555555555555555555".into(),
                vout: 0,
                value: req + 5000,
                asset: asset_b(),
                spk: bad_spk,
                secret_key: skb,
            }],
            receipt_addr: dummy_addr(),
            change_addr: dummy_addr(),
            fee_atoms: 5000,
            fee_asset: asset_b(),
        };
        assert!(build_covenant_fill_tx(&plan).is_err());
    }

    #[test]
    fn maker_payout_program_is_deterministic_p2tr() {
        // Derive a BIP86 internal key and confirm the elements key-spend program is
        // a stable 32-byte value with an OP_1<32> spk.
        let seed = [0x42u8; 32];
        let master = Xpriv::new_master(BtcNetwork::Testnet, &seed).unwrap();
        let secp = Secp256k1::new();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ]);
        let child = master.derive_priv(&secp, &path).unwrap();
        let (xonly, _p) = secp256k1::PublicKey::from_secret_key(&secp, &child.private_key)
            .x_only_public_key();
        let (prog, spk) = maker_payout_program(xonly).unwrap();
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x51);
        assert_eq!(spk[1], 0x20);
        assert_eq!(&spk[2..], &prog[..]);
        // Determinism.
        let (prog2, _) = maker_payout_program(xonly).unwrap();
        assert_eq!(prog, prog2);
    }
}
