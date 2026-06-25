//! Sequentia (SeqDEX) cross-chain HTLC — the SEQ-leg pieces a browser taker needs.
//!
//! Phase 6c-2. This is the SEQ-side counterpart to the same-chain swap builder in
//! [`crate::seqdex_swap`] and to the BTC-leg work that `btc.js` already does in the
//! web wallet. It is a faithful Rust port of the SeqDEX daemon's `pkg/xchain`:
//! `primitive.go` (the HashLock HTLC redeem script + leg-agnostic unlock items),
//! `leg_elements.go` (the `ElementsLeg` SEQ HTLC redeem/refund spend builder), and
//! `keys.go` (secp256k1 DER + SIGHASH_ALL).
//!
//! ## The cross-chain flow (MVP: taker BUYS a SEQ asset with BTC)
//!
//! The taker (browser) is the swap initiator. It (1) generates the secret `s` and
//! `H = sha256(s)`; (2) locks + funds the BTC-leg HTLC on the parent chain (this is
//! `btc.js`, NOT this module); (3) calls the daemon's `ProposeXchainSwap`; (4) the
//! daemon locks the SEQ-leg HTLC; (5) the taker verifies the anchor ordering and
//! then **CLAIMS the SEQ-leg HTLC, revealing `s` on-chain** (this module); (6) the
//! daemon reads `s` off the SEQ-leg claim and claims the BTC leg. Refund: the taker
//! refunds the BTC leg after `T_btc` (`btc.js`); the SEQ-leg refund is the maker's,
//! but we build it here too for completeness/symmetry.
//!
//! ## Design A — the HTLC
//!
//! Both legs are locked to the SAME hashlock `H` and the SAME preimage `s`. The
//! redeemScript is plain Bitcoin Script, identical byte-for-byte on both chains:
//!
//! ```text
//! OP_IF
//!     OP_SHA256 <H> OP_EQUALVERIFY <claim_pub> OP_CHECKSIG       # redeem branch
//! OP_ELSE
//!     <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pub> OP_CHECKSIG  # refund
//! OP_ENDIF
//! ```
//!
//! paid to P2SH. The redeem (IF) branch reveals the preimage; the refund (ELSE)
//! branch spends back to the locker once nLockTime reaches `<locktime>` (CLTV).
//!
//! ## Byte-for-byte fidelity with the daemon
//!
//! - **Redeem script**: built with elements' [`script::Builder`], whose `push_int`
//!   / `push_slice` / `push_opcode` are byte-identical to btcd's `txscript`
//!   `AddInt64` / `AddData` / `AddOp` used in `primitive.go::LockScript`. In
//!   particular the CLTV `<locktime>` is a minimal little-endian signed-magnitude
//!   scriptint (same `build_scriptint` / `scriptNum.Bytes()` encoding), `<H>` is a
//!   32-byte data push (`OP_PUSHBYTES_32`), and `<claim_pub>`/`<refund_pub>` are
//!   33-byte compressed-key pushes (`OP_PUSHBYTES_33`).
//! - **Sighash**: the legacy SIGHASH_ALL sighash over the redeemScript, via
//!   [`elements::sighash::SighashCache::legacy_sighash`] — the exact construction
//!   the daemon uses through go-elements' `tx.HashForSignature(0, redeemScript,
//!   SigHashAll)`. The Sequentia HTLC outputs are explicit (unconfidential), as in
//!   the daemon, so the legacy sighash has no commitment subtleties.
//! - **Signature**: ECDSA over secp256k1, DER-encoded, low-S normalized (relay
//!   policy), with a trailing `SIGHASH_ALL` (0x01) byte appended — matching
//!   `keys.go::SignDER` + `leg_elements.go::sign`.
//! - **scriptSig**: `<unlock items…> <redeemScript>`, where the empty-vector unlock
//!   item serializes to `OP_0` (the ELSE-branch selector) and the `{0x01}` item
//!   serializes to `OP_1`/`OP_TRUE` (the IF-branch selector) — exactly
//!   `leg_elements.go::finalize`'s `AddOp(OP_0)` / `AddData` minimal-push behaviour.
//! - **Tx body**: version 2; redeem uses a final sequence `0xffffffff` and
//!   nLockTime 0; refund uses a non-final sequence `0xfffffffe` and nLockTime =
//!   `<locktime>`. Two explicit outputs in the input's asset: the recipient
//!   (amount − fee) and an explicit Elements fee output (empty scriptPubKey) —
//!   matching `leg_elements.go::buildSpendTx`.

use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::hex::{FromHex, ToHex};
use elements::script::Builder;
use elements::secp256k1_zkp::rand::RngCore;
use elements::{
    confidential, opcodes, AssetId, EcdsaSighashType, LockTime, OutPoint, Script, Sequence,
    Transaction, TxIn, TxInWitness, TxOut, Txid,
};

use crate::bitcoin::secp256k1::{self, Message, Secp256k1, SecretKey};
use crate::error::Error;

/// SIGHASH_ALL, appended to the DER signature (matches the daemon's
/// `byte(txscript.SigHashAll)`).
const SIGHASH_ALL_BYTE: u8 = 0x01;

/// A freshly generated swap secret and its hashlock, as the taker-initiator needs.
///
/// `secret` is the 32-byte preimage `s`; `hash` is `sha256(s)` (`H`), the public
/// part embedded in both legs' HTLC scripts. The taker keeps `secret` private until
/// it claims the SEQ leg, at which point `s` is revealed on-chain.
#[derive(Debug, Clone)]
pub struct SwapSecret {
    /// The 32-byte preimage `s` (hex).
    pub secret_hex: String,
    /// `H = sha256(s)` (hex), the hashlock both legs commit to.
    pub hash_hex: String,
}

/// Generate a fresh 32-byte swap secret and its sha256 hashlock.
///
/// Mirrors the taker's `rand.Read(secret[32])` + `sha256.Sum256(secret)` in
/// `cmd/seqdex-xchain-taker`. The taker hands `H` (hash) to the daemon (in the BTC
/// leg lock and `ProposeXchainSwap`) and keeps `s` (secret) to claim the SEQ leg.
pub fn generate_swap_secret() -> SwapSecret {
    let mut secret = [0u8; 32];
    elements::secp256k1_zkp::rand::thread_rng().fill_bytes(&mut secret);
    let hash = sha256::Hash::hash(&secret);
    SwapSecret {
        secret_hex: secret.to_hex(),
        hash_hex: hash.to_byte_array().to_hex(),
    }
}

/// Build the Design-A HTLC redeemScript.
///
/// Byte-identical to the daemon's `HashLock.LockScript` (`primitive.go`):
/// `OP_IF OP_SHA256 <H> OP_EQUALVERIFY <claim_pub> OP_CHECKSIG OP_ELSE <locktime>
/// OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pub> OP_CHECKSIG OP_ENDIF`.
///
/// - `hash`: 32-byte `H = sha256(secret)`.
/// - `claim_pub`: 33-byte compressed pubkey that can spend the IF/redeem branch
///   (the taker's SEQ claim key).
/// - `refund_pub`: 33-byte compressed pubkey that can spend the ELSE/CLTV refund
///   branch (the SEQ-leg locker's = maker's refund key).
/// - `locktime`: the CLTV value (a block height on regtest/testnet).
pub fn build_htlc_redeem_script(
    hash: &[u8],
    claim_pub: &[u8],
    refund_pub: &[u8],
    locktime: u32,
) -> Result<Script, Error> {
    if hash.len() != 32 {
        return Err(Error::Generic(format!(
            "hashlock H must be 32 bytes, got {}",
            hash.len()
        )));
    }
    // Compressed-key sanity: the daemon always embeds 33-byte compressed keys, and
    // the byte-match depends on it (OP_PUSHBYTES_33). Validate parseability too.
    for (label, pk) in [("claim", claim_pub), ("refund", refund_pub)] {
        if pk.len() != 33 {
            return Err(Error::Generic(format!(
                "{label} pubkey must be 33-byte compressed, got {}",
                pk.len()
            )));
        }
        secp256k1::PublicKey::from_slice(pk)
            .map_err(|e| Error::Generic(format!("invalid {label} pubkey: {e}")))?;
    }

    let script = Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_opcode(opcodes::all::OP_SHA256)
        .push_slice(hash)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_slice(claim_pub)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_int(locktime as i64)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(refund_pub)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();
    Ok(script)
}

/// The HTLC output being spent on the SEQ leg, plus the spend's destination.
///
/// Mirrors the daemon's `ElementsSpendInput` (`leg_elements.go`). All values are in
/// atoms; ids/txids are display-order (txid-style) hex, exactly as a node reports
/// them. The Sequentia HTLC output is explicit (unconfidential), so no blinders are
/// needed — only the outpoint, value, asset and the destination scriptPubKey.
#[derive(Debug, Clone)]
pub struct SeqHtlcSpend {
    /// Funding txid (display/big-endian hex), the HTLC outpoint.
    pub txid: String,
    /// Funding vout of the HTLC output.
    pub vout: u32,
    /// Value of the HTLC output, in atoms.
    pub amount: u64,
    /// 32-byte asset id of the HTLC output, display hex.
    pub asset_id: String,
    /// scriptPubKey of the redeem/refund destination (where the spend pays).
    pub dest_spk: Vec<u8>,
    /// Fee in atoms; emitted as an explicit Elements fee output.
    pub fee: u64,
}

/// Build the unsigned SEQ-leg spend skeleton shared by redeem and refund.
///
/// Two explicit outputs in the input's asset: recipient = `amount − fee`, and an
/// explicit fee output (empty scriptPubKey). Mirrors `leg_elements.go::buildSpendTx`.
fn build_spend_tx(spend: &SeqHtlcSpend, locktime: u32, refund: bool) -> Result<Transaction, Error> {
    let txid = Txid::from_str(&spend.txid)
        .map_err(|e| Error::Generic(format!("invalid HTLC txid {}: {e}", spend.txid)))?;
    let asset = AssetId::from_str(&spend.asset_id)
        .map_err(|e| Error::Generic(format!("invalid asset id {}: {e}", spend.asset_id)))?;
    let recv_value = spend
        .amount
        .checked_sub(spend.fee)
        .ok_or_else(|| Error::Generic("fee exceeds HTLC value".into()))?;

    let (sequence, lock_time) = if refund {
        // non-final sequence lets nLockTime/CLTV take effect (0xfffffffe), as in the
        // daemon's refund path.
        (Sequence(0xffff_fffe), LockTime::from_consensus(locktime))
    } else {
        (Sequence::MAX, LockTime::ZERO)
    };

    let input = TxIn {
        previous_output: OutPoint::new(txid, spend.vout),
        is_pegin: false,
        script_sig: Script::new(),
        sequence,
        asset_issuance: Default::default(),
        witness: TxInWitness::default(),
    };

    let recipient = TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(recv_value),
        nonce: confidential::Nonce::Null,
        script_pubkey: Script::from(spend.dest_spk.clone()),
        witness: Default::default(),
    };
    // Explicit Elements fee output: empty scriptPubKey, denominated in the same asset.
    let fee_out = TxOut::new_fee(spend.fee, asset);

    Ok(Transaction {
        version: 2,
        lock_time,
        input: vec![input],
        output: vec![recipient, fee_out],
    })
}

/// Compute the legacy SIGHASH_ALL sighash over `redeem_script` for input 0 and sign
/// it, returning `DER(sig) || 0x01`. Matches `leg_elements.go::sign` +
/// `keys.go::SignDER`.
fn sign_legacy(tx: &Transaction, redeem_script: &Script, key: &SecretKey) -> Vec<u8> {
    let cache = elements::sighash::SighashCache::new(tx);
    let sighash = cache.legacy_sighash(0, redeem_script, EcdsaSighashType::All);
    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(sighash.to_byte_array());
    // sign_ecdsa produces a low-S (normalized) signature, satisfying relay policy
    // (the daemon relies on btcec's low-S for the same reason).
    let sig = secp.sign_ecdsa(&msg, key);
    let mut der = sig.serialize_der().to_vec();
    der.push(SIGHASH_ALL_BYTE);
    der
}

/// Assemble the P2SH scriptSig `<unlock items…> <redeemScript>` and serialize the
/// signed Elements tx to hex. An empty unlock item becomes `OP_0` (ELSE selector);
/// a non-empty one is a minimal data push (so `{0x01}` becomes `OP_1`/`OP_TRUE`, the
/// IF selector) — matching `leg_elements.go::finalize`.
fn finalize(mut tx: Transaction, redeem_script: &Script, items: &[Vec<u8>]) -> String {
    let mut b = Builder::new();
    for it in items {
        b = push_data_minimal(b, it);
    }
    // The redeemScript push always uses the canonical PUSHDATA encoding for its
    // length (it is far larger than the small-int range), so push_slice matches
    // btcd's AddData here.
    b = b.push_slice(redeem_script.as_bytes());
    tx.input[0].script_sig = b.into_script();
    // Full Elements tx serialization, matching go-elements' tx.ToHex().
    elements::encode::serialize_hex(&tx)
}

/// Push one scriptSig data item with the SAME minimization btcd's
/// `ScriptBuilder.AddData` applies (which `leg_elements.go::finalize` relies on):
/// empty (or a single `0x00`) becomes `OP_0`; a single byte `1..=16` becomes the
/// `OP_1..OP_16` small-int opcode; a single `0x81` becomes `OP_1NEGATE`; everything
/// else is a normal length-prefixed push. rust-elements' `push_slice` does NOT do
/// this small-value minimization, so we must do it by hand to avoid a non-minimal
/// push (which the node rejects as "Data push larger than necessary"). In practice
/// only the redeem branch's `{0x01}` (OP_TRUE) selector and the refund branch's
/// empty (OP_0) selector hit the special cases; sig/preimage take the normal path.
fn push_data_minimal(b: Builder, data: &[u8]) -> Builder {
    match data {
        [] => b.push_opcode(opcodes::all::OP_PUSHBYTES_0), // OP_0 / OP_FALSE
        [0x00] => b.push_opcode(opcodes::all::OP_PUSHBYTES_0),
        [v] if *v >= 1 && *v <= 16 => {
            // OP_1 (0x51) .. OP_16 (0x60): (OP_1 - 1) + v
            let op = opcodes::All::from(opcodes::all::OP_PUSHNUM_1.into_u8() - 1 + *v);
            b.push_opcode(op)
        }
        [0x81] => b.push_opcode(opcodes::all::OP_PUSHNUM_NEG1),
        _ => b.push_slice(data),
    }
}

/// Build the signed SEQ-leg **claim** (IF/redeem branch) tx, revealing the preimage.
///
/// The unlock items are `<sig> <preimage> OP_TRUE`, selecting the IF branch and
/// satisfying `SHA256(<preimage>) == H` plus the claim-key CHECKSIG. Mirrors
/// `HashLock.RedeemUnlockItems` + `ElementsLeg.Redeem`.
///
/// - `spend`: the SEQ HTLC outpoint/value/asset + destination + fee.
/// - `redeem_script`: the HTLC redeemScript from [`build_htlc_redeem_script`].
/// - `claim_secret`: the 32-byte secp256k1 scalar of the taker's SEQ claim key.
/// - `preimage`: the 32-byte swap secret `s` (revealed on-chain by this spend).
///
/// Returns the serialized Elements tx hex for `sendrawtransaction`.
pub fn build_claim_tx(
    spend: &SeqHtlcSpend,
    redeem_script: &Script,
    claim_secret: &SecretKey,
    preimage: &[u8],
) -> Result<String, Error> {
    if preimage.len() != 32 {
        return Err(Error::Generic(format!(
            "preimage must be 32 bytes, got {}",
            preimage.len()
        )));
    }
    let tx = build_spend_tx(spend, 0, false)?;
    let sig = sign_legacy(&tx, redeem_script, claim_secret);
    // <sig> <preimage> OP_TRUE  (OP_TRUE encoded as the {0x01} -> OP_1 minimal push)
    let items = vec![sig, preimage.to_vec(), vec![0x01]];
    Ok(finalize(tx, redeem_script, &items))
}

/// Build the signed SEQ-leg **refund** (ELSE/CLTV branch) tx, valid once nLockTime
/// reaches `locktime`.
///
/// The unlock items are `<sig> OP_FALSE`, selecting the ELSE branch. The tx carries
/// a non-final sequence and `nLockTime = locktime` so CLTV passes. Mirrors
/// `HashLock.RefundUnlockItems` + `ElementsLeg.Refund`. This is the maker's path in
/// the MVP, built here for symmetry/completeness.
///
/// - `refund_secret`: the secp256k1 scalar of the refund key embedded in the script.
/// - `locktime`: the CLTV value; also set as the tx's nLockTime.
pub fn build_refund_tx(
    spend: &SeqHtlcSpend,
    redeem_script: &Script,
    refund_secret: &SecretKey,
    locktime: u32,
) -> Result<String, Error> {
    let tx = build_spend_tx(spend, locktime, true)?;
    let sig = sign_legacy(&tx, redeem_script, refund_secret);
    // <sig> OP_FALSE
    let items = vec![sig, Vec::new()];
    Ok(finalize(tx, redeem_script, &items))
}

/// Derive the 33-byte compressed public key for a given secp256k1 secret scalar
/// (hex), as embedded in the HTLC redeemScript. Helper for callers that hold the
/// key bytes (e.g. a derived HTLC key) and need the pubkey to give the daemon.
pub fn pubkey_for_secret(secret_hex: &str) -> Result<String, Error> {
    let key = secret_from_hex(secret_hex)?;
    let secp = Secp256k1::signing_only();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &key);
    Ok(pk.serialize().to_hex())
}

/// Parse a 32-byte secp256k1 secret scalar from hex.
pub fn secret_from_hex(secret_hex: &str) -> Result<SecretKey, Error> {
    let bytes = Vec::<u8>::from_hex(secret_hex)
        .map_err(|e| Error::Generic(format!("invalid secret hex: {e}")))?;
    SecretKey::from_slice(&bytes).map_err(|e| Error::Generic(format!("invalid secret key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed set of inputs the Go daemon also produces a script for, so the
    // redeem-script byte-match can be checked both here and against the daemon.
    const H_HEX: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const CLAIM_PUB: &str = "02e8bdd7e8b1e7c1b8a8d3f2c5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5";
    const REFUND_PUB: &str = "03a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    #[test]
    fn redeem_script_layout() {
        let h = Vec::<u8>::from_hex(H_HEX).unwrap();
        let claim = Vec::<u8>::from_hex(CLAIM_PUB).unwrap();
        let refund = Vec::<u8>::from_hex(REFUND_PUB).unwrap();
        let script = build_htlc_redeem_script(&h, &claim, &refund, 250).unwrap();
        let hex = script.as_bytes().to_hex();
        // OP_IF(63) OP_SHA256(a8) PUSH32(20)<H> OP_EQUALVERIFY(88) PUSH33(21)<claim>
        // OP_CHECKSIG(ac) OP_ELSE(67) <250 as scriptint = fa00>(02 fa00)
        // OP_CLTV(b1) OP_DROP(75) PUSH33(21)<refund> OP_CHECKSIG(ac) OP_ENDIF(68)
        assert!(
            hex.starts_with(&format!("63a820{H_HEX}88")),
            "IF SHA256 PUSH32 <H> EQUALVERIFY: {hex}"
        );
        // 250 = 0xfa -> needs a high-byte guard -> scriptint "fa00", pushed as 02 fa00.
        assert!(hex.contains("6702fa00b175"), "ELSE <250> CLTV DROP: {hex}");
        assert!(hex.ends_with("ac68"), "...CHECKSIG ENDIF: {hex}");
    }

    #[test]
    fn small_locktime_uses_scriptnum() {
        // locktime 17 is > 16, so it is NOT a small-int opcode: pushed as 0x01 0x11.
        let h = Vec::<u8>::from_hex(H_HEX).unwrap();
        let claim = Vec::<u8>::from_hex(CLAIM_PUB).unwrap();
        let refund = Vec::<u8>::from_hex(REFUND_PUB).unwrap();
        let script = build_htlc_redeem_script(&h, &claim, &refund, 17).unwrap();
        assert!(script.as_bytes().to_hex().contains("670111b175"));
    }

    #[test]
    fn redeem_script_byte_matches_daemon() {
        // Golden vectors emitted by the SeqDEX daemon's HashLock.LockScript
        // (pkg/xchain/primitive.go) for these exact inputs — proves byte-for-byte
        // parity of the IF/SHA256/CLTV HTLC redeemScript across the Go txscript
        // builder and the Rust elements Builder, including the CLTV scriptint
        // encoding (small <=16, the high-byte-guard 250, and a 3-byte 1_000_000).
        let h = Vec::<u8>::from_hex(H_HEX).unwrap();
        let claim = Vec::<u8>::from_hex(CLAIM_PUB).unwrap();
        let refund = Vec::<u8>::from_hex(REFUND_PUB).unwrap();
        let cases = [
            (17u32, "63a820a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90882102e8bdd7e8b1e7c1b8a8d3f2c5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5ac670111b1752103a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90ac68"),
            (250u32, "63a820a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90882102e8bdd7e8b1e7c1b8a8d3f2c5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5ac6702fa00b1752103a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90ac68"),
            (1_000_000u32, "63a820a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90882102e8bdd7e8b1e7c1b8a8d3f2c5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5ac670340420fb1752103a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90ac68"),
        ];
        for (lt, want) in cases {
            let script = build_htlc_redeem_script(&h, &claim, &refund, lt).unwrap();
            assert_eq!(script.as_bytes().to_hex(), want, "locktime {lt}");
        }
    }

    #[test]
    fn secret_generation_hashes() {
        let s = generate_swap_secret();
        let secret = Vec::<u8>::from_hex(&s.secret_hex).unwrap();
        assert_eq!(secret.len(), 32);
        let h = sha256::Hash::hash(&secret);
        assert_eq!(h.to_byte_array().to_hex(), s.hash_hex);
    }

    #[test]
    fn pubkey_roundtrip() {
        let s = generate_swap_secret();
        // The 32-byte random secret is also a valid secp256k1 scalar with overwhelming
        // probability; derive its pubkey and confirm the script accepts it.
        let pk = pubkey_for_secret(&s.secret_hex).unwrap();
        let pk_bytes = Vec::<u8>::from_hex(&pk).unwrap();
        assert_eq!(pk_bytes.len(), 33);
        let h = Vec::<u8>::from_hex(H_HEX).unwrap();
        build_htlc_redeem_script(&h, &pk_bytes, &pk_bytes, 100).unwrap();
    }
}
