//! CoinJoin: sign the coordinator's round transaction for the wallet's own inputs.
//!
//! In a CoinJoin the transaction is assembled by somebody else. The participant's whole
//! contribution is a signature over its own inputs of a transaction it did not build — which is the
//! one thing the browser cannot do from JavaScript, exactly as with the covenant FILL
//! ([`crate::seqob_covenant`]): an Elements segwit-v0 sighash commits to the confidential value of
//! the coin being spent and to every output commitment, and there is no JS implementation of that
//! in the wallet.
//!
//! Scope, deliberately narrow:
//!
//! * it signs **only** the outpoints it is given, and only key-path P2WPKH ones — the shape the
//!   wallet's `wpkh`/SLIP-77 descriptor produces;
//! * it refuses when the derived key does not control the coin, rather than producing a signature
//!   that will simply fail later with no explanation;
//! * it does **not** decide whether the transaction is one worth signing. That judgement needs the
//!   wallet's blinding key to unblind the outputs, and it belongs — and lives — on the JS side, in
//!   `coinjoin.js`, which checks the round pays it what was promised BEFORE calling this. Signing is
//!   the irreversible step, so the check must not be inside the thing being checked.
//!
//! The result is the same transaction with witnesses filled in for those inputs only, ready to hand
//! back to the coordinator, which merges it into its own copy.

use elements::hashes::{hash160, Hash};
use elements::hex::FromHex;
use elements::sighash::SighashCache;
use elements::{confidential, EcdsaSighashType, Transaction, Txid};

use crate::bitcoin::secp256k1::{self, Message, Secp256k1, SecretKey};
use crate::error::Error;
use crate::seqob_covenant::{p2wpkh_script_code, p2wpkh_spk};

const SIGHASH_ALL_BYTE: u8 = 0x01;

/// One of the participant's own coins in the round transaction.
pub struct CoinjoinInput {
    /// The coin's transaction id.
    pub txid: Txid,
    /// The coin's output index.
    pub vout: u32,
    /// The coin's explicit value. Round inputs are transparent by construction — the coordinator
    /// refuses confidential ones, because blinding the round would otherwise require their blinders.
    pub value: u64,
    /// Its scriptPubKey, checked against the derived key so a wrong derivation path fails loudly.
    pub spk: Vec<u8>,
    /// The key that controls the coin, derived by the caller from the wallet seed.
    pub secret_key: SecretKey,
}

/// Sign the caller's inputs of `tx_hex`, returning the transaction with those witnesses attached.
///
/// Inputs are located by OUTPOINT, never by position: the coordinator shuffles the round, so an
/// index supplied by it would be a value we must not trust.
pub fn sign_coinjoin_inputs(tx_hex: &str, inputs: &[CoinjoinInput]) -> Result<String, Error> {
    let bytes = Vec::<u8>::from_hex(tx_hex)
        .map_err(|e| Error::Generic(format!("invalid coinjoin tx hex: {e}")))?;
    let mut tx: Transaction = elements::encode::deserialize(&bytes)
        .map_err(|e| Error::Generic(format!("coinjoin tx decode: {e}")))?;
    if inputs.is_empty() {
        return Err(Error::Generic("no inputs to sign".into()));
    }

    let secp = Secp256k1::signing_only();
    for ci in inputs {
        let idx = tx
            .input
            .iter()
            .position(|i| i.previous_output.txid == ci.txid && i.previous_output.vout == ci.vout)
            .ok_or_else(|| {
                Error::Generic(format!(
                    "my input {}:{} is not in the round transaction",
                    ci.txid, ci.vout
                ))
            })?;

        let pk = secp256k1::PublicKey::from_secret_key(&secp, &ci.secret_key);
        let compressed = pk.serialize();
        let pkh = hash160::Hash::hash(&compressed).to_byte_array();
        if p2wpkh_spk(&pkh) != ci.spk {
            return Err(Error::Generic(format!(
                "coinjoin input {}:{} p2wpkh(key) != its scriptPubKey — wrong derivation",
                ci.txid, ci.vout
            )));
        }

        let script_code = p2wpkh_script_code(&pkh);
        let sighash = {
            let mut cache = SighashCache::new(&tx);
            cache.segwitv0_sighash(
                idx,
                &script_code,
                confidential::Value::Explicit(ci.value),
                EcdsaSighashType::All,
            )
        };
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa_low_r(&msg, &ci.secret_key);
        let mut der = sig.serialize_der().to_vec();
        der.push(SIGHASH_ALL_BYTE);
        tx.input[idx].witness.script_witness = vec![der, compressed.to_vec()];
    }

    Ok(elements::encode::serialize_hex(&tx))
}
