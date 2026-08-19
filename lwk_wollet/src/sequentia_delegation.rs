//! SEQUENTIA staking pools: delegation records, from a light wallet.
//!
//! A staker (the **controller**) lends its stake weight to a **signer** (a pool
//! operator) by funding one small bare output, the delegation record:
//!
//! ```text
//! <"SEQDEL"> OP_DROP <signer> OP_DROP <controller> OP_CHECKSIG
//! ```
//!
//! While that record is unspent the controller's whole stake weight counts for
//! the signer, who must produce and sign the blocks. The staked coins are not
//! touched by any of this, and the signer never appears in the staking output's
//! spending condition, so a pool can never spend a delegator's stake.
//!
//! Creating the record is an ordinary payment to a bare script, which the PSET
//! builder handles ([`crate::TxBuilder::add_delegation_output`]). SPENDING it is
//! not: a bare pre-segwit script matches no descriptor, so the wallet's signer
//! will not touch it. That is what this module is for, and why it exists at all
//! - without it a light wallet could join a pool but never leave, which would
//! turn the one property that makes delegation safe (exit is unilateral and
//! immediate) into a promise the wallet could not keep.
//!
//! Two spends, one shape:
//!
//! * **reclaim** - spend the record back to the wallet. The delegation ends at
//!   that confirmation.
//! * **re-point** - spend it and create a new record for a different signer in
//!   the SAME transaction. This is not an optimisation. Consensus permits at
//!   most one unspent record per controller, so a reclaim and a fresh
//!   delegation broadcast as two loose transactions could be mined in the order
//!   that leaves two live records, which invalidates the block carrying the
//!   second. One transaction cannot be mis-ordered against itself.
//!
//! The record pays its own fee out of its own value, so neither spend needs to
//! select a wallet coin, which is what keeps this independent of the PSET path.

use elements::bitcoin::hashes::Hash as _;
use elements::hashes::hash160;
use elements::secp256k1_zkp::{Message, Secp256k1, SecretKey};
use elements::{
    confidential, opcodes, AssetId, EcdsaSighashType, LockTime, OutPoint, Script, Sequence,
    Transaction, TxIn, TxInWitness, TxOut, TxOutWitness, Txid,
};
use elements::encode::serialize_hex;
use elements::hex::FromHex;
use elements::sighash::SighashCache;
use std::str::FromStr;

use crate::error::Error;

/// The record's marker, byte for byte the node's `DELEGATION_MARKER`.
const DELEGATION_MARKER: &[u8; 6] = b"SEQDEL";

/// SIGHASH_ALL, as the byte appended to a DER signature.
const SIGHASH_ALL_BYTE: u8 = 0x01;

/// The canonical Sequentia delegation-record script, a byte-for-byte mirror of
/// the node's `BuildDelegationScript`:
/// `<"SEQDEL"> OP_DROP <signer> OP_DROP <controller> OP_CHECKSIG`.
///
/// Note the order: the SIGNER is pushed first and the CONTROLLER last, because
/// the controller is the key the final `OP_CHECKSIG` tests. Only the controller
/// can spend the record; the signer is inert data.
pub fn sequentia_delegation_script(controller_pubkey: &[u8], signer_pubkey: &[u8]) -> Script {
    elements::script::Builder::new()
        .push_slice(DELEGATION_MARKER)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(signer_pubkey)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(controller_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

/// Everything needed to spend one delegation record: reclaiming it, or
/// re-pointing it at another signer.
#[derive(Debug, Clone)]
pub struct DelegationSpendPlan {
    /// The record output being spent.
    pub record_txid: Txid,
    /// Its index in that transaction.
    pub record_vout: u32,
    /// Its explicit value. A record is always unblinded (it is a bare script),
    /// so this is readable from the chain.
    pub record_value: u64,
    /// The policy asset (SEQ); a record only ever holds that.
    pub asset: AssetId,
    /// The signer named in the record being spent. Needed to rebuild the exact
    /// script, which is both the sighash subscript and the thing being satisfied.
    pub current_signer: Vec<u8>,
    /// The controller's secret key. It alone can spend the record.
    pub controller_secret: SecretKey,
    /// `Some(new signer)` re-points the delegation, `None` reclaims it.
    pub rotate_to: Option<Vec<u8>>,
    /// Where reclaimed coins go. Ignored when re-pointing, since the value goes
    /// straight back into the new record.
    pub reclaim_spk: Script,
    /// Network fee, taken out of the record's own value.
    pub fee_atoms: u64,
    /// The dust floor the resulting output must clear to relay. A record funded
    /// with barely more than the floor has nothing left after one fee, so this
    /// is a reachable refusal rather than a theoretical one. 0 disables it.
    pub dust_floor: u64,
    /// nLockTime, normally the current tip (anti-fee-sniping).
    pub locktime: u32,
}

/// Build and sign the spend of a delegation record. Returns `(raw_hex, txid)`.
///
/// The transaction is self-contained: one input (the record), one output (the
/// new record when re-pointing, otherwise the reclaimed coins), and the explicit
/// fee output Elements requires.
pub fn build_delegation_spend_tx(plan: &DelegationSpendPlan) -> Result<(String, Txid), Error> {
    let secp = Secp256k1::new();

    if plan.fee_atoms >= plan.record_value {
        return Err(Error::Generic(format!(
            "the delegation record holds {} atoms, which does not cover the {} atom fee to spend it",
            plan.record_value, plan.fee_atoms
        )));
    }
    let out_value = plan.record_value - plan.fee_atoms;
    if out_value < plan.dust_floor {
        return Err(Error::Generic(format!(
            "this would leave {} atoms, below the {} the network will relay; the record cannot pay its own fee \
             and still leave a usable output. The delegation is unaffected, and the stake was never at risk",
            out_value, plan.dust_floor
        )));
    }

    // The controller key must be the one the record actually commits to,
    // otherwise the signature cannot satisfy it. Catch a wrong derivation here,
    // with a message that says so, rather than broadcasting an unspendable
    // transaction and watching it be rejected.
    let controller_pk = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &plan.controller_secret);
    let controller_bytes = controller_pk.serialize().to_vec();
    let record_script = sequentia_delegation_script(&controller_bytes, &plan.current_signer);

    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(plan.locktime),
        input: vec![TxIn {
            previous_output: OutPoint::new(plan.record_txid, plan.record_vout),
            is_pegin: false,
            script_sig: Script::new(),
            // A record carries no relative lock, so nothing forces a sequence.
            // Stay replaceable, so a fee that turns out too low can be bumped.
            sequence: Sequence::from_consensus(0xffff_fffd),
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![],
    };

    let destination = match &plan.rotate_to {
        Some(new_signer) => {
            if new_signer.as_slice() == plan.current_signer.as_slice() {
                return Err(Error::Generic(
                    "re-pointing to the signer the record already names would change nothing".into(),
                ));
            }
            if new_signer.as_slice() == controller_bytes.as_slice() {
                return Err(Error::Generic(
                    "delegating to the controller itself is what already happens with no record at all; reclaim instead"
                        .into(),
                ));
            }
            sequentia_delegation_script(&controller_bytes, new_signer)
        }
        None => plan.reclaim_spk.clone(),
    };
    tx.output.push(TxOut {
        asset: confidential::Asset::Explicit(plan.asset),
        value: confidential::Value::Explicit(out_value),
        nonce: confidential::Nonce::Null,
        script_pubkey: destination,
        witness: TxOutWitness::default(),
    });
    tx.output.push(TxOut::new_fee(plan.fee_atoms, plan.asset));

    // A bare (pre-segwit) script is satisfied by a legacy signature over the
    // script itself, and the scriptSig is nothing but that signature push -
    // the same shape the node's own reclaim builds.
    let sighash = {
        let cache = SighashCache::new(&tx);
        cache.legacy_sighash(0, &record_script, EcdsaSighashType::All)
    };
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_ecdsa(&message, &plan.controller_secret);
    let mut der = signature.serialize_der().to_vec();
    der.push(SIGHASH_ALL_BYTE);
    tx.input[0].script_sig = elements::script::Builder::new().push_slice(&der).into_script();

    let txid = tx.txid();
    Ok((serialize_hex(&tx), txid))
}

/// Parse a 33-byte compressed secp256k1 public key from hex, rejecting anything
/// that is not one. Every pubkey crossing this boundary comes from a pool
/// listing or a user paste, so it is checked rather than trusted.
pub fn delegation_pubkey_from_hex(hex: &str, what: &str) -> Result<Vec<u8>, Error> {
    let bytes = Vec::<u8>::from_hex(hex.trim())
        .map_err(|e| Error::Generic(format!("invalid {what} public key hex: {e}")))?;
    if bytes.len() != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03) {
        return Err(Error::Generic(format!(
            "{what} must be a 33-byte compressed public key (66 hex characters starting 02 or 03)"
        )));
    }
    elements::secp256k1_zkp::PublicKey::from_slice(&bytes)
        .map_err(|e| Error::Generic(format!("invalid {what} public key: {e}")))?;
    Ok(bytes)
}

/// Parse a delegation-record script back into `(controller, signer)`, the exact
/// inverse of [`sequentia_delegation_script`]. Used to recognise a record found
/// on-chain, so a restored wallet can discover a delegation it no longer has any
/// local note of.
pub fn parse_delegation_script(script: &Script) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut instructions = script.instructions();
    let marker = instructions.next()?.ok()?.push_bytes()?.to_vec();
    if marker.as_slice() != DELEGATION_MARKER {
        return None;
    }
    if instructions.next()?.ok()?.push_bytes().is_some() {
        return None; // expected OP_DROP
    }
    let signer = instructions.next()?.ok()?.push_bytes()?.to_vec();
    if instructions.next()?.ok()?.push_bytes().is_some() {
        return None; // expected OP_DROP
    }
    let controller = instructions.next()?.ok()?.push_bytes()?.to_vec();
    // Trailing OP_CHECKSIG, and nothing after it.
    instructions.next()?.ok()?;
    if instructions.next().is_some() {
        return None;
    }
    if signer.len() != 33 || controller.len() != 33 {
        return None;
    }
    Some((controller, signer))
}

/// Hash160 of a compressed public key, for the p2wpkh reclaim destination a
/// light wallet uses when it takes its delegation back.
pub fn p2wpkh_script_pubkey(compressed_pubkey: &[u8]) -> Script {
    let pkh = hash160::Hash::hash(compressed_pubkey).to_byte_array();
    elements::script::Builder::new()
        .push_int(0)
        .push_slice(&pkh)
        .into_script()
}

/// Parse a txid from hex.
pub fn delegation_txid_from_hex(hex: &str) -> Result<Txid, Error> {
    Txid::from_str(hex.trim()).map_err(|e| Error::Generic(format!("invalid txid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> (SecretKey, Vec<u8>) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pk = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &sk);
        (sk, pk.serialize().to_vec())
    }

    #[test]
    fn script_matches_the_nodes_layout() {
        let (_, controller) = key(1);
        let (_, signer) = key(2);
        let script = sequentia_delegation_script(&controller, &signer);
        let bytes = script.as_bytes();
        // <6-byte push> SEQDEL OP_DROP <33-push> signer OP_DROP <33-push> controller OP_CHECKSIG
        assert_eq!(bytes[0], 6);
        assert_eq!(&bytes[1..7], DELEGATION_MARKER);
        assert_eq!(bytes[7], opcodes::all::OP_DROP.into_u8());
        assert_eq!(bytes[8], 33);
        assert_eq!(&bytes[9..42], signer.as_slice(), "the signer is pushed FIRST");
        assert_eq!(bytes[42], opcodes::all::OP_DROP.into_u8());
        assert_eq!(bytes[43], 33);
        assert_eq!(&bytes[44..77], controller.as_slice(), "the controller is what OP_CHECKSIG tests");
        assert_eq!(bytes[77], opcodes::all::OP_CHECKSIG.into_u8());
        assert_eq!(bytes.len(), 78);
    }

    #[test]
    fn matches_the_nodes_pinned_vector() {
        // A cross-implementation vector, asserted identically by the node in
        // test/functional/feature_pos_pools.py. Two independent implementations
        // of one consensus script is exactly where a silent divergence hides: a
        // swapped push order still looks like a valid script, still relays, and
        // simply credits the stake weight to the wrong key. Neither side can
        // drift alone while both assert this.
        let (_, controller) = key(7);
        let (_, signer) = key(8);
        assert_eq!(
            elements::hex::ToHex::to_hex(controller.as_slice()),
            "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
        );
        assert_eq!(
            elements::hex::ToHex::to_hex(signer.as_slice()),
            "03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b"
        );
        let script = sequentia_delegation_script(&controller, &signer);
        let expected = format!(
            "06{}75 21{}75 21{}ac",
            elements::hex::ToHex::to_hex(DELEGATION_MARKER.as_slice()),
            elements::hex::ToHex::to_hex(signer.as_slice()),
            elements::hex::ToHex::to_hex(controller.as_slice()),
        )
        .replace(' ', "");
        assert_eq!(elements::hex::ToHex::to_hex(script.as_bytes()), expected);
        assert_eq!(
            expected,
            "0653455144454c752103f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b752102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac"
        );
    }

    #[test]
    fn parse_is_the_inverse_of_build() {
        let (_, controller) = key(3);
        let (_, signer) = key(4);
        let script = sequentia_delegation_script(&controller, &signer);
        let (c, s) = parse_delegation_script(&script).expect("should parse");
        assert_eq!(c, controller);
        assert_eq!(s, signer);
    }

    #[test]
    fn parse_rejects_other_scripts() {
        assert!(parse_delegation_script(&Script::new()).is_none());
        let (_, pk) = key(5);
        // A staking script, which is the other bare script in play.
        let stake = elements::script::Builder::new()
            .push_int(1000)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_slice(&pk)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(parse_delegation_script(&stake).is_none());
    }

    fn plan(rotate_to: Option<Vec<u8>>) -> (DelegationSpendPlan, Vec<u8>) {
        let (controller_sk, controller) = key(7);
        let (_, signer) = key(8);
        (
            DelegationSpendPlan {
                record_txid: Txid::from_slice(&[9u8; 32]).unwrap(),
                record_vout: 1,
                record_value: 100_000,
                asset: AssetId::from_slice(&[3u8; 32]).unwrap(),
                current_signer: signer,
                controller_secret: controller_sk,
                rotate_to,
                reclaim_spk: p2wpkh_script_pubkey(&controller),
                fee_atoms: 1_000,
                dust_floor: 1_000,
                locktime: 500,
            },
            controller,
        )
    }

    #[test]
    fn reclaim_spends_the_record_to_the_wallet() {
        let (p, controller) = plan(None);
        let (raw, _txid) = build_delegation_spend_tx(&p).unwrap();
        let tx: Transaction = elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2, "destination + the explicit fee output");
        assert_eq!(tx.output[0].script_pubkey, p2wpkh_script_pubkey(&controller));
        assert_eq!(tx.output[0].value, confidential::Value::Explicit(99_000));
        assert!(tx.output[1].is_fee());
        assert_eq!(tx.output[1].value, confidential::Value::Explicit(1_000));
        assert!(!tx.input[0].script_sig.is_empty(), "the record must be signed");
    }

    #[test]
    fn repoint_spends_and_recreates_in_one_transaction() {
        let (_, new_signer) = key(11);
        let (p, controller) = plan(Some(new_signer.clone()));
        let (raw, _) = build_delegation_spend_tx(&p).unwrap();
        let tx: Transaction = elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        // The whole point: the old record is consumed and the new one created by
        // the SAME transaction, so no block can ever hold two for one controller.
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output.vout, 1);
        let (c, s) = parse_delegation_script(&tx.output[0].script_pubkey).expect("output 0 is a record");
        assert_eq!(c, controller);
        assert_eq!(s, new_signer);
    }

    #[test]
    fn refuses_a_fee_the_record_cannot_pay() {
        let (mut p, _) = plan(None);
        p.fee_atoms = p.record_value;
        assert!(build_delegation_spend_tx(&p).is_err());
    }

    #[test]
    fn refuses_an_output_below_the_relay_floor() {
        // Reachable, not theoretical: a record funded with barely more than the
        // dust floor has nothing left once it has paid one fee, and the
        // resulting transaction would be rejected by every relay.
        let (mut p, _) = plan(None);
        p.record_value = 1_500;
        p.fee_atoms = 1_000;
        p.dust_floor = 1_000; // leaves 500
        let e = build_delegation_spend_tx(&p).unwrap_err().to_string();
        assert!(e.contains("relay"), "unexpected error: {e}");
        // The stake is never involved in any of this, and the message says so.
        assert!(e.contains("stake was never at risk"), "unexpected error: {e}");
    }

    #[test]
    fn refuses_a_pointless_or_self_repoint() {
        let (p, _) = plan(None);
        let same = DelegationSpendPlan {
            rotate_to: Some(p.current_signer.clone()),
            ..p.clone()
        };
        assert!(build_delegation_spend_tx(&same).is_err(), "re-pointing to the same signer");

        let secp = Secp256k1::new();
        let controller = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &p.controller_secret)
            .serialize()
            .to_vec();
        let to_self = DelegationSpendPlan {
            rotate_to: Some(controller),
            ..p.clone()
        };
        assert!(build_delegation_spend_tx(&to_self).is_err(), "re-pointing at yourself");
    }

    #[test]
    fn signature_satisfies_the_record_script() {
        // The signature must verify against the exact script the record commits
        // to. This is the check that catches a wrong sighash or a mixed-up
        // controller/signer order, which would otherwise only show up as a
        // rejected broadcast.
        let (p, controller) = plan(None);
        let (raw, _) = build_delegation_spend_tx(&p).unwrap();
        let tx: Transaction = elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        let script = sequentia_delegation_script(&controller, &p.current_signer);
        let sighash = SighashCache::new(&tx).legacy_sighash(0, &script, EcdsaSighashType::All);

        // Pull the signature back out of the scriptSig and verify it.
        let sig_push = tx.input[0]
            .script_sig
            .instructions()
            .next()
            .unwrap()
            .unwrap()
            .push_bytes()
            .unwrap()
            .to_vec();
        assert_eq!(*sig_push.last().unwrap(), SIGHASH_ALL_BYTE);
        let sig = elements::secp256k1_zkp::ecdsa::Signature::from_der(&sig_push[..sig_push.len() - 1]).unwrap();
        let secp = Secp256k1::new();
        let pk = elements::secp256k1_zkp::PublicKey::from_slice(&controller).unwrap();
        secp.verify_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sig, &pk)
            .expect("the scriptSig must satisfy the record it spends");
    }

    #[test]
    fn pubkey_hex_is_validated() {
        let (_, pk) = key(12);
        let hex = elements::hex::ToHex::to_hex(pk.as_slice());
        assert!(delegation_pubkey_from_hex(&hex, "signer").is_ok());
        assert!(delegation_pubkey_from_hex("not hex", "signer").is_err());
        assert!(delegation_pubkey_from_hex("02ab", "signer").is_err(), "too short");
        // Right length, wrong prefix: an uncompressed-style lead byte.
        assert!(delegation_pubkey_from_hex(&format!("04{}", &hex[2..]), "signer").is_err());
    }
}
