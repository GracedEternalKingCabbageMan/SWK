//! Bitcoin parent-chain (testnet4) HTLC leg for cross-chain SeqDEX swaps.
//!
//! The wallet is Alice (the secret holder): she funds the BTC HTLC, the maker
//! (Bob) claims it by revealing the preimage, and Alice refunds via the CLTV
//! branch if Bob never claims.
//!
//!   OP_IF  OP_SHA256 <H> OP_EQUALVERIFY <claimPub> OP_CHECKSIG
//!   OP_ELSE  <locktime> OP_CLTV OP_DROP <refundPub> OP_CHECKSIG
//!   OP_ENDIF                                            (paid to a bare P2SH)
//!
//! The redeemScript is NOT rebuilt here: it delegates to the kit's single
//! chain-agnostic source [`crate::build_htlc_redeem_script`] (the
//! daemon-parity-proven SEQ builder), so the BTC and SEQ legs are byte-identical
//! by construction. The refund spend uses a legacy SIGHASH_ALL over the
//! redeemScript and a hand-built scriptSig `<sig> OP_0 <redeemScript>` to select
//! the ELSE branch (a generic signer won't template the OP_0 selector). The BTC
//! claim is Bob's path and is not built here.

use std::str::FromStr;

use crate::bitcoin::absolute::LockTime;
use crate::bitcoin::consensus::encode::serialize_hex;
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::script::{Builder, PushBytes};
use crate::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use crate::bitcoin::sighash::SighashCache;
use crate::bitcoin::transaction::Version;
use crate::bitcoin::{
    opcodes, Address, Amount, EcdsaSighashType, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};

use crate::error::Error;

fn map<E: std::fmt::Debug>(e: E) -> Error {
    Error::Generic(format!("{e:?}"))
}

fn push_bytes(b: &[u8]) -> Result<&PushBytes, Error> {
    <&PushBytes>::try_from(b).map_err(map)
}

/// Build the BTC-leg HTLC redeemScript as a bitcoin [`ScriptBuf`].
///
/// Delegates to the kit's single source [`crate::build_htlc_redeem_script`] and
/// wraps its bytes, so the BTC leg is byte-identical to the SEQ leg (and the
/// daemon) by construction — not by a coincidentally-matching second builder.
pub fn build_htlc_redeem_script(
    hash: &[u8],
    claim_pub: &[u8],
    refund_pub: &[u8],
    locktime: u32,
) -> Result<ScriptBuf, Error> {
    let seq = crate::build_htlc_redeem_script(hash, claim_pub, refund_pub, locktime)?;
    Ok(ScriptBuf::from_bytes(seq.as_bytes().to_vec()))
}

/// The bare-P2SH address + scriptPubKey for an HTLC redeemScript, on testnet
/// (testnet `2…` base58 P2SH; the version byte is shared with testnet4). The
/// wallet funds this address and locates the funding output by matching this spk.
pub fn htlc_p2sh(redeem: &ScriptBuf) -> Result<(Address, ScriptBuf), Error> {
    let address = Address::p2sh(redeem, Network::Testnet).map_err(map)?;
    Ok((address, redeem.to_p2sh()))
}

/// A spend of an HTLC P2SH output: the funding outpoint, its value, where the
/// refund pays, and the fee to subtract.
pub struct BtcHtlcSpend {
    /// Funding txid (the HTLC outpoint).
    pub txid: String,
    /// Funding vout of the HTLC P2SH output.
    pub vout: u32,
    /// Value of the HTLC output, in sats.
    pub amount_sats: u64,
    /// scriptPubKey the refund pays to.
    pub dest_spk: ScriptBuf,
    /// Fee to subtract from the HTLC amount, in sats.
    pub fee_sats: u64,
}

/// Build + sign the BTC refund: a legacy P2SH spend of the HTLC via the ELSE/CLTV
/// branch, paying `amount - fee` to `dest_spk`. Only valid once the chain tip
/// reaches `locktime` (CLTV). Returns the raw tx hex to broadcast.
///
/// The scriptSig is `<sig> OP_0 <redeemScript>`: the empty (false) item selects
/// the OP_ELSE branch, and the redeemScript push is what P2SH executes. The
/// sighash is a LEGACY SIGHASH_ALL over the redeemScript (not the P2SH spk).
pub fn build_refund_tx(
    redeem: &ScriptBuf,
    spend: &BtcHtlcSpend,
    locktime: u32,
    refund_sk: &SecretKey,
) -> Result<String, Error> {
    let out_value = spend
        .amount_sats
        .checked_sub(spend.fee_sats)
        .ok_or_else(|| Error::Generic("fee exceeds the HTLC amount".into()))?;
    if out_value == 0 {
        return Err(Error::Generic("refund output is zero after fee".into()));
    }
    let txid = Txid::from_str(&spend.txid).map_err(map)?;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: spend.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffe), // non-final (BIP68 disabled) so absolute CLTV applies
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(out_value), script_pubkey: spend.dest_spk.clone() }],
    };
    // Legacy SIGHASH_ALL over the redeemScript (the subscript), computed while the
    // cache borrows &tx; then drop it before mutating the input's scriptSig.
    let sighash = SighashCache::new(&tx)
        .legacy_signature_hash(0, redeem, EcdsaSighashType::All.to_u32())
        .map_err(map)?;
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), refund_sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8); // 0x01

    tx.input[0].script_sig = Builder::new()
        .push_slice(push_bytes(&sig_bytes)?)
        .push_opcode(opcodes::all::OP_PUSHBYTES_0) // OP_0 / false -> selects the ELSE/CLTV branch
        .push_slice(push_bytes(redeem.as_bytes())?)
        .into_script();
    Ok(serialize_hex(&tx))
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::consensus::encode::deserialize;
    use crate::bitcoin::hex::FromHex;
    use crate::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use crate::bitcoin::Transaction;

    fn pubkey(byte: u8) -> [u8; 33] {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        sk.public_key(&secp).serialize()
    }

    // The fund-safety chain rests on the BTC redeemScript being byte-identical to
    // the daemon's. The kit's `build_htlc_redeem_script` is the single proven
    // source; confirm the BTC wrapper reproduces its bytes exactly.
    #[test]
    fn btc_redeem_matches_seq_builder() {
        let hash = [0x11u8; 32];
        let claim = pubkey(2);
        let refund = pubkey(3);
        let locktime = 1_234_567u32;

        let btc = super::build_htlc_redeem_script(&hash, &claim, &refund, locktime).unwrap();
        let seq = crate::build_htlc_redeem_script(&hash, &claim, &refund, locktime).unwrap();
        assert_eq!(btc.as_bytes(), seq.as_bytes(), "BTC HTLC script must byte-match the SEQ/daemon script");

        let (addr, spk) = super::htlc_p2sh(&btc).unwrap();
        assert!(addr.to_string().starts_with('2'), "testnet P2SH base58 starts with 2, got {addr}");
        assert_eq!(spk.as_bytes()[0], 0xa9, "P2SH spk starts with OP_HASH160");
    }

    #[test]
    fn refund_tx_shape() {
        let secp = Secp256k1::new();
        let refund_sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let refund_pub = refund_sk.public_key(&secp).serialize();
        let redeem = super::build_htlc_redeem_script(&[0x22u8; 32], &pubkey(2), &refund_pub, 800_000).unwrap();
        let dest_spk = super::htlc_p2sh(&redeem).unwrap().1; // any spk for the structural check
        let spend = super::BtcHtlcSpend {
            txid: "a".repeat(64),
            vout: 1,
            amount_sats: 50_000,
            dest_spk,
            fee_sats: 2_000,
        };
        let hex = super::build_refund_tx(&redeem, &spend, 800_000, &refund_sk).unwrap();
        let raw = Vec::<u8>::from_hex(&hex).unwrap();
        let tx: Transaction = deserialize(&raw).unwrap();
        assert_eq!(tx.version, super::Version::TWO);
        assert_eq!(tx.lock_time.to_consensus_u32(), 800_000); // CLTV enforced
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].sequence.0, 0xffff_fffe); // non-final
        assert!(tx.input[0].witness.is_empty()); // legacy P2SH, no witness
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 48_000); // amount - fee
        assert!(!tx.input[0].script_sig.is_empty());
    }

    #[test]
    fn refund_rejects_fee_over_amount() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let redeem =
            super::build_htlc_redeem_script(&[0x22u8; 32], &pubkey(2), &sk.public_key(&secp).serialize(), 1).unwrap();
        let spend = super::BtcHtlcSpend {
            txid: "a".repeat(64),
            vout: 0,
            amount_sats: 1_000,
            dest_spk: super::htlc_p2sh(&redeem).unwrap().1,
            fee_sats: 2_000,
        };
        assert!(super::build_refund_tx(&redeem, &spend, 1, &sk).is_err());
    }
}
