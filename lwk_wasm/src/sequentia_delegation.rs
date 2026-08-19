//! SEQUENTIA staking pools, for the browser and mobile wallets: join a pool,
//! move between pools, and leave one.
//!
//! Creating a delegation record is an ordinary payment to a bare script, which
//! the PSET builder already handles (`TxBuilder.addDelegationOutput`). Spending
//! one is not: a bare pre-segwit script matches no descriptor, so the wallet's
//! own signer will not touch it. `buildDelegationSpendTx` is that missing half,
//! and shipping the first without it would let a wallet join a pool it could
//! never leave, turning the property that makes delegation safe into a promise
//! the wallet cannot keep.
//!
//! Note what is deliberately NOT here: announcing a payout policy, which is what
//! turns a staker into a pool anyone should join. That binds every block a key
//! ever produces and requires being online with the signing key on the machine
//! producing them, so it belongs to the node wallet and is offered only there.

use lwk_wollet::bitcoin::bip32;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::sequentia_delegation::{
    build_delegation_spend_tx, delegation_pubkey_from_hex, delegation_txid_from_hex,
    sequentia_delegation_script, DelegationSpendPlan,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{Error, Network};

/// Build the canonical Sequentia delegation-record script for a 33-byte hex
/// controller and signer; returns the scriptPubKey as hex. Cross-checked
/// byte-for-byte against the node's `getdelegationscript`, and pinned by a
/// shared test vector on both sides.
#[wasm_bindgen(js_name = sequentiaDelegationScript)]
pub fn sequentia_delegation_script_js(controller: &str, signer: &str) -> Result<String, Error> {
    let c = delegation_pubkey_from_hex(controller, "controller")?;
    let s = delegation_pubkey_from_hex(signer, "signer")?;
    Ok(sequentia_delegation_script(&c, &s).as_bytes().to_hex())
}

/// Read a delegation record back out of a scriptPubKey hex, returning
/// `{ controller, signer }`, or `null` if the script is not one.
///
/// This is how a wallet finds a delegation it has no local note of, which is the
/// case that matters: restore a seed on a new device and the record is still
/// out there lending your weight to a pool. Scanning the wallet's own history
/// for a script this recognises needs no index, no extra service and no pool
/// list, because the transaction that funded the record spent this wallet's
/// coins and is therefore in its history.
#[wasm_bindgen(js_name = parseDelegationScript)]
pub fn parse_delegation_script_js(script_hex: &str) -> Result<JsValue, Error> {
    let bytes = Vec::<u8>::from_hex(script_hex.trim())
        .map_err(|e| Error::Generic(format!("invalid script hex: {e}")))?;
    let script = lwk_wollet::elements::Script::from(bytes);
    match lwk_wollet::sequentia_delegation::parse_delegation_script(&script) {
        None => Ok(JsValue::NULL),
        Some((controller, signer)) => Ok(serde_wasm_bindgen::to_value(&ParsedDelegation {
            controller: controller.to_hex(),
            signer: signer.to_hex(),
        })?),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParsedDelegation {
    controller: String,
    signer: String,
}

/// Every delegation record in `tx_hex` naming `controller` as its controller,
/// as `[{ vout, signer, value }]`.
///
/// This is how a wallet finds a delegation it has no local note of, which is
/// the case that matters: restore a seed on another device and the record is
/// still out there lending your weight to a pool. The wallet does not hold the
/// record as one of its own coins (a bare script matches no descriptor), but
/// the transaction that FUNDED it spent this wallet's coins and is therefore in
/// its history, so scanning that history finds it with no index, no pool list
/// and no stored state. Whether it is still unspent is a separate question only
/// the explorer can answer, because a transaction spending a bare script need
/// not touch this wallet at all.
#[wasm_bindgen(js_name = findDelegationRecords)]
pub fn find_delegation_records_js(tx_hex: &str, controller: &str) -> Result<JsValue, Error> {
    let want = delegation_pubkey_from_hex(controller, "controller")?;
    let bytes = Vec::<u8>::from_hex(tx_hex.trim())
        .map_err(|e| Error::Generic(format!("invalid transaction hex: {e}")))?;
    let tx: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(&bytes)
        .map_err(|e| Error::Generic(format!("could not decode the transaction: {e}")))?;

    let mut found = Vec::new();
    for (vout, out) in tx.output.iter().enumerate() {
        let parsed = lwk_wollet::sequentia_delegation::parse_delegation_script(&out.script_pubkey);
        let (controller_bytes, signer_bytes) = match parsed {
            Some(p) => p,
            None => continue,
        };
        if controller_bytes != want {
            continue;
        }
        // A record is always explicit; a blinded one would carry no readable
        // value and could not be spent by this path anyway.
        let value = match out.value {
            lwk_wollet::elements::confidential::Value::Explicit(v) => v,
            _ => continue,
        };
        found.push(FoundDelegationRecord {
            vout: vout as u32,
            signer: signer_bytes.to_hex(),
            // A string: a JS number cannot hold 64 bits without silently rounding.
            value: value.to_string(),
        });
    }
    Ok(serde_wasm_bindgen::to_value(&found)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FoundDelegationRecord {
    vout: u32,
    signer: String,
    value: String,
}

/// Everything needed to spend a delegation record, as JSON from the wallet.
///
/// `rotateTo` decides which of the two spends this is: present re-points the
/// delegation at a new signer, absent reclaims it to `reclaimAddress`. Both are
/// one self-contained transaction paying its fee out of the record's own value,
/// so neither needs the wallet to select a coin.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DelegationSpendRecipeJson {
    mnemonic: String,
    /// The record output being spent.
    record_txid: String,
    record_vout: u32,
    /// Its explicit value in atoms, as a string (JS numbers cannot hold 64 bits).
    record_value: String,
    /// The signer the record currently names. Needed to rebuild the exact script
    /// being satisfied.
    current_signer: String,
    /// Present: re-point at this signer. Absent: reclaim.
    #[serde(default)]
    rotate_to: Option<String>,
    /// Where the reclaimed coins go. Required unless re-pointing.
    #[serde(default)]
    reclaim_address: Option<String>,
    /// Network fee in atoms, taken out of the record.
    fee_atoms: String,
    /// nLockTime, normally the current tip.
    locktime: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltDelegationTx {
    raw_hex: String,
    txid: String,
    /// What the record will hold afterwards (re-point), or what comes back to
    /// the wallet (reclaim). Atoms, as a string.
    out_value: String,
    /// True when this re-points rather than reclaims, so the caller can say the
    /// right thing without re-deriving it.
    repointed: bool,
}

/// Build and sign the spend of a delegation record. Returns
/// `{ rawHex, txid, outValue, repointed }`.
#[wasm_bindgen(js_name = buildDelegationSpendTx)]
pub fn build_delegation_spend_tx_js(recipe: JsValue, network: &Network) -> Result<JsValue, Error> {
    let r: DelegationSpendRecipeJson = serde_wasm_bindgen::from_value(recipe)?;

    let signer = crate::Signer::new(&crate::Mnemonic::new(&r.mnemonic)?, network)?;
    // The controller is this wallet's staking key, m/2/0, the same key
    // Signer.stakerPublicKey() hands out and the same one the stake itself is
    // registered to. Only it can spend the record.
    let path = bip32::DerivationPath::from(vec![
        bip32::ChildNumber::Normal { index: 2 },
        bip32::ChildNumber::Normal { index: 0 },
    ]);
    let xprv = signer
        .inner
        .derive_xprv(&path)
        .map_err(|e| Error::Generic(format!("derive staking key: {e}")))?;
    let controller_secret =
        lwk_wollet::elements::secp256k1_zkp::SecretKey::from_slice(&xprv.private_key.secret_bytes())
            .map_err(|e| Error::Generic(format!("invalid staking key: {e}")))?;

    let current_signer = delegation_pubkey_from_hex(&r.current_signer, "current signer")?;
    let rotate_to = match r.rotate_to.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(delegation_pubkey_from_hex(s, "new signer")?),
        _ => None,
    };

    // A reclaim with nowhere to go would burn the record's value to fees, so
    // require the destination rather than inventing one.
    let reclaim_spk = match (&rotate_to, r.reclaim_address.as_deref()) {
        (Some(_), _) => lwk_wollet::elements::Script::new(),
        (None, Some(a)) if !a.trim().is_empty() => {
            let addr: lwk_wollet::elements::Address = a
                .trim()
                .parse()
                .map_err(|e| Error::Generic(format!("invalid reclaim address: {e}")))?;
            addr.script_pubkey()
        }
        (None, _) => {
            return Err(Error::Generic(
                "reclaiming a delegation needs a reclaimAddress to send its coins to".into(),
            ))
        }
    };

    let plan = DelegationSpendPlan {
        record_txid: delegation_txid_from_hex(&r.record_txid)?,
        record_vout: r.record_vout,
        record_value: r
            .record_value
            .trim()
            .parse()
            .map_err(|_| Error::Generic("recordValue must be an integer number of atoms".into()))?,
        asset: network.policy_asset().into(),
        current_signer,
        controller_secret,
        rotate_to: rotate_to.clone(),
        reclaim_spk,
        fee_atoms: r
            .fee_atoms
            .trim()
            .parse()
            .map_err(|_| Error::Generic("feeAtoms must be an integer number of atoms".into()))?,
        // Elements' default dust relay fee over the ~200-byte spend-and-output
        // pair a record produces. Refusing here beats a broadcast rejection the
        // wallet would have to explain after the fact.
        dust_floor: 1_000,
        locktime: r.locktime,
    };
    let out_value = plan.record_value.saturating_sub(plan.fee_atoms);
    let (raw_hex, txid) = build_delegation_spend_tx(&plan)?;
    Ok(serde_wasm_bindgen::to_value(&BuiltDelegationTx {
        raw_hex,
        txid: txid.to_string(),
        out_value: out_value.to_string(),
        repointed: rotate_to.is_some(),
    })?)
}
