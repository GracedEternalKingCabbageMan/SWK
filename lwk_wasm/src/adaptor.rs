//! BIP340 Schnorr adaptor-signature wasm bindings.
//!
//! Thin `#[wasm_bindgen]` layer over `lwk_wollet::adaptor` (btc-atomic-swap-followup
//! §8), mirroring the shape of [`crate::openamp`]. Every argument and return value is
//! hex; no secret is ever logged. These are the four functions the swap venue and
//! wallet drive:
//!
//! - [`adaptor_sign`] (`adaptorSign`): pre-signature `â` locked to adaptor point `T`.
//! - [`adaptor_complete`] (`adaptorComplete`): completes `â` with `t` into a plain
//!   64-byte BIP340 signature.
//! - [`adaptor_extract`] (`adaptorExtract`): recovers `t` from `(σ, â)`.
//! - [`adaptor_verify`] (`adaptorVerify`): the seller's normative release gate.
//!
//! This is a security-critical, pending-audit primitive (spec §8); use on testnet
//! only until independently reviewed.

use lwk_wollet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use lwk_wollet::elements::hex::{FromHex, ToHex};
use wasm_bindgen::prelude::*;

use crate::Error;

fn hex32(field: &str, s: &str) -> Result<[u8; 32], Error> {
    let v = Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("invalid {field} hex: {e}")))?;
    v.try_into()
        .map_err(|_| Error::Generic(format!("{field} must be 32 bytes")))
}

fn parse_presig(s: &str) -> Result<[u8; lwk_wollet::PRESIG_LEN], Error> {
    let v =
        Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("invalid presig hex: {e}")))?;
    v.try_into().map_err(|_| {
        Error::Generic(format!(
            "pre-signature must be {} bytes (compressed R+T || ŝ)",
            lwk_wollet::PRESIG_LEN
        ))
    })
}

fn parse_sig(s: &str) -> Result<[u8; lwk_wollet::SIG_LEN], Error> {
    let v = Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("invalid sig hex: {e}")))?;
    v.try_into()
        .map_err(|_| Error::Generic(format!("signature must be {} bytes", lwk_wollet::SIG_LEN)))
}

/// `adaptorSign(privkey_hex, msg_hex, tPointHex) -> â` (spec §8).
///
/// - `privkey_hex`: the signer secret `d`, 64-hex (BIP340-normalized internally).
/// - `msg_hex`: the 32-byte sighash the pre-signature commits to, 64-hex.
/// - `t_point_hex`: the adaptor point `T = t·G`, 66-hex COMPRESSED sec1.
///
/// Returns the 65-byte pre-signature `â` (130-hex) `= compressed(R+T) || ŝ`.
/// Deterministic for fixed inputs (spec 0.4(4)).
#[wasm_bindgen(js_name = adaptorSign)]
pub fn adaptor_sign(
    privkey_hex: &str,
    msg_hex: &str,
    t_point_hex: &str,
) -> Result<String, Error> {
    let d = SecretKey::from_slice(&hex32("privkey", privkey_hex)?)
        .map_err(|e| Error::Generic(format!("invalid privkey: {e}")))?;
    let msg = hex32("msg", msg_hex)?;
    let t_point = PublicKey::from_slice(
        &Vec::<u8>::from_hex(t_point_hex)
            .map_err(|e| Error::Generic(format!("invalid T point hex: {e}")))?,
    )
    .map_err(|e| Error::Generic(format!("invalid T point: {e}")))?;
    let secp = Secp256k1::new();
    let presig = lwk_wollet::adaptor_sign(&secp, &d, &msg, &t_point)?;
    Ok(presig.to_hex())
}

/// `adaptorComplete(presig_hex, t_hex) -> σ` (spec §8).
///
/// Completes the pre-signature with the coupling secret `t` (64-hex) into a standard
/// 64-byte BIP340 signature (128-hex) that verifies byte-identically under stock
/// `secp256k1` schnorr verification.
#[wasm_bindgen(js_name = adaptorComplete)]
pub fn adaptor_complete(presig_hex: &str, t_hex: &str) -> Result<String, Error> {
    let presig = parse_presig(presig_hex)?;
    let t = SecretKey::from_slice(&hex32("t", t_hex)?)
        .map_err(|e| Error::Generic(format!("invalid t scalar: {e}")))?;
    let sig = lwk_wollet::adaptor_complete(&presig, &t)?;
    Ok(sig.to_hex())
}

/// `adaptorExtract(sig_hex, presig_hex) -> t` (spec §8).
///
/// Recovers the coupling secret `t` (64-hex) from the completed signature `σ`
/// (128-hex) and the pre-signature `â` (130-hex) it was completed from.
#[wasm_bindgen(js_name = adaptorExtract)]
pub fn adaptor_extract(sig_hex: &str, presig_hex: &str) -> Result<String, Error> {
    let sig = parse_sig(sig_hex)?;
    let presig = parse_presig(presig_hex)?;
    let t = lwk_wollet::adaptor_extract(&sig, &presig)?;
    Ok(t.to_hex())
}

/// `adaptorVerify(pubkey_xonly_hex, msg_hex, tPointHex, presig_hex) -> bool` (spec §8).
///
/// The seller's normative release gate: returns `true` only for a well-formed
/// pre-signature `â` that is valid under the buyer key `P` (64-hex x-only), message
/// `m` (64-hex), and adaptor point `T` (66-hex compressed). Returns `false` for any
/// tampered or malformed input; never throws for a bad `â`.
#[wasm_bindgen(js_name = adaptorVerify)]
pub fn adaptor_verify(
    pubkey_xonly_hex: &str,
    msg_hex: &str,
    t_point_hex: &str,
    presig_hex: &str,
) -> Result<bool, Error> {
    let p = XOnlyPublicKey::from_slice(&hex32("pubkey", pubkey_xonly_hex)?)
        .map_err(|e| Error::Generic(format!("invalid x-only pubkey: {e}")))?;
    let msg = hex32("msg", msg_hex)?;
    let t_point = PublicKey::from_slice(
        &Vec::<u8>::from_hex(t_point_hex)
            .map_err(|e| Error::Generic(format!("invalid T point hex: {e}")))?,
    )
    .map_err(|e| Error::Generic(format!("invalid T point: {e}")))?;
    let presig = parse_presig(presig_hex)?;
    let secp = Secp256k1::new();
    Ok(lwk_wollet::adaptor_verify(&secp, &p, &msg, &t_point, &presig))
}
