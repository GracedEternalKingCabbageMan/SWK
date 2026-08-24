//! Execution tests for the SeqOB cross-chain Sequentia-leg covenant
//! (`data/seqob_xchain_seqleg.simf`), design doc section 3.
//!
//! Each case builds a distinct `elements::Transaction`, wraps it in a CUSTOM
//! execution environment (via `ElementsEnv::new`, so we control the input's
//! `Sequence` and the tx `lock_time` for the CLTV refund leaf), and runs the
//! compiled covenant on the Simplicity BitMachine (the same evaluator as
//! consensus) through `lwk_simplicity::runner::run_program`.
//!
//!   Ok(..)  == the covenant ACCEPTS the spend.
//!   Err(..) == the covenant REJECTS the spend.
//!
//! CLAIM leaf (`witness::PATH = Left(preimage: u256)`, permissionless):
//!   * `sha256(preimage) == HASHLOCK`;
//!   * output 0 pays EXPLICIT `ASSET_A`, amount `>= AMOUNT_A`, to a scriptPubKey
//!     whose `SHA256 == CLAIMANT_SPK_HASH`;
//!   * hard-aborts on a blinded output 0 (`unwrap_right` on the confidential
//!     `Left`).
//!
//! REFUND leaf (`witness::PATH = Right(funder_sig: Signature)`):
//!   * absolute CLTV `check_lock_height(2000)`, THEN
//!   * `bip_0340_verify(FUNDER_PUBKEY, sig)` over `sig_all_hash()`.

use std::sync::Arc;

use lwk_simplicity::error::ProgramError;
use lwk_simplicity::runner::run_program;
use lwk_simplicity::scripts::{create_p2tr_address, load_program};

// Everything transaction/hash related MUST go through the re-exported `elements`
// / `simplicity` (the versions simplicity-lang pins) so the types line up with
// what the BitMachine / `ElementsEnv` expect.
use lwk_simplicity::simplicityhl::elements;
use lwk_simplicity::simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use lwk_simplicity::simplicityhl::simplicity::hashes::{sha256, Hash};
use lwk_simplicity::simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use lwk_simplicity::simplicityhl::simplicity::Cmr;
use lwk_simplicity::simplicityhl::tracker::TrackerLogLevel;
use lwk_simplicity::simplicityhl::{Arguments, WitnessValues};

use elements::confidential::{Asset, Nonce, Value as CValue};
use elements::secp256k1_zkp as zkp;
use elements::taproot::ControlBlock;
use elements::{
    AssetId, AssetIssuance, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness,
};

/// The covenant source, compiled fresh per case with the case's arguments.
const SEQOB_XCHAIN: &str = include_str!("../data/seqob_xchain_seqleg.simf");

/// Minimum credited payment of ASSET_A, in atoms (design doc AMOUNT_A).
const AMOUNT_A: u64 = 1000;

/// The refund CLTV height baked into the tapleaf (`T_SEQ` literal in the .simf).
const T_SEQ: u32 = 2000;

/// The 32-byte HTLC preimage from `htlc.simf`: 32 zero bytes.
/// `sha256([0u8;32]) == HASHLOCK`.
const KNOWN_HASHLOCK_HEX: &str =
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";

/// x-only internal key used for the Taproot substrate demonstration, and also
/// the FUNDER key on the refund leaf: the secp256k1 generator point G (== 1*G,
/// the x-only pubkey of the secret scalar 1). A valid on-curve x-only key.
const GENERATOR_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// The control block bytes used by the custom env (a well-formed 33-byte
/// Taproot control block; its contents do not affect the CLAIM leaf, and for the
/// REFUND leaf the signed message is derived from this SAME env, so it stays
/// self-consistent with what `sig_all_hash()` computes at runtime).
const CTRL_BLK: [u8; 33] = [
    0xc0, 0xeb, 0x04, 0xb6, 0x8e, 0x9a, 0x26, 0xd1, 0x16, 0x04, 0x6c, 0x76, 0xe8, 0xff, 0x47, 0x33,
    0x2f, 0xb7, 0x1d, 0xda, 0x90, 0xff, 0x4b, 0xef, 0x53, 0x70, 0xf2, 0x52, 0x26, 0xd3, 0xbc, 0x09,
    0xfc,
];

// A `'static` copy of the Elements address params, so we can hand a
// `&'static AddressParams` to `create_p2tr_address`.
static ELEMENTS_PARAMS: elements::AddressParams = elements::AddressParams::ELEMENTS;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// An explicit asset id as the `u256` argument the jets read: serialize
/// `Asset::Explicit(id)` (33 bytes) and take the trailing 32 (the leading
/// `0x01` is the explicit prefix). Byte-order-agnostic and consistent with
/// `output_amount`. (Verbatim from `seqob_partial.rs`.)
fn asset_u256_hex(asset_id: AssetId) -> String {
    let ser = elements::encode::serialize(&Asset::Explicit(asset_id));
    assert_eq!(ser.len(), 33, "explicit asset serializes to 33 bytes");
    assert_eq!(ser[0], 0x01, "explicit asset prefix is 0x01");
    format!("0x{}", hex_of(&ser[1..]))
}

/// `output_script_hash(i)` returns the PLAIN SHA-256 of the raw scriptPubKey
/// bytes (no tag, no length prefix). (Verbatim from `seqob_partial.rs`.)
fn spk_hash_u256_hex(spk: &Script) -> String {
    let h = sha256::Hash::hash(spk.as_bytes());
    format!("0x{}", hex_of(h.as_ref()))
}

/// The HTLC hashlock: `sha256([0u8;32])`, computed in-harness (not hardcoded),
/// then cross-checked against the known `htlc.simf` value.
fn hashlock_hex() -> String {
    let h = sha256::Hash::hash(&[0u8; 32]);
    let hex = hex_of(h.as_ref());
    assert_eq!(hex, KNOWN_HASHLOCK_HEX, "computed hashlock must match htlc.simf");
    format!("0x{}", hex)
}

fn asset_a() -> AssetId {
    AssetId::from_slice(&[0x0a; 32]).unwrap()
}

/// A different, distinct explicit asset (for the wrong-asset case).
fn other_asset() -> AssetId {
    AssetId::from_slice(&[0x0c; 32]).unwrap()
}

/// The claimant payout script (P2WPKH-shaped: OP_0 <20 bytes>). Output 0 must
/// pay to (the hash of) exactly this script.
fn claimant_script() -> Script {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xab; 20]);
    Script::from(v)
}

/// A different, non-matching script (wrong-claimant-script case).
fn other_script() -> Script {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xcd; 20]);
    Script::from(v)
}

/// The covenant's OWN scriptPubKey stand-in (P2TR-shaped: OP_1 <32 bytes>). The
/// spent input carries this; the CLAIM leaf never reads it, but the env needs a
/// UTXO for the input being spent.
fn covenant_spk() -> Script {
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(&[0x7e; 32]);
    Script::from(v)
}

/// The five `param::` arguments (HASHLOCK / ASSET_A / AMOUNT_A /
/// CLAIMANT_SPK_HASH / FUNDER_PUBKEY). Committed to `claimant_script()` and to
/// G's x-coordinate as the funder key.
fn build_args() -> Arguments {
    let json = format!(
        r#"{{
            "HASHLOCK":          {{ "value": "{hashlock}", "type": "u256" }},
            "ASSET_A":           {{ "value": "{asset_a}", "type": "u256" }},
            "AMOUNT_A":          {{ "value": "{amount_a}", "type": "u64" }},
            "CLAIMANT_SPK_HASH": {{ "value": "{spk}", "type": "u256" }},
            "FUNDER_PUBKEY":     {{ "value": "0x{funder}", "type": "Pubkey" }}
        }}"#,
        hashlock = hashlock_hex(),
        asset_a = asset_u256_hex(asset_a()),
        amount_a = AMOUNT_A,
        spk = spk_hash_u256_hex(&claimant_script()),
        funder = hex_of(&GENERATOR_X),
    );
    serde_json::from_str::<Arguments>(&json).expect("arguments JSON should parse")
}

/// A CLAIM witness: `witness::PATH = Left(<32-byte preimage>)`. The REFUND
/// (`Right`) leaf is pruned.
fn claim_witness(preimage: &[u8; 32]) -> WitnessValues {
    let json = format!(
        r#"{{ "PATH": {{ "value": "Left(0x{})", "type": "Either<u256, Signature>" }} }}"#,
        hex_of(preimage),
    );
    serde_json::from_str::<WitnessValues>(&json).expect("witness JSON should parse")
}

/// A REFUND witness: `witness::PATH = Right(<64-byte signature>)`. The CLAIM
/// (`Left`) leaf is pruned.
fn refund_witness(sig: &[u8; 64]) -> WitnessValues {
    let json = format!(
        r#"{{ "PATH": {{ "value": "Right(0x{})", "type": "Either<u256, Signature>" }} }}"#,
        hex_of(sig),
    );
    serde_json::from_str::<WitnessValues>(&json).expect("witness JSON should parse")
}

/// An EXPLICIT (asset, amount) output paying to `spk`.
fn mk_txout(asset: AssetId, value: u64, spk: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: CValue::Explicit(value),
        nonce: Nonce::default(),
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    }
}

/// A genuinely blinded (confidential) asset+value pair for the same asset/amount
/// (blinded-output case). The commitments are valid curve points; from the tx
/// environment's point of view the prefixes are non-`0x01`, so `output_amount`
/// yields the confidential `Left` and `unwrap_right` hard-aborts.
/// (Pattern from `seqob_covenant.rs`.)
fn mk_blinded_txout(asset_id: AssetId, value: u64, spk: Script) -> TxOut {
    let secp = zkp::Secp256k1::new();
    let generator = zkp::Generator::new_unblinded(&secp, asset_id.into_tag());
    let commitment = zkp::PedersenCommitment::new_unblinded(&secp, value, generator);
    TxOut {
        asset: Asset::Confidential(generator),
        value: CValue::Confidential(commitment),
        nonce: Nonce::default(),
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    }
}

/// A fee output (the covenant never reads it; present for realism).
fn fee_out() -> TxOut {
    TxOut::new_fee(500, asset_a())
}

/// Build a transaction with a single input at the given `sequence` and the given
/// `lock_time`, plus the supplied outputs.
fn mk_tx(lock_time: LockTime, sequence: Sequence, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            is_pegin: false,
            script_sig: Script::new(),
            sequence,
            asset_issuance: AssetIssuance::default(),
            witness: TxInWitness::default(),
        }],
        output: outputs,
    }
}

/// The covenant-owned UTXO for the single input (EXPLICIT ASSET_A on the
/// covenant script). Its details are irrelevant to both leaves, but the env
/// needs one UTXO per input.
fn covenant_utxo() -> ElementsUtxo {
    ElementsUtxo {
        script_pubkey: covenant_spk(),
        asset: Asset::Explicit(asset_a()),
        value: CValue::Explicit(AMOUNT_A),
    }
}

/// Build a CUSTOM environment for a single-input spend at index 0.
fn build_env(tx: Transaction) -> ElementsEnv<Arc<Transaction>> {
    ElementsEnv::new(
        Arc::new(tx),
        vec![covenant_utxo()],
        0,
        Cmr::from_byte_array([0; 32]),
        ControlBlock::from_slice(&CTRL_BLK).unwrap(),
        None,
        BlockHash::all_zeros(),
    )
}

/// Compile the covenant with the fixed args, run `witness` against `tx`,
/// return Ok (ACCEPT) / Err (REJECT).
fn run(tx: Transaction, witness: WitnessValues) -> Result<(), ProgramError> {
    let program = load_program(SEQOB_XCHAIN, build_args()).expect("covenant should compile");
    let env = build_env(tx);
    run_program(&program, witness, &env, TrackerLogLevel::None).map(|_| ())
}

/// A CLAIM transaction: output 0 = `(asset, amount, spk)`, output 1 = fee.
/// lock_time/sequence are irrelevant to the CLAIM leaf (final input, no CLTV).
fn claim_tx(output0: TxOut) -> Transaction {
    mk_tx(LockTime::ZERO, Sequence::MAX, vec![output0, fee_out()])
}

/// The correct 32-byte preimage (all zeros).
fn good_preimage() -> [u8; 32] {
    [0u8; 32]
}

// ---------------------------------------------------------------------------
// CLAIM path (the deliverable)
// ---------------------------------------------------------------------------

// 1. VALID CLAIM: correct preimage; output 0 = ASSET_A, AMOUNT_A, claimant script. ACCEPT.
#[test]
fn case1_valid_claim_accepts() {
    let tx = claim_tx(mk_txout(asset_a(), AMOUNT_A, claimant_script()));
    let r = run(tx, claim_witness(&good_preimage()));
    assert!(r.is_ok(), "VALID CLAIM must ACCEPT, got REJECT: {:?}", r.err());
}

// 2. OVERPAY: output 0 amount == AMOUNT_A + 1 (>= holds). ACCEPT.
#[test]
fn case2_overpay_accepts() {
    let tx = claim_tx(mk_txout(asset_a(), AMOUNT_A + 1, claimant_script()));
    let r = run(tx, claim_witness(&good_preimage()));
    assert!(r.is_ok(), "OVERPAY must ACCEPT, got REJECT: {:?}", r.err());
}

// 3. WRONG PREIMAGE: preimage = 0x00..01, so sha256 != HASHLOCK. REJECT.
#[test]
fn case3_wrong_preimage_rejects() {
    let mut bad = [0u8; 32];
    bad[31] = 0x01;
    let tx = claim_tx(mk_txout(asset_a(), AMOUNT_A, claimant_script()));
    let r = run(tx, claim_witness(&bad));
    assert!(r.is_err(), "WRONG PREIMAGE must REJECT, but it ACCEPTED");
}

// 4. WRONG ASSET: output 0 asset != ASSET_A. REJECT (eq_256 on asset fails).
#[test]
fn case4_wrong_asset_rejects() {
    let tx = claim_tx(mk_txout(other_asset(), AMOUNT_A, claimant_script()));
    let r = run(tx, claim_witness(&good_preimage()));
    assert!(r.is_err(), "WRONG ASSET must REJECT, but it ACCEPTED");
}

// 5. UNDERPAY: output 0 amount == AMOUNT_A - 1. REJECT (subtract_64 borrow guard).
#[test]
fn case5_underpay_rejects() {
    let tx = claim_tx(mk_txout(asset_a(), AMOUNT_A - 1, claimant_script()));
    let r = run(tx, claim_witness(&good_preimage()));
    assert!(r.is_err(), "UNDERPAY must REJECT, but it ACCEPTED");
}

// 6. WRONG CLAIMANT SCRIPT: correct asset+amount, but paid to a different script.
//    REJECT (eq_256 on the scriptPubKey hash fails). Passing this also proves
//    CLAIMANT_SPK_HASH is computed correctly (case 1 uses the same derivation).
#[test]
fn case6_wrong_claimant_script_rejects() {
    let tx = claim_tx(mk_txout(asset_a(), AMOUNT_A, other_script()));
    let r = run(tx, claim_witness(&good_preimage()));
    assert!(r.is_err(), "WRONG CLAIMANT SCRIPT must REJECT, but it ACCEPTED");
}

// 7. BLINDED OUTPUT: output 0 asset+value are confidential. REJECT
//    (unwrap_right hard-abort on the confidential `Left`).
#[test]
fn case7_blinded_output_rejects() {
    let tx = claim_tx(mk_blinded_txout(asset_a(), AMOUNT_A, claimant_script()));
    let r = run(tx, claim_witness(&good_preimage()));
    assert!(r.is_err(), "BLINDED OUTPUT must REJECT, but it ACCEPTED");
}

// ---------------------------------------------------------------------------
// REFUND path
// ---------------------------------------------------------------------------

// 8. REFUND BEFORE CLTV: tx lock_time = height 1999 (< T_SEQ = 2000), input
//    sequence < MAX (so the tx is non-final and lockHeight is enforced).
//    `check_lock_height(2000)` is the FIRST op in refund_spend, so it aborts
//    before the (dummy) signature is ever checked -> REJECT.
#[test]
fn case8_refund_before_cltv_rejects() {
    let tx = mk_tx(
        LockTime::from_height(T_SEQ - 1).unwrap(), // height 1999
        Sequence::from_consensus(0xffff_fffe),     // non-final: lockHeight enforced
        vec![mk_txout(asset_a(), AMOUNT_A, claimant_script()), fee_out()],
    );
    let r = run(tx, refund_witness(&[0u8; 64]));
    assert!(
        r.is_err(),
        "REFUND BEFORE CLTV must REJECT, but it ACCEPTED"
    );
    // Confirm it is the CLTV gate that rejects (a jet/assertion failure during
    // pruning/execution), NOT a bip_0340_verify signature failure: the dummy
    // sig is never reached because check_lock_height aborts first.
    let err = r.unwrap_err();
    println!("case8 refund-before-CLTV ProgramError: {:?}", err);
    match err {
        ProgramError::Pruning(_) | ProgramError::Execution(_) => {}
        other => panic!(
            "expected a jet failure from check_lock_height (Pruning/Execution), got: {:?}",
            other
        ),
    }

    // Control isolating the gate: give the SAME pre-CLTV tx a genuinely VALID
    // funder signature. If it STILL rejects, the rejection is unambiguously the
    // CLTV `check_lock_height` gate (the sig would satisfy bip_0340_verify).
    let tx2 = mk_tx(
        LockTime::from_height(T_SEQ - 1).unwrap(),
        Sequence::from_consensus(0xffff_fffe),
        vec![mk_txout(asset_a(), AMOUNT_A, claimant_script()), fee_out()],
    );
    let program = load_program(SEQOB_XCHAIN, build_args()).expect("covenant should compile");
    let env = build_env(tx2);
    let secp = zkp::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let sk = zkp::SecretKey::from_slice(&sk_bytes).unwrap();
    let keypair = zkp::Keypair::from_secret_key(&secp, &sk);
    let msg = zkp::Message::from_digest(env.c_tx_env().sighash_all().to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let r2 = run_program(&program, refund_witness(&sig.serialize()), &env, TrackerLogLevel::None)
        .map(|_| ());
    assert!(
        r2.is_err(),
        "REFUND BEFORE CLTV must REJECT even with a VALID funder sig (proving the CLTV gate), but it ACCEPTED"
    );
    println!(
        "case8 refund-before-CLTV (valid sig) still rejects: {:?}",
        r2.unwrap_err()
    );
}

// 9. REFUND AFTER CLTV + valid sig: tx lock_time = height 2000 (>= T_SEQ), input
//    sequence < MAX, and a real BIP340 signature by FUNDER_PUBKEY's key over
//    Simplicity's sig_all_hash() for THIS env. ACCEPT.
#[test]
fn case9_refund_after_cltv_with_valid_sig_accepts() {
    let tx = mk_tx(
        LockTime::from_height(T_SEQ).unwrap(), // height 2000
        Sequence::from_consensus(0xffff_fffe), // non-final: lockHeight enforced
        vec![mk_txout(asset_a(), AMOUNT_A, claimant_script()), fee_out()],
    );

    let program = load_program(SEQOB_XCHAIN, build_args()).expect("covenant should compile");
    let env = build_env(tx);

    // The FUNDER keypair: secret scalar 1, whose x-only pubkey is G == GENERATOR_X.
    let secp = zkp::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let sk = zkp::SecretKey::from_slice(&sk_bytes).unwrap();
    let keypair = zkp::Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = keypair.x_only_public_key();
    assert_eq!(
        xonly.serialize(),
        GENERATOR_X,
        "FUNDER key x-only must equal the committed FUNDER_PUBKEY"
    );

    // The message the `sig_all_hash()` jet will produce at runtime, derived from
    // this exact env (self-consistent regardless of the placeholder cmr/ctrl block).
    let sighash = env.c_tx_env().sighash_all();
    let msg = zkp::Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    let witness = refund_witness(&sig.serialize());
    let r = run_program(&program, witness, &env, TrackerLogLevel::None).map(|_| ());
    assert!(
        r.is_ok(),
        "REFUND AFTER CLTV with a valid funder sig must ACCEPT, got REJECT: {:?}",
        r.err()
    );
}

// Evidence that the Taproot 0xbe substrate is wired: print the covenant's
// program CMR and its P2TR address (for the VALID arguments).
#[test]
fn taproot_substrate_cmr_and_address() {
    let program = load_program(SEQOB_XCHAIN, build_args()).expect("covenant should compile");
    let cmr = program.commit().cmr();
    let internal_key = XOnlyPublicKey::from_slice(&GENERATOR_X).expect("valid x-only key");
    let address = create_p2tr_address(cmr, &internal_key, &ELEMENTS_PARAMS);
    println!("SeqOB xchain seq-leg covenant CMR : {}", cmr);
    println!("SeqOB xchain seq-leg covenant P2TR: {}", address);
}
