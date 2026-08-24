//! Execution tests for the SeqOB partial-fill covenant (`data/seqob_partial.simf`).
//!
//! Each case builds a distinct `elements::Transaction`, wraps it in a CUSTOM
//! execution environment (this covenant reads its OWN input via `input_amount(k)`
//! / `current_script_hash()`, which the stock `dummy_with_tx` cannot express),
//! and runs the compiled covenant on the Simplicity BitMachine (the same
//! evaluator as consensus) through `lwk_simplicity::runner::run_program`.
//!
//!   Ok(..)  == the covenant ACCEPTS the spend.
//!   Err(..) == the covenant REJECTS the spend.
//!
//! FILL leaf (`witness::PATH = Left(())`, permissionless), for the covenant input
//! at consensus index `k`:
//!   * its own input must be EXPLICIT `ASSET_A`, amount `in_amount`;
//!   * remainder output `2k+1`: EXPLICIT `ASSET_A`, scriptPubKey hash ==
//!     `current_script_hash()` (self-replication);
//!   * conservation `filled = in_amount - rem_amount` (subtract borrow guard);
//!   * dust floors `filled >= MIN_LOT`, `rem == 0 || rem >= MIN_LOT`;
//!   * pro-rata payment output `2k`: EXPLICIT `ASSET_B` to `MAKER_SPK_HASH`,
//!     amount `>= ceil(filled*RATE_NUM/RATE_DEN)` (ceil rounds to the maker).

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
use elements::taproot::ControlBlock;
use elements::{
    AssetId, AssetIssuance, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness,
};

/// The covenant source, compiled fresh per case with the case's arguments.
const SEQOB_PARTIAL: &str = include_str!("../data/seqob_partial.simf");

// Order terms baked into the tapleaf (design doc section 2).
const RATE_NUM: u64 = 3;
const RATE_DEN: u64 = 2;
const MIN_LOT: u64 = 10;

/// x-only internal key used for the Taproot substrate demonstration: the
/// secp256k1 generator point G (a valid on-curve x-only key).
const GENERATOR_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// The control block bytes used by `dummy_with_tx` (a well-formed 33-byte
/// Taproot control block; its contents are irrelevant to the FILL leaf, which
/// verifies no signature).
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
/// `input_amount` / `output_amount`. (Verbatim from `seqob_covenant.rs`.)
fn asset_u256_hex(asset_id: AssetId) -> String {
    let ser = elements::encode::serialize(&Asset::Explicit(asset_id));
    assert_eq!(ser.len(), 33, "explicit asset serializes to 33 bytes");
    assert_eq!(ser[0], 0x01, "explicit asset prefix is 0x01");
    format!("0x{}", hex_of(&ser[1..]))
}

/// `output_script_hash(i)` / `current_script_hash()` return the PLAIN SHA-256 of
/// the raw scriptPubKey bytes (no tag, no length prefix). (Verbatim from
/// `seqob_covenant.rs`.)
fn spk_hash_u256_hex(spk: &Script) -> String {
    let h = sha256::Hash::hash(spk.as_bytes());
    format!("0x{}", hex_of(h.as_ref()))
}

fn asset_a() -> AssetId {
    AssetId::from_slice(&[0x0a; 32]).unwrap()
}

fn asset_b() -> AssetId {
    AssetId::from_slice(&[0x0b; 32]).unwrap()
}

/// A third, distinct explicit asset (for the "remainder wrong asset" case).
fn other_asset() -> AssetId {
    AssetId::from_slice(&[0x0c; 32]).unwrap()
}

/// The covenant's OWN scriptPubKey stand-in (P2TR-shaped: OP_1 <32 bytes>).
/// The remainder output must replicate this exact script.
fn covenant_spk() -> Script {
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(&[0x7e; 32]);
    Script::from(v)
}

/// The maker payout script (P2WPKH-shaped: OP_0 <20 bytes>).
fn maker_script() -> Script {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xab; 20]);
    Script::from(v)
}

/// A different, non-matching script (remainder-wrong-script case).
fn other_script() -> Script {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xcd; 20]);
    Script::from(v)
}

/// An attacker-controlled script (output-aliasing case: the slot the covenant
/// insists must be a maker payment but the attacker filled with junk).
fn attacker_script() -> Script {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xef; 20]);
    Script::from(v)
}

/// The seven `param::` arguments (ASSET_A/ASSET_B/RATE_NUM/RATE_DEN/
/// MAKER_SPK_HASH/MIN_LOT/MAKER_PUBKEY). `MAKER_PUBKEY` is only consulted on the
/// pruned REFUND leaf but must still be a well-formed `Pubkey`; we use G's x-coord.
fn build_args() -> Arguments {
    let json = format!(
        r#"{{
            "ASSET_A":        {{ "value": "{asset_a}", "type": "u256" }},
            "ASSET_B":        {{ "value": "{asset_b}", "type": "u256" }},
            "RATE_NUM":       {{ "value": "{rate_num}", "type": "u64" }},
            "RATE_DEN":       {{ "value": "{rate_den}", "type": "u64" }},
            "MAKER_SPK_HASH": {{ "value": "{spk}", "type": "u256" }},
            "MIN_LOT":        {{ "value": "{min_lot}", "type": "u64" }},
            "MAKER_PUBKEY":   {{ "value": "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "type": "Pubkey" }}
        }}"#,
        asset_a = asset_u256_hex(asset_a()),
        asset_b = asset_u256_hex(asset_b()),
        rate_num = RATE_NUM,
        rate_den = RATE_DEN,
        spk = spk_hash_u256_hex(&maker_script()),
        min_lot = MIN_LOT,
    );
    serde_json::from_str::<Arguments>(&json).expect("arguments JSON should parse")
}

/// The FILL witness: `witness::PATH = Left(())`. The REFUND (`Right`) leaf is
/// pruned; no signature is supplied.
fn fill_witness() -> WitnessValues {
    let json = r#"{ "PATH": { "value": "Left(())", "type": "Either<(), Signature>" } }"#;
    serde_json::from_str::<WitnessValues>(json).expect("witness JSON should parse")
}

/// A transaction input with a distinct previous-output vout (so multiple
/// covenant inputs are not literally identical outpoints).
fn mk_input(vout: u32) -> TxIn {
    let mut previous_output = OutPoint::default();
    previous_output.vout = vout;
    TxIn {
        previous_output,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: AssetIssuance::default(),
        witness: TxInWitness::default(),
    }
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

/// A fee output (the covenant never reads it; present for realism).
fn fee_out() -> TxOut {
    TxOut::new_fee(500, asset_a())
}

fn mk_tx(num_inputs: u32, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: (0..num_inputs).map(mk_input).collect(),
        output: outputs,
    }
}

/// The covenant-owned UTXO: `script_pubkey = COVENANT_SPK`, EXPLICIT `ASSET_A`,
/// value = `in_amount`. This is what `input_amount(k)` and
/// `current_script_hash()` read for the covenant input.
fn covenant_utxo(in_amount: u64) -> ElementsUtxo {
    ElementsUtxo {
        script_pubkey: covenant_spk(),
        asset: Asset::Explicit(asset_a()),
        value: CValue::Explicit(in_amount),
    }
}

/// Build a CUSTOM environment: a chosen `current_index`, and the caller-supplied
/// per-input UTXO set (so the covenant input's own script/asset/amount are
/// exactly what we place at that index). Models `dummy_with_tx`, but without its
/// hardcoded index 0 and defaulted UTXOs.
fn build_env(
    tx: Transaction,
    utxos: Vec<ElementsUtxo>,
    current_index: u32,
) -> ElementsEnv<Arc<Transaction>> {
    ElementsEnv::new(
        Arc::new(tx),
        utxos,
        current_index,
        Cmr::from_byte_array([0; 32]),
        ControlBlock::from_slice(&CTRL_BLK).unwrap(),
        None,
        BlockHash::all_zeros(),
    )
}

/// Compile the covenant with the fixed args, run the FILL witness against
/// `(tx, utxos, current_index)`, return Ok (ACCEPT) / Err (REJECT).
fn run(tx: Transaction, utxos: Vec<ElementsUtxo>, current_index: u32) -> Result<(), ProgramError> {
    let program = load_program(SEQOB_PARTIAL, build_args()).expect("covenant should compile");
    let env = build_env(tx, utxos, current_index);
    run_program(&program, fill_witness(), &env, TrackerLogLevel::None).map(|_| ())
}

// ---------------------------------------------------------------------------
// cases  (single covenant input at k=0:
//         output 0 = maker payment, output 1 = remainder, output 2 = fee)
// ---------------------------------------------------------------------------

// 1. VALID PARTIAL: rem=400 -> filled=600 -> required=ceil(600*3/2)=900; pay 900. ACCEPT.
#[test]
fn case1_valid_partial_accepts() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 900, maker_script()),
            mk_txout(asset_a(), 400, covenant_spk()),
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(
        r.is_ok(),
        "VALID PARTIAL must ACCEPT, got REJECT: {:?}",
        r.err()
    );
}

// 2. OVERPAY: pay 901 (>= 900). ACCEPT.
#[test]
fn case2_overpay_accepts() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 901, maker_script()),
            mk_txout(asset_a(), 400, covenant_spk()),
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(r.is_ok(), "OVERPAY must ACCEPT, got REJECT: {:?}", r.err());
}

// 3. UNDERPAY: pay 899 (< 900). REJECT (subtract_64 borrow on pay >= required).
#[test]
fn case3_underpay_rejects() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 899, maker_script()),
            mk_txout(asset_a(), 400, covenant_spk()),
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(r.is_err(), "UNDERPAY must REJECT, but it ACCEPTED");
}

// 4a. CEIL rounds to maker: rem=399 -> filled=601 -> required=ceil(601*3/2)=902.
//     pay 901 -> REJECT.
#[test]
fn case4a_ceil_underpay_rejects() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 901, maker_script()),
            mk_txout(asset_a(), 399, covenant_spk()),
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(
        r.is_err(),
        "CEIL underpay (901 < 902) must REJECT, but it ACCEPTED"
    );
}

// 4b. CEIL rounds to maker: rem=399 -> filled=601 -> required=902. pay 902 -> ACCEPT.
#[test]
fn case4b_ceil_exact_accepts() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 902, maker_script()),
            mk_txout(asset_a(), 399, covenant_spk()),
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(
        r.is_ok(),
        "CEIL exact (902 == 902) must ACCEPT, got REJECT: {:?}",
        r.err()
    );
}

// 5. REMAINDER WRONG SCRIPT: remainder output uses a script != COVENANT_SPK.
//    REJECT (output_script_hash(2k+1) != current_script_hash()).
#[test]
fn case5_remainder_wrong_script_rejects() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 900, maker_script()),
            mk_txout(asset_a(), 400, other_script()), // not COVENANT_SPK
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(
        r.is_err(),
        "REMAINDER WRONG SCRIPT must REJECT, but it ACCEPTED"
    );
}

// 6. REMAINDER WRONG ASSET: remainder output asset != ASSET_A.
//    REJECT (eq_256(rem_asset, ASSET_A) fails).
#[test]
fn case6_remainder_wrong_asset_rejects() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 900, maker_script()),
            mk_txout(other_asset(), 400, covenant_spk()), // not ASSET_A
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(
        r.is_err(),
        "REMAINDER WRONG ASSET must REJECT, but it ACCEPTED"
    );
}

// 7. REMAINDER INFLATED (steal A): rem=1200 > in=1000.
//    REJECT (subtract_64(in, rem) borrows).
#[test]
fn case7_remainder_inflated_rejects() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 900, maker_script()),
            mk_txout(asset_a(), 1200, covenant_spk()), // > in_amount
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(
        r.is_err(),
        "REMAINDER INFLATED must REJECT (borrow), but it ACCEPTED"
    );
}

// 8. DUST FILL: rem=995 -> filled=5 < MIN_LOT(10). REJECT (ensure_ge_64(filled, MIN_LOT)).
#[test]
fn case8_dust_fill_rejects() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 900, maker_script()),
            mk_txout(asset_a(), 995, covenant_spk()),
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(r.is_err(), "DUST FILL must REJECT, but it ACCEPTED");
}

// 9. DUST REMAINDER: rem=5 (0 < 5 < MIN_LOT). filled=995, required=ceil(995*3/2)=1493
//    (paid exactly, so only the dust-remainder floor can reject).
//    REJECT (ensure_ge_64(rem_amount, MIN_LOT) in the rem != 0 branch).
#[test]
fn case9_dust_remainder_rejects() {
    let tx = mk_tx(
        1,
        vec![
            mk_txout(asset_b(), 1493, maker_script()),
            mk_txout(asset_a(), 5, covenant_spk()),
            fee_out(),
        ],
    );
    let r = run(tx, vec![covenant_utxo(1000)], 0);
    assert!(r.is_err(), "DUST REMAINDER must REJECT, but it ACCEPTED");
}

// 10. OUTPUT-ALIASING (the sharp edge): two covenant inputs, ONE reused maker
//     payment. Outputs: [maker_pay(0), rem_input0(1), NOT-a-maker-payment(2),
//     rem_input1(3), fee(4)]. Input 1's maker payment must be at output 2*1=2,
//     which the attacker did not create -> REJECT. Input 0 (current_index=0)
//     still ACCEPTs, proving it is specifically the second order the map protects.
fn aliasing_tx() -> Transaction {
    mk_tx(
        2,
        vec![
            mk_txout(asset_b(), 900, maker_script()),   // 0: the ONE maker payment
            mk_txout(asset_a(), 400, covenant_spk()),   // 1: remainder for input 0
            mk_txout(asset_a(), 400, attacker_script()), // 2: NOT a maker payment
            mk_txout(asset_a(), 400, covenant_spk()),   // 3: remainder for input 1
            fee_out(),                                   // 4: fee
        ],
    )
}

#[test]
fn case10_aliasing_second_input_rejects() {
    let utxos = vec![covenant_utxo(1000), covenant_utxo(1000)];
    let r = run(aliasing_tx(), utxos, 1); // input 1 looks for its payment at output 2
    assert!(
        r.is_err(),
        "OUTPUT-ALIASING: input 1 has no maker payment at output 2 -> must REJECT, but it ACCEPTED"
    );
}

#[test]
fn case10_aliasing_first_input_accepts() {
    let utxos = vec![covenant_utxo(1000), covenant_utxo(1000)];
    let r = run(aliasing_tx(), utxos, 0); // input 0 finds its payment at output 0
    assert!(
        r.is_ok(),
        "OUTPUT-ALIASING control: input 0 is a valid fill and must ACCEPT, got REJECT: {:?}",
        r.err()
    );
}

// Evidence that the Taproot 0xbe substrate is wired: print the covenant's
// program CMR and its P2TR address (for the VALID arguments).
#[test]
fn taproot_substrate_cmr_and_address() {
    let program = load_program(SEQOB_PARTIAL, build_args()).expect("covenant should compile");
    let cmr = program.commit().cmr();
    let internal_key = XOnlyPublicKey::from_slice(&GENERATOR_X).expect("valid x-only key");
    let address = create_p2tr_address(cmr, &internal_key, &ELEMENTS_PARAMS);
    println!("SeqOB partial-fill covenant CMR : {}", cmr);
    println!("SeqOB partial-fill covenant P2TR: {}", address);
}
