//! Execution tests for the SeqOB single-fill covenant (`data/seqob_fill.simf`).
//!
//! Each case builds a distinct `elements::Transaction`, wraps it in an execution
//! environment via `dummy_env::dummy_with_tx`, and runs the compiled covenant on
//! the Simplicity BitMachine (the same evaluator as consensus) through
//! `lwk_simplicity::runner::run_program`.
//!
//!   Ok(..)  == the covenant ACCEPTS the spend.
//!   Err(..) == the covenant REJECTS the spend.
//!
//! The FILL leaf (Left branch, permissionless) enforces that output 0 pays
//! `>= REQUIRED_B` of EXPLICIT `ASSET_B` to the maker's committed script
//! (`MAKER_SPK_HASH`), and hard-aborts on a blinded output.

use lwk_simplicity::error::ProgramError;
use lwk_simplicity::runner::run_program;
use lwk_simplicity::scripts::{create_p2tr_address, load_program};

// Everything transaction/hash related MUST go through the re-exported `elements`
// (elements 0.25.3, the version simplicity-lang pins) so the types line up with
// what `dummy_with_tx` / the BitMachine expect.
use lwk_simplicity::simplicityhl::dummy_env::dummy_with_tx;
use lwk_simplicity::simplicityhl::elements;
use lwk_simplicity::simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use lwk_simplicity::simplicityhl::simplicity::hashes::{sha256, Hash};
use lwk_simplicity::simplicityhl::tracker::TrackerLogLevel;
use lwk_simplicity::simplicityhl::{Arguments, WitnessValues};

use elements::confidential::{Asset, Nonce, Value as CValue};
use elements::secp256k1_zkp as zkp;
use elements::{
    AssetId, AssetIssuance, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness,
    TxOut, TxOutWitness,
};

/// The covenant source, compiled fresh per case with the case's arguments.
const SEQOB_FILL: &str = include_str!("../data/seqob_fill.simf");

/// Required payment amount of ASSET_B, in atoms.
const REQUIRED_B: u64 = 1000;

/// x-only internal key used for the Taproot substrate demonstration: the
/// secp256k1 generator point G (a valid on-curve x-only key).
const GENERATOR_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
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

/// The `ASSET_B` argument (a `u256`) is the 32 asset-id bytes exactly as the
/// `output_amount` jet returns them for an EXPLICIT output.
///
/// The C tx environment stores an explicit asset by reading `rawConf[1..33]`
/// from the consensus serialization of the output's `confidential::Asset`
/// (env.c `copyRawConfidential`; the leading `0x01` byte is the explicit
/// prefix). So we serialize `Asset::Explicit(id)` (33 bytes) and take the
/// trailing 32 bytes. Deriving it from the serialization makes the argument
/// byte-order-agnostic and guaranteed consistent with what the jet reads.
fn asset_b_u256_hex(asset_id: AssetId) -> String {
    let ser = elements::encode::serialize(&Asset::Explicit(asset_id));
    assert_eq!(ser.len(), 33, "explicit asset serializes to 33 bytes");
    assert_eq!(ser[0], 0x01, "explicit asset prefix is 0x01");
    format!("0x{}", hex_of(&ser[1..]))
}

/// The `MAKER_SPK_HASH` argument (a `u256`).
///
/// `output_script_hash(i)` returns the PLAIN SHA-256 of the raw scriptPubKey
/// bytes: env.c `hashBuffer` does `sha256_init -> sha256_uchars(buf,len) ->
/// sha256_finalize` over `output->scriptPubKey`, with NO tag and NO length
/// prefix (contrast the "TapData"-tagged `tap_data_hash` helper, which is a
/// different jet and is NOT used here). So the committed hash is
/// `SHA256(scriptPubKey)`.
fn maker_spk_hash_u256_hex(spk: &Script) -> String {
    let h = sha256::Hash::hash(spk.as_bytes());
    format!("0x{}", hex_of(h.as_ref()))
}

/// Build the `param::` arguments for a given order (ASSET_B + maker script).
/// `MAKER_PUBKEY` is only consulted on the pruned REFUND leaf, but it must be a
/// well-formed `Pubkey` argument; we use G's x-coordinate.
fn build_args(asset_b: AssetId, maker_spk: &Script) -> Arguments {
    let json = format!(
        r#"{{
            "ASSET_B":        {{ "value": "{asset}", "type": "u256" }},
            "REQUIRED_B":     {{ "value": "{req}",   "type": "u64" }},
            "MAKER_SPK_HASH": {{ "value": "{spk}",   "type": "u256" }},
            "MAKER_PUBKEY":   {{ "value": "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "type": "Pubkey" }}
        }}"#,
        asset = asset_b_u256_hex(asset_b),
        req = REQUIRED_B,
        spk = maker_spk_hash_u256_hex(maker_spk),
    );
    serde_json::from_str::<Arguments>(&json).expect("arguments JSON should parse")
}

/// The FILL witness: `witness::PATH = Left(())`, selecting the permissionless
/// fill leaf. No signature is supplied; the REFUND (`Right`) leaf is pruned.
fn fill_witness() -> WitnessValues {
    let json = r#"{ "PATH": { "value": "Left(())", "type": "Either<(), Signature>" } }"#;
    serde_json::from_str::<WitnessValues>(json).expect("witness JSON should parse")
}

/// A concrete maker payout script (P2WPKH-shaped: OP_0 <20-byte program>).
fn maker_script() -> Script {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xab; 20]);
    Script::from(v)
}

/// A different, non-matching script (case 5).
fn other_script() -> Script {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xcd; 20]);
    Script::from(v)
}

/// Build a transaction whose output 0 is `(asset, value, spk)`.
fn tx_with_output0(asset: Asset, value: CValue, spk: Script) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: AssetIssuance::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![TxOut {
            asset,
            value,
            nonce: Nonce::default(),
            script_pubkey: spk,
            witness: TxOutWitness::default(),
        }],
    }
}

/// A genuinely blinded (confidential) asset+value pair for the same asset/amount
/// (case 6). The commitments are valid curve points; from the tx environment's
/// point of view the prefixes are non-`0x01`, so `output_amount` yields the
/// confidential `Left` and `unwrap_right` hard-aborts.
fn blinded_output0(asset_id: AssetId, value: u64) -> (Asset, CValue) {
    let secp = zkp::Secp256k1::new();
    let generator = zkp::Generator::new_unblinded(&secp, asset_id.into_tag());
    let commitment = zkp::PedersenCommitment::new_unblinded(&secp, value, generator);
    (Asset::Confidential(generator), CValue::Confidential(commitment))
}

/// Compile the covenant with `args`, run the FILL witness against `tx`, and
/// return Ok (ACCEPT) / Err (REJECT).
fn run_fill(args: Arguments, tx: Transaction) -> Result<(), ProgramError> {
    let program = load_program(SEQOB_FILL, args).expect("covenant should compile");
    let env = dummy_with_tx(tx);
    run_program(&program, fill_witness(), &env, TrackerLogLevel::None).map(|_| ())
}

fn asset_b() -> AssetId {
    AssetId::from_slice(&[0x11; 32]).unwrap()
}

fn other_asset() -> AssetId {
    AssetId::from_slice(&[0x22; 32]).unwrap()
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

// 1. VALID FILL: explicit ASSET_B, amount == REQUIRED_B, to maker script. ACCEPT.
#[test]
fn case1_valid_fill_accepts() {
    let maker = maker_script();
    let args = build_args(asset_b(), &maker);
    let tx = tx_with_output0(
        Asset::Explicit(asset_b()),
        CValue::Explicit(REQUIRED_B),
        maker,
    );
    let r = run_fill(args, tx);
    assert!(r.is_ok(), "VALID FILL must ACCEPT, got REJECT: {:?}", r.err());
}

// 2. OVERPAY: amount == REQUIRED_B + 1 (>= holds). ACCEPT.
#[test]
fn case2_overpay_accepts() {
    let maker = maker_script();
    let args = build_args(asset_b(), &maker);
    let tx = tx_with_output0(
        Asset::Explicit(asset_b()),
        CValue::Explicit(REQUIRED_B + 1),
        maker,
    );
    let r = run_fill(args, tx);
    assert!(r.is_ok(), "OVERPAY must ACCEPT, got REJECT: {:?}", r.err());
}

// 3. WRONG ASSET: explicit but different asset id. REJECT (eq_256 on asset fails).
#[test]
fn case3_wrong_asset_rejects() {
    let maker = maker_script();
    let args = build_args(asset_b(), &maker); // committed to asset_b
    let tx = tx_with_output0(
        Asset::Explicit(other_asset()), // pays a different asset
        CValue::Explicit(REQUIRED_B),
        maker,
    );
    let r = run_fill(args, tx);
    assert!(r.is_err(), "WRONG ASSET must REJECT, but it ACCEPTED");
}

// 4. UNDERPAY: amount == REQUIRED_B - 1. REJECT (subtract_64 borrow underflow guard).
#[test]
fn case4_underpay_rejects() {
    let maker = maker_script();
    let args = build_args(asset_b(), &maker);
    let tx = tx_with_output0(
        Asset::Explicit(asset_b()),
        CValue::Explicit(REQUIRED_B - 1),
        maker,
    );
    let r = run_fill(args, tx);
    assert!(r.is_err(), "UNDERPAY must REJECT, but it ACCEPTED");
}

// 5. WRONG SCRIPT: correct asset+amount, but paid to a different script. REJECT
//    (eq_256 on the scriptPubKey hash fails). Passing this also proves
//    MAKER_SPK_HASH is computed correctly (case 1 uses the same derivation).
#[test]
fn case5_wrong_script_rejects() {
    let maker = maker_script();
    let args = build_args(asset_b(), &maker); // committed to maker's script hash
    let tx = tx_with_output0(
        Asset::Explicit(asset_b()),
        CValue::Explicit(REQUIRED_B),
        other_script(), // pays a different script
    );
    let r = run_fill(args, tx);
    assert!(r.is_err(), "WRONG SCRIPT must REJECT, but it ACCEPTED");
}

// 6. BLINDED OUTPUT: output 0 asset+value are confidential. REJECT
//    (unwrap_right hard-abort on the confidential `Left`).
#[test]
fn case6_blinded_output_rejects() {
    let maker = maker_script();
    let args = build_args(asset_b(), &maker);
    let (asset, value) = blinded_output0(asset_b(), REQUIRED_B);
    let tx = tx_with_output0(asset, value, maker);
    let r = run_fill(args, tx);
    assert!(r.is_err(), "BLINDED OUTPUT must REJECT, but it ACCEPTED");
}

// Evidence that the Taproot 0xbe substrate is wired: print the covenant's
// program CMR and its P2TR address (for the VALID arguments).
#[test]
fn taproot_substrate_cmr_and_address() {
    let maker = maker_script();
    let args = build_args(asset_b(), &maker);
    let program = load_program(SEQOB_FILL, args).expect("covenant should compile");
    let cmr = program.commit().cmr();
    let internal_key = XOnlyPublicKey::from_slice(&GENERATOR_X).expect("valid x-only key");
    let address = create_p2tr_address(cmr, &internal_key, &ELEMENTS_PARAMS);
    println!("SeqOB fill covenant CMR : {}", cmr);
    println!("SeqOB fill covenant P2TR: {}", address);
}
