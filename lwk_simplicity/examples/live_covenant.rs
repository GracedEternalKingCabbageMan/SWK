//! Fund and spend a real Simplicity covenant on a live Sequentia node.
//!
//! Simplicity showing as "active" in `getdeploymentinfo` says the rule is
//! switched on; it does not say the machinery works end to end on a real
//! chain. This closes that gap. It derives the address of an actual Simplicity
//! leaf (taproot leaf version 0xbe) and finalizes a spend of it with the
//! four-element witness consensus expects, so the chain itself is what accepts
//! or rejects the result.
//!
//! It talks to the node only through hex on the command line, so funding, fees
//! and broadcast stay with the node's own RPC where they belong and this stays
//! a pure compile-and-satisfy step.
//!
//!   live_covenant address
//!       Print the program CMR, the scriptPubKey, and the address to fund.
//!
//!   live_covenant spend <unsigned-tx-hex> <prevout-spk-hex> <prevout-asset-hex> <prevout-value>
//!       Attach the Simplicity witness to input 0; print the final tx hex.
//!
//! The program is `fn main() { }`, the trivial always-succeeds Simplicity
//! program. It needs no witness data and no signature, which makes it a clean
//! test of the RULE rather than of a signature scheme: before activation such
//! an output is spendable by anyone with any garbage witness, and after
//! activation only a well-formed Simplicity program satisfies it.

use std::collections::HashMap;
use std::str::FromStr;

use lwk_common::{ElementsParamsBuilder, Network};
use lwk_simplicity::scripts::create_p2tr_address;
use lwk_simplicity::scripts::load_program;
use lwk_simplicity::signer::finalize_transaction;
use lwk_simplicity::simplicityhl::elements::hashes::Hash;
use lwk_simplicity::simplicityhl::elements::pset::serialize::{Deserialize, Serialize};
use lwk_simplicity::simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;
use lwk_simplicity::simplicityhl::elements::{
    confidential, bitcoin::bech32::Hrp, AddressParams, AssetId, BlockHash, Script, Transaction,
    TxOut,
};
use lwk_simplicity::simplicityhl::{Arguments, WitnessValues};

const SOURCE: &str = "fn main() { }\n";

/// A nothing-up-my-sleeve internal key, so the covenant has no key-path
/// escape: the Simplicity leaf is the only way to spend it, which is the point
/// of the test.
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Sequentia testnet. Its unblinded addresses are deliberately identical in
/// format to Bitcoin's, so the HRP is "tb" rather than an Elements-specific one.
static SEQ_TESTNET_ADDRESS_PARAMS: AddressParams = AddressParams {
    p2pkh_prefix: 235,
    p2sh_prefix: 75,
    blinded_prefix: 4,
    bech_hrp: Hrp::parse_unchecked("tb"),
    blech_hrp: Hrp::parse_unchecked("tsqb"),
};

const GENESIS: &str = "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e";
const POLICY_ASSET: &str = "c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40";

fn network() -> Network {
    // The genesis hash is not cosmetic here: an Elements sighash commits to it,
    // so a witness built against the wrong chain simply will not verify.
    let params = ElementsParamsBuilder::new()
        .with_genesis_hash(BlockHash::from_str(GENESIS).expect("genesis hash"))
        .with_policy_asset(AssetId::from_str(POLICY_ASSET).expect("policy asset"))
        .with_address_params(&SEQ_TESTNET_ADDRESS_PARAMS)
        .with_name("sequentia-testnet")
        .build()
        .expect("params");
    Network::CustomElements(params)
}

fn program() -> lwk_simplicity::simplicityhl::CompiledProgram {
    load_program(SOURCE, Arguments::from(HashMap::new())).expect("trivial program compiles")
}

fn nums_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str(NUMS).expect("valid x-only key")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("address") => {
            let prog = program();
            let cmr = prog.commit().cmr();
            let addr = create_p2tr_address(cmr, &nums_key(), &SEQ_TESTNET_ADDRESS_PARAMS);
            println!("cmr {}", hex(cmr.as_ref()));
            println!("spk {}", hex(addr.script_pubkey().as_bytes()));
            println!("address {addr}");
        }
        Some("spend") | Some("spend-garbage") => {
            let tx_hex = args.get(2).expect("unsigned tx hex");
            let spk_hex = args.get(3).expect("prevout spk hex");
            let asset_hex = args.get(4).expect("prevout asset hex");
            let value: u64 = args.get(5).expect("prevout value").parse().expect("value");

            let tx = Transaction::deserialize(&unhex(tx_hex)).expect("tx parses");
            let spk = Script::from(unhex(spk_hex));
            // Asset ids print in display (reversed) order, as txids do.
            let mut asset_bytes = unhex(asset_hex);
            asset_bytes.reverse();
            let asset = AssetId::from_slice(&asset_bytes).expect("asset id");

            let prevout = TxOut {
                asset: confidential::Asset::Explicit(asset),
                value: confidential::Value::Explicit(value),
                nonce: confidential::Nonce::Null,
                script_pubkey: spk,
                witness: Default::default(),
            };

            let final_tx = finalize_transaction(
                tx,
                &program(),
                &nums_key(),
                &[prevout],
                0,
                WitnessValues::from(HashMap::new()),
                network(),
                Default::default(),
            )
            .expect("program satisfies its own spend");
            let mut final_tx = final_tx;
            // "garbage" keeps the witness shape but corrupts the program, which
            // is the difference that matters: while the deployment is inactive
            // consensus does not look at a 0xbe leaf at all, so this spends
            // exactly as well as the real thing. Once the rule is enforced only
            // the real program can. Running both against the same output turns
            // activation from a status field into an observable.
            if args.get(1).map(String::as_str) == Some("spend-garbage") {
                let w = &mut final_tx.input[0].witness.script_witness;
                w[1] = vec![0xff; w[1].len().max(1)];
            }
            println!("{}", hex(&final_tx.serialize()));
        }
        _ => {
            eprintln!("usage: live_covenant address");
            eprintln!("       live_covenant spend <tx-hex> <spk-hex> <asset-hex> <value>");
            std::process::exit(2);
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
