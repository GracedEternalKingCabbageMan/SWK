# Sequentia changes vs upstream LWK

This document is the precise list of what the `sequentia` branch changes
relative to upstream [Blockstream LWK](https://github.com/Blockstream/lwk).
The fork point is upstream v0.18.1 (commit `1095b825`, "bump 0.18.0 -> 0.18.1");
all Sequentia work is additive commits on top of the upstream history so
upstream can still be merged. Crate names and versions stay `lwk_*` / 0.18.x for
the same reason.

Everything targets the public Sequentia testnet (parent chain: Bitcoin
testnet4). Protocol background lives in the node repo,
https://github.com/GracedEternalKingCabbageMan/Sequentia, under `doc/sequentia/`.

Crates NOT touched by the fork (still pure upstream): `lwk_signer`, `lwk_cli`,
`lwk_app`, `lwk_bindings`, `lwk_jade`, `lwk_ledger`, `lwk_hwi`, `lwk_boltz`,
`lwk_payment_instructions`, `lwk_simplicity`, `lwk_rpc_model`, `lwk_tiny_jrpc`,
`lwk_containers`, `lwk_test_util`, `amp2_mock`. In particular `lwk_simplicity`
is an upstream LWK crate that predates the fork, not a Sequentia addition, and
the CLI/UniFFI surfaces have no Sequentia network selector yet.

## Workspace (`Cargo.toml`)

- `[patch.crates-io] elements = { path = "rust-elements" }`: the whole workspace
  uses the vendored `rust-elements` (see below).
- `elements` workspace dependency enables features
  `["base64", "serde", "sequentia"]`. The `sequentia` serialization is therefore
  ON for every crate in the workspace. Consequence: upstream Liquid test
  fixtures that hard-code the Liquid wire format fail to deserialize, so a plain
  `cargo test -p lwk_wollet --lib` has known failures in upstream fixture tests;
  the Sequentia-specific test modules all pass.
- `bitcoin = "=0.32.7"` pinned exactly to the version `elements-miniscript`
  pulls transitively, so the parent-chain crate can never drift and silently
  change HTLC redeemScript bytes.

## Vendored `rust-elements` (`./rust-elements`, cargo feature `sequentia`)

A vendored fork of the `elements` crate. All Sequentia deltas are gated behind
its `sequentia` cargo feature:

- `src/block.rs`: `BlockHeader::bitcoin_anchor: Option<(u32, BlockHash)>`.
  Sequentia headers commit a 36-byte Bitcoin anchor (parent-chain height + block
  hash) right after the height, matching the node's `src/primitives/block.h`.
  It is (de)serialized on the wire and committed in the block hash. Without
  this, upstream `elements` cannot even decode a Sequentia tip header. Verified
  by re-hashing a real header to the chain's block hash.
- `src/transaction.rs` (+ `src/issuance.rs`, `src/pset/map/input.rs`,
  `src/sighash.rs`, `src/blind.rs` touch points): Sequentia issuance
  transactions carry an extra `nDenomination` byte; the feature adds it to
  issuance (de)serialization, PSET input mapping, and sighash computation.
- `src/address.rs`: `AddressParams::SEQUENTIA_TESTNET` (base58 p2pkh 111 /
  p2sh 196 / blinded 70; bech32 HRP `tb`; blech32 HRP `tsqb`) and address-string
  parsing for those prefixes. Sequentia is transparent by default: the default
  unblinded address is Bitcoin's own bech32 format (`tb1...`), which is exactly
  why one address works on both chains; confidential (blinded) addresses are
  opt-in and use the distinct `tsqb` blech32 HRP.

## `lwk_common`

- `src/network.rs`:
  - `SEQUENTIA_TESTNET_ADDRESS_PARAMS` const (same parameters as above).
  - `ElementsParamsBuilder::with_address_params()` / `with_name()`: custom
    Elements networks can carry their own address params and short name
    (upstream hard-codes `AddressParams::ELEMENTS` and "liquid-regtest").
  - `Network::sequentia_testnet()`: Sequentia testnet as a custom Elements
    network with the policy asset (the Sequence token, tSEQ:
    `c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40`), the
    Sequentia address params, and the name `sequentia-testnet`.
  - The genesis-hash constant in `sequentia_testnet()` is the current
    2026-07-05 re-genesis hash (`ddd11d54...`). The policy-asset id was
    preserved across the re-genesis. Inside LWK the network genesis hash is
    used for BIP341 (taproot) sighash computation (e.g. the SeqOB covenant
    flows), so it must track the live chain.

## `lwk_wollet`

New cargo features:

- `sequentia = ["elements/sequentia"]`: transparent-by-default wallet behavior.
- `btc = ["bitcoin", "sequentia"]`: the I/O-free Bitcoin parent-chain core.
- `btc-async` / `btc-blocking`: the two esplora transports over that core
  (wasm/async apps vs native blocking apps). `btc-blocking` on wasm32 is a
  compile error by design.

Changes by file:

- `src/wollet.rs`, `src/pset_create.rs`, `src/update.rs` (feature `sequentia`):
  explicit (non-confidential) outputs are first-class wallet funds: they count
  in balance, coin selection, and history; wallet inputs may be explicit;
  change is sent unblinded unless a confidential input is being spent (Elements
  requires at least one blinded output to balance a blinded input). Also
  `Wollet::explicit_utxos()` and a valid zero anchor in the placeholder header.
- `src/tx_builder.rs`:
  - Any-asset fees: `TxBuilder::fee_asset(asset, rate)` pays the fee in any
    accepted asset at a given rate, per Sequentia's open fee market (no
    privileged fee asset). Fee-rate units are the chosen asset's own units per
    vByte.
  - RBF/CPFP rescue: `Wollet::bump_fee_of()`, `replace_tx_of()`, `cpfp_of()`,
    `cpfp_suggested_feerate()` build fee-bump/replacement/child transactions,
    any-asset-fee aware. Exercised live by `examples/rescue_test.rs`.
  - Staking (the one place the Sequence token is special):
    `sequentia_stake_script()` and `TxBuilder::add_stake_output(staker_pubkey,
    csv, satoshi)` build the CSV-locked bonding output used to stake for block
    production.
- `src/seqdex_swap.rs` (feature `sequentia`): `SeqdexSwapRequest`, the taker
  half of a SeqDEX same-chain atomic swap (unsigned unblinded PSETv2 plus
  revealed input blinders), wire-compatible with the SeqDEX daemon's
  `/v1/trade/propose`.
- `src/seqdex_htlc.rs` (feature `sequentia`): the cross-chain HTLC's Sequentia
  leg: `build_htlc_redeem_script()` (the single redeemScript source for BOTH
  legs, byte-identical to the daemon's), `build_claim_tx()`,
  `build_refund_tx()`, `SwapSecret` handling.
- `src/btc/` (features `btc*`): the Bitcoin parent-chain side of the dual-chain
  kit:
  - `addr.rs`: `ChainAddressParams`, the shared `(coin_type, HRP, Bitcoin
    network)` triple. Testnet `(1, tb, Testnet4)`: Bitcoin testnet4 and
    Sequentia testnet derive the identical `tb1...` address from one BIP84
    seed. A `mainnet()` constructor exists for the future shared `bc1...`
    space; there is no Sequentia mainnet.
  - `core.rs`: I/O-free wallet logic (BIP39+BIP32 derivation done directly, no
    `lwk_signer` dependency; gap-limit scan; largest-first coin selection;
    P2WPKH build and BIP143 sign). Shared by both transports so blocking and
    async builds are byte-identical (locked by a parity test).
  - `esplora.rs`: Bitcoin testnet4 esplora client, blocking + async (the public
    deployment serves `/testnet4/api` same-origin with the Sequentia esplora).
  - `wallet.rs` / `wallet_async.rs`: the blocking (Ambra) and async (wasm)
    wallet drivers: scan, balance, prepare/sign/broadcast, tip height,
    fee estimates.
  - `htlc.rs`: the BTC-leg HTLC (P2SH from the shared redeemScript, funding,
    and the manual-scriptSig CLTV refund with BIP125 RBF).
  - `xchain.rs`: cross-chain (BTC to Sequentia-asset) swap glue for the taker:
    HTLC key derivation (canonical absolute paths outside the receive/change
    branches, plus a legacy relative mode recorded in persisted state), the
    swap secret, the reveal gate, claim-deadline gate, rate-derived
    Sequentia-leg claim fee, and the Sequentia-leg claim + broadcast (plus the
    on-chain preimage read). The reveal gate is anchoring supremacy in
    code: the taker reveals the preimage only after ITS OWN nodes confirm the
    Sequentia funding's Bitcoin anchor height is at or above the BTC funding
    height, `anchorstatus` is ok, and the anchor is D confirmations deep
    (D is a taker dial, default 1); the Sequentia transaction's finality IS its
    anchor's Bitcoin finality, so no extra reorg timelocks are needed and the
    CLTV timelocks are liveness only.
- `examples/sequentia_sync.rs`: end-to-end watch-only sync against the live
  explorer (`cargo run -p lwk_wollet --example sequentia_sync`).
- `examples/rescue_test.rs`: live functional test of bump/replace/CPFP against
  the testnet (needs a funded wallet).

## `lwk_wasm`

Built with `lwk_wollet` features `sequentia` + `btc-async` (plus upstream
defaults), so the npm-style `pkg/` output of this fork is Sequentia-enabled.
The fork is not published to npm; consumers build `pkg/` with `wasm-pack`.

- `src/network.rs`: `Network.sequentiaTestnet()`; `Network.isSequentia()`
  (Sequentia is modelled as a custom Elements network, so upstream's
  `isRegtest()` returns true for it; use `isSequentia()`).
- `src/btc_wallet.rs`: `BtcWallet` (address, scan, prepare, sign+broadcast) with
  `BtcScan` / `BtcPrepared` result types: the Bitcoin testnet4 half of a
  dual-chain browser wallet.
- `src/xchain.rs`: the `xchain*` helper functions (secret and key derivation,
  BTC HTLC, Sequentia redeem script, Sequentia claim, BTC claim and refund)
  wrapping `lwk_wollet::btc::xchain` for the web wallet.
- `src/seqdex_swap.rs`: `SwapRequest` (same-chain SeqDEX swap proposal).
- `src/seqdex_htlc.rs`: `generateSwapSecret`, `htlcKeypair`,
  `buildSeqHtlcRedeemScript`, `buildSeqHtlcClaimTx`, `buildSeqHtlcRefundTx`.
- `src/tx_builder.rs`: `feeAsset()` (any-asset fees), `addExplicitRecipient()`,
  `addStakeOutput()`, `sequentiaStakeScript()`.
- `src/wollet.rs`: explicit-UTXO and rescue (bump/replace/CPFP) bindings.
- `src/signer.rs`: `Signer.stakerPublicKey()` (staking key at `m/2/0`).

The browser-wallet demo that used to live in `lwk_wasm/www/` was extracted to
its own repository,
[sequentia-web-wallet](https://github.com/GracedEternalKingCabbageMan/sequentia-web-wallet),
live at https://sequentiatestnet.com/wallet.

## Design invariants the fork keeps

- Sequentia is transparent by default; confidentiality is opt-in. Docs and code
  never assume blinded-by-default (that is the Liquid model).
- The Sequence token (SEQ; tSEQ on testnet) is the policy asset but has no
  privilege anywhere in the kit except the staking output builder; fees are
  payable in any accepted asset and fee rates are denominated in the chosen
  asset's own units per vByte.
- One redeemScript source for cross-chain HTLCs: the Bitcoin leg wraps the same
  builder the Sequentia leg uses, so the legs cannot drift (this is why the
  `btc` feature implies `sequentia`).
- Anchor verification is always done against the wallet's own backends, never
  data supplied by a swap counterparty.
