# SWK — Sequentia Wallet Kit

SWK is a fork of [Blockstream LWK](https://github.com/Blockstream/lwk) (Liquid
Wallet Kit) adapted to **Sequentia** — an Elements-based, Proof-of-Stake,
Bitcoin-anchored chain. It is the toolkit for building **standard Sequentia
wallets**, which are always **dual-chain: a Bitcoin parent-chain (testnet4) wallet
plus Sequentia, with no exception**; the same BIP84 keys yield the shared
Bitcoin-format (`tb1…`) addresses valid on both chains. The kit (descriptors,
scanning, balances, PSET) currently implements the Sequentia (Elements) side
against a Sequentia esplora/electrum backend; the Bitcoin parent-chain side
(testnet4 watching, BTC balance and send, cross-chain swaps) is the roadmap to a
complete dual-chain kit.

This branch (`sequentia`) tracks upstream LWK via the `upstream` git remote;
Sequentia changes are kept as small, additive commits so upstream updates can be
merged.

## What's different from upstream LWK

- **Sequentia network** — `lwk_common::Network::sequentia_testnet()` models the
  testnet (`chain=test`) as a custom Elements network with Sequentia's policy asset, the
  Sequence token (SEQ) (`c8eccacf…`), genesis `c2a0a99b…`, and address parameters
  (base58 p2pkh 111 / p2sh 196 / blinded 70, bech32 `tb`, blech32 `tsqb`). It
  identifies as `sequentia-testnet`.
- **Vendored `rust-elements` with a `sequentia` feature** (`./rust-elements`,
  wired via `[patch.crates-io]`). Sequentia block headers carry a 36-byte
  Bitcoin anchor that upstream `elements` can't parse — without this the wallet
  couldn't even decode its tip header. The patch adds
  `BlockHeader::bitcoin_anchor` and (de)serializes + commits it in the block
  hash exactly like Sequentia's `src/primitives/block.h`. Verified by re-hashing
  a real header to the chain's block hash.

## Quick start

```rust
use lwk_wollet::{Network, WolletBuilder, WolletDescriptor};
use lwk_wollet::blocking::{BlockchainBackend, EsploraClient};

let network = Network::sequentia_testnet();
let desc = WolletDescriptor::from_str("ct(slip77(<blinding>),elwpkh(<xpub>/<0;1>/*))#…")?;
let mut wollet = WolletBuilder::new(network, desc).build()?;
let mut client = EsploraClient::new("http://<your-sequentia-esplora>/api", network)?;
if let Some(update) = client.full_scan(&wollet)? { wollet.apply_update(update)?; }
println!("{:?}", wollet.balance()?);
```

A runnable end-to-end example (syncs against a live explorer):

```
cargo run -p lwk_wollet --example sequentia_sync
```

## Web wallet (WASM)

`lwk_wasm` builds the toolkit to WebAssembly, and `lwk_wasm/www/index.html` is a
self-contained, Sequentia-branded browser wallet on top of it: create/import a
12-word mnemonic, derive non-confidential, Bitcoin-format receive addresses
(`tb1…`; confidentiality is opt-in on Sequentia), sync against a Sequentia
esplora at `<origin>/api`, and show asset balances — all client-side, keys
never leaving the browser. (The Bitcoin parent-chain side is not in this demo yet;
see the roadmap.)

```
cd lwk_wasm && wasm-pack build --target web --release      # needs clang
# then serve www/ with the generated pkg/ alongside it
```

A public instance runs alongside the Sequentia explorer.

## Status / roadmap

- [x] Sequentia network + address params
- [x] Vendored rust-elements with the anchored-header `sequentia` serialization
- [x] End-to-end watch-only sync against a live Sequentia explorer
- [x] `nDenomination` issuance byte (issuance-tx serialization delta)
- [x] WASM build + browser wallet (create/import, receive, balance)
- [ ] Send / PSET signing in the browser wallet
- [ ] **Bitcoin parent-chain (testnet4) side**: watching, BTC balance/send, and cross-chain swaps — the dual-chain half every standard Sequentia wallet needs
- [ ] Confidential-tx review for the testnet's non-confidential outputs
- [ ] Wider SWK branding (crate names stay `lwk_*` for upstream tracking)
