//! Testnet4 esplora client (blocking transport).
//!
//! GET `/address/{a}`, `/address/{a}/utxo`, `/tx/{txid}`, `/blocks/tip/height`;
//! POST `/tx`. Bounded-concurrency fan-out via `std::thread::scope`. The async
//! transport (wasm, `.buffered(8)`) lands in a later phase behind `btc-async`.

use std::time::Duration;

use crate::error::Error;

fn map<E: std::fmt::Debug>(e: E) -> Error {
    Error::Generic(format!("{e:?}"))
}

/// esplora address stats (chain + mempool): funded/spent sums + tx count.
#[derive(serde::Deserialize, Default)]
pub(crate) struct Stats {
    #[serde(default)]
    pub funded_txo_sum: i64,
    #[serde(default)]
    pub spent_txo_sum: i64,
    #[serde(default)]
    pub tx_count: i64,
}

#[derive(serde::Deserialize)]
pub(crate) struct AddrInfo {
    #[serde(default)]
    pub chain_stats: Stats,
    #[serde(default)]
    pub mempool_stats: Stats,
}

#[derive(serde::Deserialize)]
pub(crate) struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

/// Concurrent esplora requests per batch (bounded so a mobile client doesn't
/// spawn dozens of threads at once).
const CONCURRENCY: usize = 8;

pub(crate) fn client() -> Result<reqwest::blocking::Client, Error> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(map)
}

/// Map `f` over `items` with at most [`CONCURRENCY`] in-flight at once, preserving
/// order. Scoped threads borrow the client + base URL (no clones, no 'static bound).
pub(crate) fn par_fetch<I: Sync, R: Send>(
    client: &reqwest::blocking::Client,
    base: &str,
    items: &[I],
    f: impl Fn(&reqwest::blocking::Client, &str, &I) -> R + Sync,
) -> Vec<R> {
    let mut out = Vec::with_capacity(items.len());
    for chunk in items.chunks(CONCURRENCY) {
        let part = std::thread::scope(|s| {
            let handles: Vec<_> = chunk.iter().map(|it| s.spawn(|| f(client, base, it))).collect();
            handles.into_iter().map(|h| h.join().expect("esplora worker panicked")).collect::<Vec<_>>()
        });
        out.extend(part);
    }
    out
}

pub(crate) fn addr_info(client: &reqwest::blocking::Client, base: &str, addr: &String) -> Option<AddrInfo> {
    client.get(format!("{base}/address/{addr}")).send().ok()?.json::<AddrInfo>().ok()
}

pub(crate) fn addr_utxos(client: &reqwest::blocking::Client, base: &str, addr: &String) -> Vec<EsploraUtxo> {
    client
        .get(format!("{base}/address/{addr}/utxo"))
        .send()
        .ok()
        .and_then(|r| r.json::<Vec<EsploraUtxo>>().ok())
        .unwrap_or_default()
}
