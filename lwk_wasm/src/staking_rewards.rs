//! SEQUENTIA staking rewards, for the browser and mobile wallets: which coins a
//! staker was PAID, and which of them to convert.
//!
//! Layers 1 and 2 of reward auto-conversion (the node repo's
//! `doc/sequentia/reward-autoconvert-design.md`). Execution is layer 3 and stays
//! in each wallet, because it is the wallet's own SeqDEX take path and this adds
//! no settlement primitive of its own.
//!
//! Both layers are exposed as pure JSON in / JSON out, so the web wallet, the
//! extension and Ambra share ONE implementation of the two decisions that must
//! not differ between them - which coins are rewards, and which of them to sell.
//! Three wallets each inventing "which coins are rewards" would disagree on the
//! first edge case, and disagreeing about which coins to SELL is the expensive
//! kind of disagreement.
//!
//! The DTOs below carry ids as hex strings and amounts as numbers rather than
//! leaning on the element types' own serde, so the shape the wallets see is
//! stated here and cannot drift underneath them.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use lwk_wollet::elements::hex::FromHex;
use lwk_wollet::elements::{AssetId, OutPoint, Script, Txid};
use lwk_wollet::staking_rewards::{
    attribute_rewards, batches, decide, AutoConvertSettings, ConvertTarget, Decision, OwnedOutput,
    Quote, RewardBatch, SignerRelation, StakingReward, TxFacts,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::Error;

/// One output of one wallet transaction, as attribution needs to see it.
/// `asset`/`value` are the UNBLINDED values; an output the wallet cannot
/// unblind is simply left out of `ownedOutputs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedOutputDto {
    pub vout: u32,
    /// scriptPubKey, hex.
    pub script_pubkey: String,
    /// Asset id, hex.
    pub asset: String,
    pub value: u64,
    #[serde(default)]
    pub spent: bool,
}

/// A wallet transaction, reduced to the facts attribution depends on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxFactsDto {
    pub txid: String,
    /// Height it confirmed at; omitted or null while it is in the mempool.
    #[serde(default)]
    pub height: Option<u32>,
    pub is_coinbase: bool,
    /// Whether this wallet SENT it. A coinbase is never anyone's to send, and
    /// off the coinbase path this is what excludes a delegator's own withdrawal
    /// or re-pointing, which pay back to the same staking key a pool would.
    #[serde(default)]
    pub from_me: bool,
    pub owned_outputs: Vec<OwnedOutputDto>,
}

/// One staking key the wallet can be paid on: the `P2WPKH` script that pays it,
/// the key itself, and whether that key signs for itself or has lent its weight
/// to a pool - which is the whole difference between `solo` and `lottery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakingKeyDto {
    /// `P2WPKH(pubkey)` scriptPubKey, hex.
    pub script_pubkey: String,
    /// The staker public key, 33-byte hex.
    pub pubkey: String,
    /// True when this key's weight is lent to a pool.
    #[serde(default)]
    pub delegated: bool,
}

/// One coin this wallet was paid for staking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakingRewardDto {
    pub txid: String,
    pub vout: u32,
    pub asset: String,
    pub value: u64,
    /// `"solo"`, `"direct"`, `"lottery"` or `"split"`.
    pub source: String,
    #[serde(default)]
    pub height: Option<u32>,
    pub blocks_to_maturity: u32,
    pub mature: bool,
    pub spent: bool,
}

/// The staker's standing instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    #[serde(default)]
    pub enabled: bool,
    /// The asset id to convert into, hex - or omitted/null for native
    /// parent-chain BTC, which is the default and the top of every picker.
    /// Never SBTC: a staker who asks for Bitcoin gets Bitcoin, and one who
    /// genuinely wants the peg picks it as an asset like any other.
    #[serde(default)]
    pub target: Option<String>,
    /// Asset ids to keep as they are, on top of the target itself.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// The floor a batch must clear, in the TARGET asset's atoms.
    pub min_receive: u64,
    /// How far from the reference price a fill may land, in basis points.
    pub max_slippage_bp: u32,
}

/// Reward coins of one asset, gathered until they are worth converting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardBatchDto {
    pub asset: String,
    /// Exactly the coins this batch would spend, `"<txid>:<vout>"`. Nothing
    /// else is ever spent: not the staker's principal, not a stake output, not
    /// a delegation record.
    pub inputs: Vec<String>,
    pub value: u64,
}

/// What the book is offering for a batch right now.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteDto {
    /// Target atoms the book would actually deliver, having walked the levels,
    /// net of the swap's own costs.
    pub receives: u64,
    /// Target atoms the batch is worth at the reference price, ignoring depth.
    pub reference: u64,
}

/// Whether a batch converts now, and if not, why not. Every "not now" is a
/// WAIT, never an error: the coins stay exactly where they are.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionDto {
    /// `"convert"`, `"disabled"`, `"notConverted"`, `"noMarket"`,
    /// `"belowFloor"` or `"slippageTooHigh"`.
    pub decision: String,
    pub converts: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receives: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub floor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slippage_bp: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_bp: Option<u32>,
    /// A sentence a wallet can show as-is.
    pub reason: String,
}

fn asset_from_hex(s: &str) -> Result<AssetId, Error> {
    AssetId::from_str(s.trim()).map_err(|e| Error::Generic(format!("bad asset id {s}: {e}")))
}

fn script_from_hex(s: &str) -> Result<Script, Error> {
    let bytes = Vec::<u8>::from_hex(s.trim())
        .map_err(|e| Error::Generic(format!("bad scriptPubKey {s}: {e}")))?;
    Ok(Script::from(bytes))
}

fn outpoint_to_string(o: &OutPoint) -> String {
    format!("{}:{}", o.txid, o.vout)
}

fn outpoint_from_string(s: &str) -> Result<OutPoint, Error> {
    let (txid, vout) = s
        .rsplit_once(':')
        .ok_or_else(|| Error::Generic(format!("bad outpoint {s}: expected <txid>:<vout>")))?;
    let txid = Txid::from_str(txid.trim())
        .map_err(|e| Error::Generic(format!("bad outpoint txid {txid}: {e}")))?;
    let vout: u32 = vout
        .trim()
        .parse()
        .map_err(|e| Error::Generic(format!("bad outpoint vout {vout}: {e}")))?;
    Ok(OutPoint::new(txid, vout))
}

fn settings_from_dto(dto: &SettingsDto) -> Result<AutoConvertSettings, Error> {
    let target = match dto.target.as_deref().map(str::trim) {
        None | Some("") => ConvertTarget::NativeBtc,
        Some(hex) => ConvertTarget::Asset(asset_from_hex(hex)?),
    };
    let mut exclude = HashSet::new();
    for a in &dto.exclude {
        exclude.insert(asset_from_hex(a)?);
    }
    Ok(AutoConvertSettings {
        enabled: dto.enabled,
        target,
        exclude,
        min_receive: dto.min_receive,
        max_slippage_bp: dto.max_slippage_bp,
    })
}

fn reward_to_dto(r: &StakingReward) -> StakingRewardDto {
    StakingRewardDto {
        txid: r.outpoint.txid.to_string(),
        vout: r.outpoint.vout,
        asset: r.asset.to_string(),
        value: r.value,
        source: r.source.as_str().to_string(),
        height: r.height,
        blocks_to_maturity: r.blocks_to_maturity,
        mature: r.mature(),
        spent: r.spent,
    }
}

fn reward_from_dto(d: &StakingRewardDto) -> Result<StakingReward, Error> {
    use lwk_wollet::staking_rewards::RewardSource;
    let source = match d.source.as_str() {
        "solo" => RewardSource::Solo,
        "direct" => RewardSource::Direct,
        "lottery" => RewardSource::Lottery,
        "split" => RewardSource::Split,
        other => return Err(Error::Generic(format!("unknown reward source {other}"))),
    };
    let txid = Txid::from_str(d.txid.trim())
        .map_err(|e| Error::Generic(format!("bad txid {}: {e}", d.txid)))?;
    Ok(StakingReward {
        outpoint: OutPoint::new(txid, d.vout),
        asset: asset_from_hex(&d.asset)?,
        value: d.value,
        source,
        height: d.height,
        blocks_to_maturity: d.blocks_to_maturity,
        spent: d.spent,
    })
}

/// Every staking reward in `txs`, newest first.
///
/// `txsJson` is `TxFactsDto[]`, `stakingKeysJson` is `StakingKeyDto[]`.
/// Returns `StakingRewardDto[]`.
#[wasm_bindgen(js_name = attributeStakingRewards)]
pub fn attribute_staking_rewards_js(
    txs_json: &str,
    staking_keys_json: &str,
    tip_height: u32,
    coinbase_maturity: u32,
) -> Result<JsValue, Error> {
    let txs: Vec<TxFactsDto> = serde_json::from_str(txs_json)
        .map_err(|e| Error::Generic(format!("bad txs json: {e}")))?;
    let keys: Vec<StakingKeyDto> = serde_json::from_str(staking_keys_json)
        .map_err(|e| Error::Generic(format!("bad staking keys json: {e}")))?;

    let mut scripts = HashMap::new();
    let mut relations = HashMap::new();
    for k in &keys {
        let pk = lwk_wollet::elements::secp256k1_zkp::PublicKey::from_str(k.pubkey.trim())
            .map_err(|e| Error::Generic(format!("bad staker pubkey {}: {e}", k.pubkey)))?;
        scripts.insert(script_from_hex(&k.script_pubkey)?, pk);
        relations.insert(
            pk,
            if k.delegated {
                SignerRelation::Delegated
            } else {
                SignerRelation::SelfSigning
            },
        );
    }

    let mut facts = Vec::with_capacity(txs.len());
    for t in &txs {
        let txid = Txid::from_str(t.txid.trim())
            .map_err(|e| Error::Generic(format!("bad txid {}: {e}", t.txid)))?;
        let mut owned = Vec::with_capacity(t.owned_outputs.len());
        for o in &t.owned_outputs {
            owned.push(OwnedOutput {
                vout: o.vout,
                script_pubkey: script_from_hex(&o.script_pubkey)?,
                asset: asset_from_hex(&o.asset)?,
                value: o.value,
                spent: o.spent,
            });
        }
        facts.push(TxFacts {
            txid,
            height: t.height,
            is_coinbase: t.is_coinbase,
            from_me: t.from_me,
            owned_outputs: owned,
        });
    }

    let rewards = attribute_rewards(&facts, &scripts, &relations, tip_height, coinbase_maturity);
    let out: Vec<StakingRewardDto> = rewards.iter().map(reward_to_dto).collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| Error::Generic(e.to_string()))
}

/// Group convertible rewards into one batch per asset, skipping the target
/// itself and anything excluded.
///
/// `alreadyConvertedJson` is `string[]` of `"<txid>:<vout>"` - the coins a
/// conversion has already consumed. That is the idempotence which stops a
/// restart, or a second window, selling the same reward twice.
#[wasm_bindgen(js_name = planRewardBatches)]
pub fn plan_reward_batches_js(
    rewards_json: &str,
    settings_json: &str,
    already_converted_json: &str,
) -> Result<JsValue, Error> {
    let rewards: Vec<StakingRewardDto> = serde_json::from_str(rewards_json)
        .map_err(|e| Error::Generic(format!("bad rewards json: {e}")))?;
    let settings: SettingsDto = serde_json::from_str(settings_json)
        .map_err(|e| Error::Generic(format!("bad settings json: {e}")))?;
    let already: Vec<String> = serde_json::from_str(already_converted_json)
        .map_err(|e| Error::Generic(format!("bad alreadyConverted json: {e}")))?;

    let rewards: Result<Vec<_>, Error> = rewards.iter().map(reward_from_dto).collect();
    let settings = settings_from_dto(&settings)?;
    let mut done = HashSet::new();
    for s in &already {
        done.insert(outpoint_from_string(s)?);
    }

    let out: Vec<RewardBatchDto> = batches(&rewards?, &settings, &done)
        .iter()
        .map(|b| RewardBatchDto {
            asset: b.asset.to_string(),
            inputs: b.inputs.iter().map(outpoint_to_string).collect(),
            value: b.value,
        })
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| Error::Generic(e.to_string()))
}

/// Whether one batch converts, given what the book is offering for it.
///
/// `quoteJson` is a `QuoteDto`, or `"null"` when there is no market for
/// `ASSET/TARGET` - or none deep enough to fill the batch. No market is not an
/// error: the batch waits, and converts if one appears.
#[wasm_bindgen(js_name = decideRewardConversion)]
pub fn decide_reward_conversion_js(
    batch_json: &str,
    quote_json: &str,
    settings_json: &str,
) -> Result<JsValue, Error> {
    let batch: RewardBatchDto = serde_json::from_str(batch_json)
        .map_err(|e| Error::Generic(format!("bad batch json: {e}")))?;
    let quote: Option<QuoteDto> = serde_json::from_str(quote_json)
        .map_err(|e| Error::Generic(format!("bad quote json: {e}")))?;
    let settings: SettingsDto = serde_json::from_str(settings_json)
        .map_err(|e| Error::Generic(format!("bad settings json: {e}")))?;

    let mut inputs = Vec::with_capacity(batch.inputs.len());
    for i in &batch.inputs {
        inputs.push(outpoint_from_string(i)?);
    }
    let batch = RewardBatch {
        asset: asset_from_hex(&batch.asset)?,
        inputs,
        value: batch.value,
    };
    let settings = settings_from_dto(&settings)?;
    let quote = quote.map(|q| Quote {
        receives: q.receives,
        reference: q.reference,
    });

    let d = decide(&batch, quote, &settings);
    let dto = match d {
        Decision::Convert { receives } => DecisionDto {
            decision: "convert".into(),
            converts: true,
            receives: Some(receives),
            floor: None,
            slippage_bp: None,
            cap_bp: None,
            reason: "converting".into(),
        },
        Decision::Disabled => DecisionDto {
            decision: "disabled".into(),
            converts: false,
            receives: None,
            floor: None,
            slippage_bp: None,
            cap_bp: None,
            reason: "Automatic conversion is switched off.".into(),
        },
        Decision::NotConverted => DecisionDto {
            decision: "notConverted".into(),
            converts: false,
            receives: None,
            floor: None,
            slippage_bp: None,
            cap_bp: None,
            reason: "This asset is the one you convert into, or you chose to keep it.".into(),
        },
        Decision::NoMarket => DecisionDto {
            decision: "noMarket".into(),
            converts: false,
            receives: None,
            floor: None,
            slippage_bp: None,
            cap_bp: None,
            reason: "No market for this pair right now. These rewards wait; \
                     they convert if one appears."
                .into(),
        },
        Decision::BelowFloor { receives, floor } => DecisionDto {
            decision: "belowFloor".into(),
            converts: false,
            receives: Some(receives),
            floor: Some(floor),
            slippage_bp: None,
            cap_bp: None,
            reason: "Not yet worth converting: these rewards would fetch less than \
                     your minimum. They wait for the next ones."
                .into(),
        },
        Decision::SlippageTooHigh {
            slippage_bp,
            cap_bp,
        } => DecisionDto {
            decision: "slippageTooHigh".into(),
            converts: false,
            receives: None,
            floor: None,
            slippage_bp: Some(slippage_bp),
            cap_bp: Some(cap_bp),
            reason: "The market is quoting too far from the reference price. \
                     These rewards wait for a better one."
                .into(),
        },
    };
    serde_wasm_bindgen::to_value(&dto).map_err(|e| Error::Generic(e.to_string()))
}
