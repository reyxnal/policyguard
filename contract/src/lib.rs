//! PolicyGuard: an on-chain counterparty + policy check for AI agents that pay.
//!
//! An agent about to send funds or call a contract first asks this contract:
//! `check(agent, receiver, amount, method)` returns allow / warn / block plus
//! the reasons. The decision rules live in `policy.rs` (pure, unit-tested) and
//! are mirrored in `shared/policy.mjs` for the demo and the agent wrapper.
//!
//! State:
//! - shared blocklist with reporter + reason + evidence (anyone can report)
//! - shared allowlist of trusted counterparties (owner-managed)
//! - per-agent spending policies (owner-managed)
//! - daily spend buckets per agent, decision log, seen-pairs set
//! - owner-controlled pause switch
//!
//! The contract never holds agent funds and never signs: it is a policy
//! oracle. Enforcement happens in the agent-side wrapper, which refuses to
//! sign on `block` and asks a human on `warn`.

mod policy;

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::{UnorderedMap, UnorderedSet};
use near_sdk::{AccountId, PanicOnDefault, env, near};

use policy::{PolicyRules, Verdict, evaluate};

// Storage key prefixes (single bytes keep keys short).
const KEY_BLOCKLIST: &[u8] = b"b";
const KEY_ALLOWLIST: &[u8] = b"a";
const KEY_POLICIES: &[u8] = b"p";
const KEY_SPENT: &[u8] = b"s";
const KEY_DECISIONS: &[u8] = b"d";
const KEY_SEEN: &[u8] = b"e";

const NANOS_PER_DAY: u64 = 86_400_000_000_000;
const MAX_REASON_LEN: usize = 280;
const MAX_EVIDENCE_LEN: usize = 500;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct Report {
    pub reporter: AccountId,
    pub reason: String,
    pub evidence: String,
    pub reported_at: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct StoredPolicy {
    pub per_tx_cap: u128,
    pub daily_cap: u128,
    pub methods_allowed: Vec<String>,
    pub receivers_allowed: Vec<AccountId>,
    pub human_above: u128,
}

impl StoredPolicy {
    fn as_rules(&self) -> PolicyRules {
        PolicyRules {
            per_tx_cap: self.per_tx_cap,
            daily_cap: self.daily_cap,
            methods_allowed: self.methods_allowed.clone(),
            receivers_allowed: self.receivers_allowed.iter().map(|a| a.to_string()).collect(),
            human_above: self.human_above,
        }
    }
}

/// JSON input for `set_policy` (amounts as decimal strings via U128).
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct PolicyInput {
    pub per_tx_cap: U128,
    pub daily_cap: U128,
    pub methods_allowed: Vec<String>,
    pub receivers_allowed: Vec<AccountId>,
    pub human_above: U128,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct StoredDecision {
    pub agent: AccountId,
    pub receiver: AccountId,
    pub amount: u128,
    pub method: String,
    pub verdict: String,
    pub executed: bool,
    pub at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct VerdictView {
    pub verdict: String,
    pub reasons: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct DecisionView {
    pub index: u64,
    pub agent: AccountId,
    pub receiver: AccountId,
    pub amount: U128,
    pub method: String,
    pub verdict: String,
    pub executed: bool,
    pub at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct StatsView {
    pub owner: AccountId,
    pub paused: bool,
    pub blocklist_size: u64,
    pub allowlist_size: u64,
    pub decision_count: u64,
    pub policies_count: u64,
}

// near-sdk 5.x: `#[near(contract_state)]` generates the `ContractState`
// impl (state_read/state_write) that the method wrappers require, plus the
// Borsh derives — so the struct must NOT repeat them (duplicate derives).
// The old bare `#[near_bindgen]` does not generate `ContractState`, which
// broke the wasm build with E0277 while `cargo test` stayed green.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PolicyGuard {
    owner: AccountId,
    paused: bool,
    blocklist: UnorderedMap<AccountId, Report>,
    allowlist: UnorderedSet<AccountId>,
    policies: UnorderedMap<AccountId, StoredPolicy>,
    spent: UnorderedMap<String, u128>,
    decisions: UnorderedMap<u64, StoredDecision>,
    decision_count: u64,
    seen: UnorderedSet<String>,
}

#[near]
impl PolicyGuard {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner,
            paused: false,
            blocklist: UnorderedMap::new(KEY_BLOCKLIST),
            allowlist: UnorderedSet::new(KEY_ALLOWLIST),
            policies: UnorderedMap::new(KEY_POLICIES),
            spent: UnorderedMap::new(KEY_SPENT),
            decisions: UnorderedMap::new(KEY_DECISIONS),
            decision_count: 0,
            seen: UnorderedSet::new(KEY_SEEN),
        }
    }

    fn assert_owner(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "only owner");
    }

    fn day_bucket() -> u64 {
        env::block_timestamp() / NANOS_PER_DAY
    }

    fn spent_key(agent: &AccountId, day: u64) -> String {
        format!("{}|{}", agent, day)
    }

    fn seen_key(agent: &AccountId, receiver: &AccountId) -> String {
        format!("{}|{}", agent, receiver)
    }

    /// The check: allow / warn / block + reasons. Pure view, no state change.
    pub fn check(
        &self,
        agent: AccountId,
        receiver: AccountId,
        amount: U128,
        method: String,
    ) -> VerdictView {
        let block_reason = self.blocklist.get(&receiver).map(|r| r.reason.clone());
        let stored = self.policies.get(&agent);
        let rules = stored.map(|p| p.as_rules());
        let spent_today = self
            .spent
            .get(&Self::spent_key(&agent, Self::day_bucket()))
            .copied()
            .unwrap_or(0);
        let (verdict, reasons) = evaluate(
            self.paused,
            block_reason.as_deref(),
            rules.as_ref(),
            spent_today,
            receiver.as_str(),
            amount.0,
            method.as_str(),
            self.allowlist.contains(&receiver),
            self.seen.contains(&Self::seen_key(&agent, &receiver)),
        );
        VerdictView { verdict: verdict.as_str().to_string(), reasons }
    }

    /// Record a decision the agent acted on. Only the agent itself (or the
    /// owner) may record for that agent. When `executed` is true the amount
    /// counts toward the agent's daily spend, and the pair is marked seen.
    pub fn record(
        &mut self,
        agent: AccountId,
        receiver: AccountId,
        amount: U128,
        method: String,
        verdict: String,
        executed: bool,
    ) {
        let caller = env::predecessor_account_id();
        assert!(
            caller == agent || caller == self.owner,
            "only the agent itself or the owner can record"
        );
        assert!(
            verdict == Verdict::Allow.as_str()
                || verdict == Verdict::Warn.as_str()
                || verdict == Verdict::Block.as_str(),
            "verdict must be allow, warn or block"
        );
        let index = self.decision_count;
        self.decisions.insert(
            index,
            StoredDecision {
                agent: agent.clone(),
                receiver: receiver.clone(),
                amount: amount.0,
                method,
                verdict,
                executed,
                at: env::block_timestamp(),
            },
        );
        self.decision_count += 1;
        if executed {
            let key = Self::spent_key(&agent, Self::day_bucket());
            let total = self.spent.get(&key).copied().unwrap_or(0).saturating_add(amount.0);
            self.spent.insert(key, total);
            self.seen.insert(Self::seen_key(&agent, &receiver));
        }
        env::log_str(&format!("decision recorded: index={} agent={}", index, agent));
    }

    /// Report a bad counterparty to the shared blocklist, with evidence.
    /// Anyone can report; the reporter is recorded with the entry.
    pub fn report(&mut self, receiver: AccountId, reason: String, evidence: String) {
        assert!(!reason.trim().is_empty(), "reason required");
        assert!(!evidence.trim().is_empty(), "evidence required");
        assert!(reason.len() <= MAX_REASON_LEN, "reason too long");
        assert!(evidence.len() <= MAX_EVIDENCE_LEN, "evidence too long");
        assert_ne!(receiver, env::predecessor_account_id(), "cannot report yourself");
        self.blocklist.insert(
            receiver.clone(),
            Report {
                reporter: env::predecessor_account_id(),
                reason,
                evidence,
                reported_at: env::block_timestamp(),
            },
        );
        env::log_str(&format!("counterparty reported: {}", receiver));
    }

    /// Owner removes a blocklist entry (appeals / false reports).
    pub fn unreport(&mut self, receiver: AccountId) {
        self.assert_owner();
        self.blocklist.remove(&receiver);
    }

    /// Owner sets (or replaces) an agent's spending policy.
    pub fn set_policy(&mut self, agent: AccountId, policy: PolicyInput) {
        self.assert_owner();
        self.policies.insert(
            agent,
            StoredPolicy {
                per_tx_cap: policy.per_tx_cap.0,
                daily_cap: policy.daily_cap.0,
                methods_allowed: policy.methods_allowed,
                receivers_allowed: policy.receivers_allowed,
                human_above: policy.human_above.0,
            },
        );
    }

    /// Owner adds/removes a trusted counterparty on the shared allowlist.
    pub fn set_allowlisted(&mut self, receiver: AccountId, allowed: bool) {
        self.assert_owner();
        if allowed {
            self.allowlist.insert(receiver);
        } else {
            self.allowlist.remove(&receiver);
        }
    }

    /// Owner kill-switch: while paused, every check returns block.
    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;
    }

    // ---- views ----

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn get_policy(&self, agent: AccountId) -> Option<StoredPolicy> {
        self.policies.get(&agent).cloned()
    }

    pub fn get_block_entry(&self, receiver: AccountId) -> Option<Report> {
        self.blocklist.get(&receiver).cloned()
    }

    pub fn is_allowlisted(&self, receiver: AccountId) -> bool {
        self.allowlist.contains(&receiver)
    }

    pub fn get_spent_today(&self, agent: AccountId) -> U128 {
        U128(self.spent.get(&Self::spent_key(&agent, Self::day_bucket())).copied().unwrap_or(0))
    }

    pub fn get_decision_count(&self) -> u64 {
        self.decision_count
    }

    pub fn get_decisions(&self, from_index: u64, limit: u64) -> Vec<DecisionView> {
        let limit = limit.min(100);
        let mut out = Vec::new();
        let mut i = from_index;
        while i < self.decision_count && out.len() < limit as usize {
            if let Some(d) = self.decisions.get(&i) {
                out.push(DecisionView {
                    index: i,
                    agent: d.agent.clone(),
                    receiver: d.receiver.clone(),
                    amount: U128(d.amount),
                    method: d.method.clone(),
                    verdict: d.verdict.clone(),
                    executed: d.executed,
                    at: d.at,
                });
            }
            i += 1;
        }
        out
    }

    pub fn get_stats(&self) -> StatsView {
        StatsView {
            owner: self.owner.clone(),
            paused: self.paused,
            blocklist_size: self.blocklist.len() as u64,
            allowlist_size: self.allowlist.len() as u64,
            decision_count: self.decision_count,
            policies_count: self.policies.len() as u64,
        }
    }
}
