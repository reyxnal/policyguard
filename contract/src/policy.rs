//! Pure policy evaluation: the on-chain decision rules.
//!
//! This module has NO near-sdk dependency so the rules can be unit-tested with
//! plain `cargo test` and audited in isolation. It mirrors `shared/policy.mjs`
//! EXACTLY: same rule order, same precedence, same reason strings. If you
//! change a rule here, change it in `shared/policy.mjs` too (and vice versa).

/// The three possible outcomes of a check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Warn => "warn",
            Verdict::Block => "block",
        }
    }
}

/// Spending policy for one agent. Amounts are yoctoNEAR (1 NEAR = 10^24).
#[derive(Clone, Debug, Default)]
pub struct PolicyRules {
    /// Max yoctoNEAR in a single payment/call. 0 = nothing allowed.
    pub per_tx_cap: u128,
    /// Max yoctoNEAR per UTC day (agent-local day bucket on chain).
    pub daily_cap: u128,
    /// Allowed method names. Empty = any method allowed.
    pub methods_allowed: Vec<String>,
    /// Allowed receivers. Empty = any receiver allowed.
    pub receivers_allowed: Vec<String>,
    /// Amounts above this need a human approval (warn, not block).
    pub human_above: u128,
}

/// Evaluate one proposed payment/call.
///
/// Rule order (all block reasons collected, then warns):
///   1. paused -> block
///   2. blocklisted receiver -> block
///   3. over per-tx cap -> block
///   4. over daily cap -> block
///   5. method not allowed -> block
///   6. receiver not in agent allowlist -> block
///   7. over human-approval threshold -> warn
///   8. first interaction and not allowlisted -> warn
///   9. otherwise -> allow
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    paused: bool,
    block_reason: Option<&str>,
    policy: Option<&PolicyRules>,
    spent_today: u128,
    receiver: &str,
    amount: u128,
    method: &str,
    allowlisted: bool,
    seen_before: bool,
) -> (Verdict, Vec<String>) {
    let mut blocks: Vec<String> = Vec::new();
    let mut warns: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    if paused {
        blocks.push("policy engine paused by owner".to_string());
    }
    if let Some(reason) = block_reason {
        blocks.push(format!("blocklisted: {}", reason));
    }

    if let Some(p) = policy {
        if amount > p.per_tx_cap {
            blocks.push("exceeds per-transaction cap".to_string());
        }
        if spent_today.saturating_add(amount) > p.daily_cap {
            blocks.push("exceeds daily cap".to_string());
        }
        if !p.methods_allowed.is_empty() && !p.methods_allowed.iter().any(|m| m == method) {
            blocks.push("method not in allowed list".to_string());
        }
        if !p.receivers_allowed.is_empty()
            && !p.receivers_allowed.iter().any(|r| r == receiver)
        {
            blocks.push("receiver not in agent allowlist".to_string());
        }
        if amount > p.human_above {
            warns.push("above human-approval threshold".to_string());
        }
    }

    if allowlisted {
        notes.push("allowlisted counterparty".to_string());
    } else if !seen_before {
        warns.push("first interaction with this counterparty".to_string());
    }

    if !blocks.is_empty() {
        return (Verdict::Block, blocks);
    }
    if !warns.is_empty() {
        return (Verdict::Warn, warns);
    }
    notes.push("within policy".to_string());
    (Verdict::Allow, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEAR: u128 = 10u128.pow(24);

    fn policy() -> PolicyRules {
        PolicyRules {
            per_tx_cap: 5 * NEAR,
            daily_cap: 20 * NEAR,
            methods_allowed: vec![],
            receivers_allowed: vec![],
            human_above: 2 * NEAR,
        }
    }

    fn base() -> (bool, Option<&'static str>, Option<PolicyRules>, u128, &'static str, u128, &'static str, bool, bool)
    {
        // paused, block_reason, policy, spent_today, receiver, amount, method, allowlisted, seen_before
        (false, None, Some(policy()), 0, "alice.near", NEAR, "transfer", false, true)
    }

    #[test]
    fn allow_within_policy() {
        let (p, b, pol, spent, recv, amt, method, allow, seen) = base();
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, recv, amt, method, allow, seen);
        assert_eq!(v, Verdict::Allow);
        assert_eq!(reasons, vec!["within policy".to_string()]);
    }

    #[test]
    fn allowlisted_counterparty_noted() {
        let (p, b, pol, spent, recv, amt, method, _, seen) = base();
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, recv, amt, method, true, seen);
        assert_eq!(v, Verdict::Allow);
        assert_eq!(reasons, vec!["allowlisted counterparty".to_string(), "within policy".to_string()]);
    }

    #[test]
    fn paused_blocks_everything() {
        let (_, b, pol, spent, recv, amt, method, allow, seen) = base();
        let (v, reasons) = evaluate(true, b, pol.as_ref(), spent, recv, amt, method, allow, seen);
        assert_eq!(v, Verdict::Block);
        assert!(reasons.contains(&"policy engine paused by owner".to_string()));
    }

    #[test]
    fn blocklisted_receiver_blocked_with_reason() {
        let (p, _, pol, spent, recv, amt, method, allow, seen) = base();
        let (v, reasons) = evaluate(
            p,
            Some("drainer, evidence: tx 9x..."),
            pol.as_ref(),
            spent,
            recv,
            amt,
            method,
            allow,
            seen,
        );
        assert_eq!(v, Verdict::Block);
        assert_eq!(reasons, vec!["blocklisted: drainer, evidence: tx 9x...".to_string()]);
    }

    #[test]
    fn per_tx_cap_blocks() {
        let (p, b, pol, spent, recv, _, method, allow, seen) = base();
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, recv, 6 * NEAR, method, allow, seen);
        assert_eq!(v, Verdict::Block);
        assert!(reasons.contains(&"exceeds per-transaction cap".to_string()));
    }

    #[test]
    fn daily_cap_blocks() {
        let (p, b, pol, _, recv, amt, method, allow, seen) = base();
        let (v, _reasons) = evaluate(p, b, pol.as_ref(), 19 * NEAR, recv, amt, method, allow, seen);
        // 19 spent + 1 = 20, not over. Use 19.5 + 1 to exceed.
        assert_eq!(v, Verdict::Allow);
        let (v, reasons) = evaluate(p, b, pol.as_ref(), 19 * NEAR + NEAR / 2, recv, amt, method, allow, seen);
        assert_eq!(v, Verdict::Block);
        assert!(reasons.contains(&"exceeds daily cap".to_string()));
        let _ = reasons;
    }

    #[test]
    fn method_allowlist_blocks() {
        let (p, b, mut pol, spent, recv, amt, _, allow, seen) = base();
        pol.as_mut().unwrap().methods_allowed = vec!["transfer".to_string()];
        let (v, _) = evaluate(p, b, pol.as_ref(), spent, recv, amt, "transfer", allow, seen);
        assert_eq!(v, Verdict::Allow);
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, recv, amt, "ft_transfer", allow, seen);
        assert_eq!(v, Verdict::Block);
        assert!(reasons.contains(&"method not in allowed list".to_string()));
    }

    #[test]
    fn receiver_allowlist_blocks() {
        let (p, b, mut pol, spent, _, amt, method, allow, seen) = base();
        pol.as_mut().unwrap().receivers_allowed = vec!["alice.near".to_string()];
        let (v, _) = evaluate(p, b, pol.as_ref(), spent, "alice.near", amt, method, allow, seen);
        assert_eq!(v, Verdict::Allow);
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, "mallory.near", amt, method, allow, seen);
        assert_eq!(v, Verdict::Block);
        assert!(reasons.contains(&"receiver not in agent allowlist".to_string()));
    }

    #[test]
    fn human_threshold_warns_but_does_not_block() {
        let (p, b, pol, spent, recv, _, method, allow, seen) = base();
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, recv, 3 * NEAR, method, allow, seen);
        assert_eq!(v, Verdict::Warn);
        assert_eq!(reasons, vec!["above human-approval threshold".to_string()]);
    }

    #[test]
    fn first_interaction_warns() {
        let (p, b, pol, spent, recv, amt, method, allow, _) = base();
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, recv, amt, method, allow, false);
        assert_eq!(v, Verdict::Warn);
        assert_eq!(reasons, vec!["first interaction with this counterparty".to_string()]);
    }

    #[test]
    fn allowlisted_suppresses_first_interaction_warn() {
        let (p, b, pol, spent, recv, amt, method, _, _) = base();
        let (v, _) = evaluate(p, b, pol.as_ref(), spent, recv, amt, method, true, false);
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn block_beats_warn_and_reasons_accumulate() {
        let (p, b, pol, spent, recv, _, method, allow, _) = base();
        // Over per-tx cap AND over human threshold AND first interaction:
        // verdict is block, and both block reasons are reported.
        let (v, reasons) = evaluate(p, b, pol.as_ref(), spent, recv, 6 * NEAR, method, allow, false);
        assert_eq!(v, Verdict::Block);
        assert!(reasons.contains(&"exceeds per-transaction cap".to_string()));
        assert!(!reasons.iter().any(|r| r.contains("human-approval")));
    }

    #[test]
    fn no_policy_means_only_lists_and_pause_apply() {
        let (p, b, _, spent, recv, _amt, method, allow, seen) = base();
        let (v, _) = evaluate(p, b, None, spent, recv, 1000 * NEAR, method, allow, seen);
        assert_eq!(v, Verdict::Allow);
    }
}
