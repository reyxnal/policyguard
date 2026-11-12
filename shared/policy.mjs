// Shared policy engine — the single source of truth for the decision rules.
//
// The NEAR smart contract (contract/src/policy.rs) implements EXACTLY these
// rules, in this order, with these reason strings. The demo page, the agent
// wrapper, and the CLI scenario runner all import this file, so what a judge
// sees in the demo is what the contract enforces on chain.
//
// Rules (evaluated in order; all block reasons are collected, then warns):
//   1. paused                         -> BLOCK "policy engine paused by owner"
//   2. receiver on shared blocklist  -> BLOCK "blocklisted: <reason>"
//   3. amount > per-tx cap           -> BLOCK "exceeds per-transaction cap"
//   4. spent-today + amount > daily  -> BLOCK "exceeds daily cap"
//   5. method not in allowed list    -> BLOCK "method not in allowed list"
//   6. receiver not in agent list    -> BLOCK "receiver not in agent allowlist"
//   7. amount > human-approval level -> WARN  "above human-approval threshold"
//   8. first interaction, not allowlisted -> WARN "first interaction with this counterparty"
//   9. otherwise                     -> ALLOW "within policy"
//        (+ "allowlisted counterparty" when the receiver is allowlisted)
//
// Verdict precedence: any block reason => block; else any warn reason => warn;
// else allow. Amounts are BigInt yoctoNEAR (1 NEAR = 10^24 yocto) — never floats.

export const VERDICTS = Object.freeze({
  ALLOW: "allow",
  WARN: "warn",
  BLOCK: "block",
});

export const YOCTO_PER_NEAR = 10n ** 24n;

/** Parse a decimal NEAR string ("1.5", "0.0001") to yoctoNEAR BigInt. No floats. */
export function parseNearToYocto(text) {
  const s = String(text).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`invalid NEAR amount: ${JSON.stringify(text)}`);
  const [whole, frac = ""] = s.split(".");
  const fracPadded = (frac + "0".repeat(24)).slice(0, 24);
  return BigInt(whole) * YOCTO_PER_NEAR + BigInt(fracPadded || "0");
}

/** Format yoctoNEAR BigInt as a short NEAR string (up to 6 decimals, trimmed). */
export function formatYocto(yocto) {
  const neg = yocto < 0n;
  const abs = neg ? -yocto : yocto;
  const whole = abs / YOCTO_PER_NEAR;
  const frac = (abs % YOCTO_PER_NEAR).toString().padStart(24, "0").slice(0, 6).replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}${frac ? "." + frac : ""} NEAR`;
}

/**
 * Evaluate one proposed payment/call.
 * @param {object} input
 * @param {boolean} input.paused
 * @param {{reason: string} | null} input.blockEntry
 * @param {object | null} input.policy - { perTxCapYocto: bigint, dailyCapYocto: bigint,
 *   methodsAllowed: string[], receiversAllowed: string[], humanAboveYocto: bigint }
 * @param {bigint} input.spentTodayYocto
 * @param {string} input.receiver
 * @param {bigint} input.amountYocto
 * @param {string} input.method
 * @param {boolean} input.allowlisted
 * @param {boolean} input.seenBefore
 * @returns {{verdict: string, reasons: string[]}}
 */
export function evaluatePolicy(input) {
  const blocks = [];
  const warns = [];
  const notes = [];

  if (input.paused) {
    blocks.push("policy engine paused by owner");
  }
  if (input.blockEntry) {
    blocks.push(`blocklisted: ${input.blockEntry.reason}`);
  }

  const policy = input.policy;
  if (policy) {
    if (input.amountYocto > policy.perTxCapYocto) {
      blocks.push("exceeds per-transaction cap");
    }
    if (input.spentTodayYocto + input.amountYocto > policy.dailyCapYocto) {
      blocks.push("exceeds daily cap");
    }
    if (policy.methodsAllowed.length > 0 && !policy.methodsAllowed.includes(input.method)) {
      blocks.push("method not in allowed list");
    }
    if (policy.receiversAllowed.length > 0 && !policy.receiversAllowed.includes(input.receiver)) {
      blocks.push("receiver not in agent allowlist");
    }
    if (input.amountYocto > policy.humanAboveYocto) {
      warns.push("above human-approval threshold");
    }
  }

  if (input.allowlisted) {
    notes.push("allowlisted counterparty");
  } else if (!input.seenBefore) {
    warns.push("first interaction with this counterparty");
  }

  if (blocks.length > 0) return { verdict: VERDICTS.BLOCK, reasons: blocks };
  if (warns.length > 0) return { verdict: VERDICTS.WARN, reasons: warns };
  return { verdict: VERDICTS.ALLOW, reasons: [...notes, "within policy"] };
}

/** Default demo policy: 5 NEAR/tx, 20 NEAR/day, human approval above 2 NEAR. */
export function defaultPolicy() {
  return {
    perTxCapYocto: parseNearToYocto("5"),
    dailyCapYocto: parseNearToYocto("20"),
    methodsAllowed: [],
    receiversAllowed: [],
    humanAboveYocto: parseNearToYocto("2"),
  };
}
