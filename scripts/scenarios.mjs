// Scenario runner: prints a decision table for a fixed set of cases.
// Run: node scripts/scenarios.mjs
// Zero dependencies. Every row is one call to the shared policy engine.

import { evaluatePolicy, defaultPolicy, parseNearToYocto, formatYocto } from "../shared/policy.mjs";

const BLOCKLIST = new Map([
  ["drainer-evil.near", { reason: "drainer, evidence: tx 9xF2…a41b" }],
]);
const ALLOWLIST = new Set(["alice.near"]);
const SEEN = new Set(["agent-demo.testnet|alice.near", "agent-demo.testnet|carol.near"]);

const scenarios = [
  { name: "Routine payment to a known counterparty", receiver: "alice.near", amount: "1", method: "transfer", spent: "0" },
  { name: "First payment to a new counterparty", receiver: "bob.near", amount: "1", method: "transfer", spent: "0" },
  { name: "Large payment, known counterparty (human threshold)", receiver: "carol.near", amount: "3", method: "transfer", spent: "0" },
  { name: "Over the per-transaction cap", receiver: "alice.near", amount: "6", method: "transfer", spent: "0" },
  { name: "Over the daily cap", receiver: "alice.near", amount: "5", method: "transfer", spent: "16" },
  { name: "Payment to a blocklisted drainer", receiver: "drainer-evil.near", amount: "0.5", method: "transfer", spent: "0" },
  { name: "Disallowed method (ft_transfer)", receiver: "alice.near", amount: "1", method: "ft_transfer", spent: "0", methodsAllowed: ["transfer"] },
  { name: "Receiver outside the agent allowlist", receiver: "mallory.near", amount: "1", method: "transfer", spent: "0", receiversAllowed: ["alice.near", "carol.near"] },
  { name: "Engine paused by owner", receiver: "alice.near", amount: "1", method: "transfer", spent: "0", paused: true },
  { name: "Allowlisted counterparty, first interaction", receiver: "alice.near", amount: "1", method: "transfer", spent: "0", seenBefore: false },
];

console.log("| Scenario | Amount | Verdict | Reasons |");
console.log("|---|---|---|---|");
for (const s of scenarios) {
  const policy = defaultPolicy();
  if (s.methodsAllowed) policy.methodsAllowed = s.methodsAllowed;
  if (s.receiversAllowed) policy.receiversAllowed = s.receiversAllowed;
  const seenBefore = s.seenBefore ?? SEEN.has(`agent-demo.testnet|${s.receiver}`);
  const d = evaluatePolicy({
    paused: s.paused ?? false,
    blockEntry: BLOCKLIST.get(s.receiver) ?? null,
    policy,
    spentTodayYocto: parseNearToYocto(s.spent),
    receiver: s.receiver,
    amountYocto: parseNearToYocto(s.amount),
    method: s.method,
    allowlisted: ALLOWLIST.has(s.receiver),
    seenBefore,
  });
  console.log(`| ${s.name} | ${formatYocto(parseNearToYocto(s.amount))} | **${d.verdict.toUpperCase()}** | ${d.reasons.join("; ")} |`);
}
