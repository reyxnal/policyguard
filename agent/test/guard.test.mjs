// Zero-dependency tests for the policy engine + guard wrapper.
// Run: node --test agent/test/guard.test.mjs   (or: npm test)

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  evaluatePolicy,
  defaultPolicy,
  parseNearToYocto,
  formatYocto,
  YOCTO_PER_NEAR,
} from "../../shared/policy.mjs";
import { GuardedAgent, RefusedError, createLocalCheck } from "../src/guard.mjs";

const NEAR = YOCTO_PER_NEAR;

function input(overrides = {}) {
  return {
    paused: false,
    blockEntry: null,
    policy: defaultPolicy(),
    spentTodayYocto: 0n,
    receiver: "alice.near",
    amountYocto: NEAR,
    method: "transfer",
    allowlisted: false,
    seenBefore: true,
    ...overrides,
  };
}

test("parse/format NEAR round-trips without floats", () => {
  assert.equal(parseNearToYocto("1.5"), (3n * NEAR) / 2n);
  assert.equal(parseNearToYocto("0.000001"), 10n ** 18n);
  assert.equal(parseNearToYocto("0"), 0n);
  assert.equal(formatYocto(parseNearToYocto("2.5")), "2.5 NEAR");
  assert.equal(formatYocto(parseNearToYocto("0.000001")), "0.000001 NEAR");
  assert.throws(() => parseNearToYocto("1.2.3"), /invalid NEAR amount/);
  assert.throws(() => parseNearToYocto("-1"), /invalid NEAR amount/);
  assert.throws(() => parseNearToYocto("abc"), /invalid NEAR amount/);
});

test("allow within policy", () => {
  const d = evaluatePolicy(input());
  assert.equal(d.verdict, "allow");
  assert.deepEqual(d.reasons, ["within policy"]);
});

test("paused blocks everything", () => {
  const d = evaluatePolicy(input({ paused: true }));
  assert.equal(d.verdict, "block");
  assert.ok(d.reasons.includes("policy engine paused by owner"));
});

test("blocklisted receiver blocked with reason", () => {
  const d = evaluatePolicy(input({ blockEntry: { reason: "drainer" } }));
  assert.equal(d.verdict, "block");
  assert.deepEqual(d.reasons, ["blocklisted: drainer"]);
});

test("per-tx and daily caps block", () => {
  assert.equal(evaluatePolicy(input({ amountYocto: 6n * NEAR })).verdict, "block");
  assert.ok(
    evaluatePolicy(input({ amountYocto: 6n * NEAR })).reasons.includes("exceeds per-transaction cap"),
  );
  const d = evaluatePolicy(input({ spentTodayYocto: 19n * NEAR, amountYocto: 2n * NEAR }));
  assert.equal(d.verdict, "block");
  assert.ok(d.reasons.includes("exceeds daily cap"));
});

test("method and receiver allowlists block", () => {
  const policy = defaultPolicy();
  policy.methodsAllowed = ["transfer"];
  assert.equal(evaluatePolicy(input({ policy, method: "ft_transfer" })).verdict, "block");
  policy.methodsAllowed = [];
  policy.receiversAllowed = ["alice.near"];
  assert.equal(evaluatePolicy(input({ policy, receiver: "mallory.near" })).verdict, "block");
  assert.equal(evaluatePolicy(input({ policy, receiver: "alice.near" })).verdict, "allow");
});

test("human threshold and first interaction warn, not block", () => {
  assert.equal(evaluatePolicy(input({ amountYocto: 3n * NEAR })).verdict, "warn");
  assert.equal(evaluatePolicy(input({ seenBefore: false })).verdict, "warn");
  assert.equal(evaluatePolicy(input({ seenBefore: false, allowlisted: true })).verdict, "allow");
});

test("block beats warn; no policy means only lists and pause apply", () => {
  const d = evaluatePolicy(input({ amountYocto: 6n * NEAR, seenBefore: false }));
  assert.equal(d.verdict, "block");
  assert.ok(!d.reasons.some((r) => r.includes("human-approval")));
  assert.equal(evaluatePolicy(input({ policy: null, amountYocto: 1000n * NEAR })).verdict, "allow");
});

function harness(overrides = {}) {
  const state = {
    paused: false,
    blocklist: new Map([["evil.near", { reason: "drainer" }]]),
    allowlist: new Set(["alice.near"]),
    policy: defaultPolicy(),
    spentTodayYocto: 0n,
    seen: new Set(["agent.testnet|alice.near"]),
    agentId: "agent.testnet",
    ...overrides,
  };
  let signed = 0;
  const records = [];
  const agent = new GuardedAgent({
    checkFn: createLocalCheck(state),
    approveFn: async () => overrides.approve ?? true,
    signerFn: async () => ({ tx: `mock-${++signed}` }),
    recordFn: async (r) => records.push(r),
    log: () => {},
  });
  return { state, agent, records, signed: () => signed };
}

test("guard: block refuses and never signs", async () => {
  const h = harness();
  await assert.rejects(
    () => h.agent.pay({ receiver: "evil.near", amountYocto: NEAR }),
    (err) => err instanceof RefusedError && err.decision.verdict === "block",
  );
  assert.equal(h.signed(), 0);
  assert.equal(h.records.length, 0);
});

test("guard: warn + human deny refuses; warn + approve proceeds and records", async () => {
  const denied = harness({ approve: false });
  await assert.rejects(
    () => denied.agent.pay({ receiver: "bob.near", amountYocto: 3n * NEAR }),
    RefusedError,
  );
  assert.equal(denied.signed(), 0);

  const approved = harness({ approve: true });
  await approved.agent.pay({ receiver: "bob.near", amountYocto: 3n * NEAR });
  assert.equal(approved.signed(), 1);
  assert.equal(approved.records.length, 1);
  assert.equal(approved.records[0].verdict, "warn");
  assert.equal(approved.records[0].executed, true);
});

test("guard: allow proceeds and records", async () => {
  const h = harness();
  const res = await h.agent.pay({ receiver: "alice.near", amountYocto: NEAR });
  assert.equal(res.tx, "mock-1");
  assert.equal(h.records[0].verdict, "allow");
});
