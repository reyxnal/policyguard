# PolicyGuard — counterparty & policy check for AI agents that pay

> Working title. The final project name is the team lead's decision (see PREP.md — internal, not shipped).

**Track:** `security` (AI Security & Defense) — also fits `agents`.
**Built for:** [NEAR HACKATHON: Build Beyond Boundaries](https://nearhackathon.com) (1–14 Nov 2026).
**Status:** scaffold + working prototype. Contract unit tests green, demo runs locally and hosted.

## The problem

AI agents can now move real money — and a single prompt injection, a pasted
"urgent" instruction, or a typo'd address can drain them. Agents today either
hold full-access keys (one mistake = everything) or cannot pay at all.

## The product

Before an agent sends funds or calls a contract, it asks PolicyGuard:

```
check(agent, receiver, amount, method) -> allow | warn | block + reasons
```

- **Block** — the wrapper refuses to sign. Nothing is sent. Ever.
- **Warn** — the wrapper asks a human to approve or deny.
- **Allow** — the wrapper signs with a least-privilege key and records the outcome.

The rules live in a NEAR smart contract (shared blocklist with evidence,
allowlist, per-agent spending policies, daily spend tracking, owner pause
switch), so every agent reading the same contract shares the same defense.
The decision log is on chain and auditable.

## How NEAR fits in

- **Function-call access keys**: the agent signs with a key scoped to one
  contract and one method, with a small gas allowance — never a full-access
  key. If the agent is compromised, the blast radius is one method on one
  contract. See "Limits of function-call keys" below.
- **Own contract on NEAR** (Q-011): the policy oracle is a Rust contract on
  NEAR testnet (Q-010: testnet-only projects are eligible in all tracks).
- **Public RPC**: the demo reads live contract state with no wallet and no
  keys (Q-009: public RPC is free).
- **No Intents dependency**: NEAR Intents has no testnet (Q-007), so the core
  demo needs no mainnet funds. Intents settlement is a documented follow-up.

## Try it — do X, see Y

No wallet, no keys, no install for the demo and the CLI:

```sh
# 1. Attack demo: a prompt-injected agent tries to pay a blocklisted drainer.
node agent/src/attack-demo.mjs
# -> See: STOPPED (blocklisted + over cap), 0 signatures; legit payment goes
#    through; warn case asks the human; daily cap stops the 4th payment.

# 2. Decision table for 10 scenarios.
node scripts/scenarios.mjs
# -> See: a markdown table of verdicts + reasons.

# 3. Hosted demo (or serve locally: python3 -m http.server, open /demo/).
# -> Change the receiver to alice.near and the amount to 1, press
#    "Check & pay": ALLOW. Leave drainer-evil.near / 50: BLOCK.
#    Try bob.near / 3: WARN, the browser asks you to approve.

# 4. Contract unit tests (needs Rust: https://rustup.rs).
cargo test --manifest-path contract/Cargo.toml
# -> See: all policy-rule tests pass.

# 5. JavaScript tests (needs Node 18+).
node --test agent/test/guard.test.mjs
# -> See: engine + wrapper tests pass.
```

## Repository layout

```
contract/            Rust smart contract (near-sdk): policy oracle
  src/lib.rs         storage + methods (check/record/report/policies/views)
  src/policy.rs      PURE decision rules + unit tests (no near-sdk dependency)
shared/policy.mjs    the SAME rules in JS (demo, wrapper, CLI) — keep in sync
agent/src/guard.mjs  the wrapper: check -> warn? human -> sign -> record
agent/src/attack-demo.mjs   prompt-injection simulation, runnable, zero deps
agent/test/          node:test suite for the engine + wrapper
demo/                static hosted demo (no build, no keys, no wallet)
scripts/scenarios.mjs  decision table printer
```

The rule order and reason strings are identical in `contract/src/policy.rs`
and `shared/policy.mjs`. A conformance fixture comparing both is a day-2 task
(see PREP.md); the two test suites cover the same cases today.

## The rules

Evaluated in order; all block reasons are collected, then warns. Any block
reason wins; otherwise any warn reason wins; otherwise allow.

| # | Rule | Verdict |
|---|------|---------|
| 1 | Engine paused by owner | block |
| 2 | Receiver on the shared blocklist | block (`blocklisted: <reason>`) |
| 3 | Amount over the per-transaction cap | block |
| 4 | Spent-today + amount over the daily cap | block |
| 5 | Method not in the agent's allowed list | block |
| 6 | Receiver not in the agent's allowed list | block |
| 7 | Amount over the human-approval threshold | warn |
| 8 | First interaction, receiver not allowlisted | warn |
| 9 | Otherwise | allow |

## Data sources for each signal

The track prompt asks for the data source behind every signal. Current state
and the honest next step for each:

| Signal | Today (scaffold) | Production source |
|---|---|---|
| Shared blocklist + evidence | On-chain contract state (`report` with reason + evidence string) | Same, plus community reports; evidence = tx hash / report link, verified by readers |
| Allowlist | On-chain, owner-managed | Same |
| Account age / activity history | Not yet wired | NEAR RPC `view_account` (existence, balance) + NEARBlocks/FastNEAR indexer API (first tx, tx count) — public, no key |
| Receiver is a contract / code changed recently | Not yet wired | RPC `view_account` `code_hash` (contract vs EOA); code-change recency needs indexer history of code_hash by block |
| Prior agent↔receiver interactions | On-chain `seen` set + decision log | Same (authoritative), plus the agent's own history |
| Spending caps / velocity | On-chain policy + daily buckets | Same |

The off-chain enrichment (age, code hash) belongs in the wrapper's check
pipeline, not in the contract: the contract stays the source of truth for
lists and policies, and the wrapper adds read-only signals before deciding.
This keeps the contract small and the signals auditable.

## Limits of function-call keys (read this)

From the NEAR docs and the track prompt's own caveat:

- A function-call key is scoped to ONE receiver account, a list of method
  names, and a gas allowance. It cannot transfer NEAR, cannot add/delete keys,
  and cannot call other contracts.
- An account holding ONLY function-call keys can lock itself out if the gas
  allowance runs out: it cannot add a new key or receive NEAR by transfer
  from itself. Keep a full-access key with the human owner, offline.
- The allowance is per-key and decreases with use; the owner must top it up
  (a human action) before it empties.
- Function-call keys do NOT constrain arguments: a key for `ft_transfer`
  can send any amount to anyone. That is exactly why the policy contract
  exists — the key limits *where*, the policy limits *what*.

## Deploy to testnet (human step — needs a testnet account)

```sh
# 1. Create a testnet account in a NEAR wallet (human). Fund it free:
#    https://near-faucet.io (Q-008: testnet NEAR is free).
# 2. Install the toolchain once:
cargo install cargo-near   # builds + deploys NEAR contracts
# 3. Build + deploy (replace ACCOUNT):
cargo near deploy build-non-reproducible-wasm --manifest-path contract/Cargo.toml
near account create-account sponsor-by-faucet-service <sub>.testnet autogenerate-new-keypair save-to-keychain
#    -- or use an existing testnet account; then:
cargo near deploy <ACCOUNT> --manifest-path contract/Cargo.toml \
  --init-function new --init-args '{"owner":"<OWNER_ACCOUNT>"}'
# 4. Put the contract account id in the demo (section 7) and in PREP.md.
```

No mainnet deployment is needed for this hackathon (Q-010). Never deploy to
mainnet or spend real tokens without the team lead's explicit confirmation.

## Baseline & AI disclosure (Q-001–Q-005)

- All code in this repository was written during the hackathon window
  (1–14 Nov 2026) unless noted. No pre-existing product is reused.
- The code was written with AI assistance (an AI coding agent working with
  the team lead). AI-written code is allowed (Q-005); it is listed here, and
  the tests + demo above let any reviewer verify what it does.
- Dependencies: `near-sdk` (contract), Node.js standard library only for the
  demo/wrapper/CLI. No other libraries, templates, or boilerplate.
- License: MIT (Q-014). The repository stays public through judging.

## What is NOT here (yet)

- Live signal enrichment (account age, code_hash) — planned, see table above.
- TEE attestation for the agent runtime — out of scope for this window; the
  contract does not depend on it.
- Mainnet deployment, Intents settlement — follow-ups, not required (Q-007, Q-010).
- A second project by the same person — none (Q-015 allows at most 2).
