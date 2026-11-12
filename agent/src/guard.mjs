// Agent-side guard: the wrapper every payment goes through.
//
// Flow for every proposed payment/call:
//   1. check  -> BLOCK: refuse to sign, throw RefusedError (nothing is sent)
//            -> WARN:  ask the human (approveFn); denied => refuse
//            -> ALLOW: proceed
//   2. sign   -> only reached on allow, or warn + human approval
//   3. record -> the outcome is written back (contract decision log / local log)
//
// The wrapper never holds a full-access key: the agent signs with a
// function-call access key scoped to ONE contract (see README, "Keys").
// This module is environment-agnostic: it works in Node and in the browser
// demo. It has no dependencies; the NEAR RPC adapter is rpcCheck() below.

import { evaluatePolicy, VERDICTS, formatYocto } from "../../shared/policy.mjs";

export class RefusedError extends Error {
  constructor(decision, action) {
    super(`refused (${decision.verdict}): ${decision.reasons.join("; ")}`);
    this.name = "RefusedError";
    this.decision = decision;
    this.action = action;
  }
}

export class GuardedAgent {
  /**
   * @param {object} deps
   * @param {(action) => Promise<{verdict: string, reasons: string[]}>} deps.checkFn
   * @param {(decision, action) => Promise<boolean>} deps.approveFn - human approval for WARN
   * @param {(action) => Promise<any>} deps.signerFn - signs + sends; only called when allowed
   * @param {(record) => Promise<void>} [deps.recordFn] - optional outcome recording
   * @param {(line: string) => void} [deps.log] - default: console.log
   */
  constructor({ checkFn, approveFn, signerFn, recordFn = null, log = console.log }) {
    this.checkFn = checkFn;
    this.approveFn = approveFn;
    this.signerFn = signerFn;
    this.recordFn = recordFn;
    this.log = log;
  }

  /** Proposed payment/call. Amounts are BigInt yoctoNEAR. */
  async pay({ receiver, amountYocto, method = "transfer" }) {
    const action = { receiver, amountYocto, method };
    const decision = await this.checkFn(action);
    const stamp = new Date().toISOString();
    const describe = `${formatYocto(amountYocto)} -> ${receiver} (${method})`;

    if (decision.verdict === VERDICTS.BLOCK) {
      this.log(`[${stamp}] BLOCK ${describe} | ${decision.reasons.join("; ")}`);
      throw new RefusedError(decision, action);
    }
    if (decision.verdict === VERDICTS.WARN) {
      this.log(`[${stamp}] WARN  ${describe} | ${decision.reasons.join("; ")} — asking human`);
      const approved = await this.approveFn(decision, action);
      if (!approved) {
        this.log(`[${stamp}] DENIED by human: ${describe}`);
        throw new RefusedError({ verdict: VERDICTS.BLOCK, reasons: ["human denied the warn"] }, action);
      }
      this.log(`[${stamp}] APPROVED by human: ${describe}`);
    } else {
      this.log(`[${stamp}] ALLOW ${describe} | ${decision.reasons.join("; ")}`);
    }

    const result = await this.signerFn(action);
    if (this.recordFn) {
      await this.recordFn({ ...action, verdict: decision.verdict, executed: true, at: stamp });
    }
    return result;
  }
}

/**
 * Build a checkFn from LOCAL state (no contract needed). Used by the demo,
 * the attack simulation, and tests. State shape:
 * {
 *   paused: boolean,
 *   blocklist: Map<receiver, {reason: string}>,
 *   allowlist: Set<receiver>,
 *   policy: object | null,          // shared/policy.mjs shape
 *   spentTodayYocto: bigint,
 *   seen: Set<"agent|receiver">,
 *   agentId: string,
 * }
 */
export function createLocalCheck(state) {
  return async ({ receiver, amountYocto, method }) => {
    return evaluatePolicy({
      paused: state.paused,
      blockEntry: state.blocklist.get(receiver) ?? null,
      policy: state.policy,
      spentTodayYocto: state.spentTodayYocto,
      receiver,
      amountYocto,
      method,
      allowlisted: state.allowlist.has(receiver),
      seenBefore: state.seen.has(`${state.agentId}|${receiver}`),
    });
  };
}

/**
 * Build a checkFn that queries a DEPLOYED PolicyGuard contract over JSON-RPC
 * (read-only view call, no wallet, no signing). Works in Node 18+ and browsers.
 */
export function createRpcCheck({ rpcUrl, contractId, agentId, fetchFn = fetch }) {
  return async ({ receiver, amountYocto, method }) => {
    const args = { agent: agentId, receiver, amount: amountYocto.toString(), method };
    const argsBase64 =
      typeof Buffer !== "undefined"
        ? Buffer.from(JSON.stringify(args), "utf8").toString("base64")
        : btoa(unescape(encodeURIComponent(JSON.stringify(args))));
    const res = await fetchFn(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "policy-guard-check",
        method: "query",
        params: {
          request_type: "call_function",
          account_id: contractId,
          method_name: "check",
          args_base64: argsBase64,
          finality: "final",
        },
      }),
    });
    const json = await res.json();
    if (json.error) throw new Error(`RPC error: ${JSON.stringify(json.error)}`);
    const bytes = json.result.result;
    const text = new TextDecoder().decode(new Uint8Array(bytes));
    return JSON.parse(text);
  };
}

/** Generic read-only view call helper (used by the demo's live-contract panel). */
export async function rpcView({ rpcUrl, contractId, method, args = {}, fetchFn = fetch }) {
  const argsBase64 =
    typeof Buffer !== "undefined"
      ? Buffer.from(JSON.stringify(args), "utf8").toString("base64")
      : btoa(unescape(encodeURIComponent(JSON.stringify(args))));
  const res = await fetchFn(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "policy-guard-view",
      method: "query",
      params: {
        request_type: "call_function",
        account_id: contractId,
        method_name: method,
        args_base64: argsBase64,
        finality: "final",
      },
    }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`RPC error: ${JSON.stringify(json.error)}`);
  return JSON.parse(new TextDecoder().decode(new Uint8Array(json.result.result)));
}
