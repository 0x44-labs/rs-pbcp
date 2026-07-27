import type { Grid, Proof, Session } from "./lib/rs_lib.js";
import {
	build_proof,
	load_session,
	start_session,
	valid_step_range,
	verify_proof
} from "./lib/rs_lib.js";

export type { Grid, Params, Proof, Session } from "./lib/rs_lib.js";

/** Start a new TLPH session. */
export function startSession(
	sid: Uint8Array,
	n: number,
	s: number,
	x: bigint,
	l: bigint,
	cid: Uint8Array
): Session {
	return start_session(sid, n, s, x, l, cid);
}

/** Resume an existing TLPH session by time step. */
export function loadSession(
	sid: Uint8Array,
	n: number,
	s: number,
	x: bigint,
	l: bigint,
	cid: Uint8Array,
	startStep: bigint
): Session {
	return load_session(sid, n, s, x, l, cid, startStep);
}

/**
 * Build a TLPH proof, binding a visual reasoning challenge answer to session
 * context through a mined proof-of-work solution.
 */
export function buildProof(session: Session, answer: Grid): Proof {
	return build_proof(session, answer);
}

/** List every time step a given TLPH session is active for. */
export function validStepRange(session: Session): BigUint64Array {
	return valid_step_range(session);
}

/** Verify a TPH proof against a session. */
export function verifyProof(session: Session, proof: Proof): boolean {
	return verify_proof(session, proof);
}
