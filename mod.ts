import type { Grid, Session } from "./lib/rs_lib.js";
import {
	build_proof,
	load_session,
	Proof,
	start_session,
	valid_step_range,
	verify_proof
} from "./lib/rs_lib.js";
import { base32nopad } from "npm:@scure/base@2.2.0";

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

/** Encode a TLPH challenge as a URI. */
export function encodeChallenge(
	sid: Uint8Array,
	n: number,
	s: number,
	x: bigint,
	l: bigint,
	cid: Uint8Array
): string {
	const url = new URL("tlph://challenge");

	url.searchParams.set("sid", base32nopad.encode(sid));
	url.searchParams.set("n", String(n));
	url.searchParams.set("s", String(s));
	url.searchParams.set("x", String(x));
	url.searchParams.set("l", String(l));
	url.searchParams.set("cid", base32nopad.encode(cid));

	return url.href;
}

/** Decode a TLPH challenge from a URI. */
export function decodeChallenge(uri: string) {
	const url = new URL(uri);
	if (url.protocol !== "tlph:" || url.hostname !== "challenge") {
		throw new Error(`Invalid TLPH challenge URI: "${uri}"`);
	}

	const p = url.searchParams;
	return {
		sid: base32nopad.decode(p.get("sid")!),
		n: Number(p.get("n")),
		s: Number(p.get("s")),
		x: BigInt(p.get("x")!),
		l: BigInt(p.get("l")!),
		cid: base32nopad.decode(p.get("cid")!)
	};
}

/** Encode a TLPH proof as a URI. */
export function encodeProof(proof: Proof): string {
	const url = new URL("tlph://proof");
	url.pathname = `/${base32nopad.encode(proof.encode())}`;
	return url.href;
}

/** Decode a TLPH proof from a URI. */
export function decodeProof(uri: string): Proof {
	const url = new URL(uri);
	if (url.protocol !== "tlph:" || url.hostname !== "proof") {
		throw new Error(`Invalid TLPH proof URI: "${uri}"`);
	}
	return Proof.decode(base32nopad.decode(url.pathname.slice(1)));
}
