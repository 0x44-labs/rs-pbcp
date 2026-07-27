// @generated file from wasmbuild -- do not edit
// deno-lint-ignore-file
// deno-fmt-ignore-file

export class Grid {
	private constructor();
	free(): void;
	[Symbol.dispose](): void;
	col(col: number): Uint8Array;
	data(): Uint8Array;
	get(row: number, col: number): number;
	static new(size: number, data: Uint8Array): Grid | undefined;
	row(row: number): Uint8Array;
}

export class Params {
	free(): void;
	[Symbol.dispose](): void;
	constructor(n: number, s: number, x: bigint, l: bigint);
	/**
	 * Time Step Count
	 */
	l: bigint;
	/**
	 * PoW Constraint
	 */
	n: number;
	/**
	 * Similarity Threshold
	 */
	s: number;
	/**
	 * Time Step Width
	 */
	x: bigint;
}

export class Proof {
	free(): void;
	[Symbol.dispose](): void;
	answer(): Grid;
	static decode(value: Uint8Array): Proof;
	encode(): Uint8Array;
	constructor(sid: Uint8Array, answer: Grid, nonce: bigint);
	nonce(): bigint;
	sid(): Uint8Array;
}

export class Session {
	free(): void;
	[Symbol.dispose](): void;
	cid(): Uint8Array;
	constructor(
		sid: Uint8Array,
		cid: Uint8Array,
		params: Params,
		start_step: bigint
	);
	params(): Params;
	sid(): Uint8Array;
	start_step(): bigint;
}

export function build_proof(session: Session, answer: Grid): Proof;

export function load_session(
	sid: Uint8Array,
	n: number,
	s: number,
	x: bigint,
	l: bigint,
	cid: Uint8Array,
	start_step: bigint
): Session;

export function start_session(
	sid: Uint8Array,
	n: number,
	s: number,
	x: bigint,
	l: bigint,
	cid: Uint8Array
): Session;

export function valid_step_range(session: Session): BigUint64Array;

export function verify_proof(session: Session, proof: Proof): boolean;
