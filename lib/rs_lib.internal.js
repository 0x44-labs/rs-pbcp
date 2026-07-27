// @generated file from wasmbuild -- do not edit
// @ts-nocheck: generated
// deno-lint-ignore-file
// deno-fmt-ignore-file

export class Grid {
	static __wrap(ptr) {
		ptr = ptr >>> 0;
		const obj = Object.create(Grid.prototype);
		obj.__wbg_ptr = ptr;
		GridFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		GridFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_grid_free(ptr, 0);
	}
	/**
	 * @param {number} col
	 * @returns {Uint8Array}
	 */
	col(col) {
		const ret = wasm.grid_col(this.__wbg_ptr, col);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	 * @returns {Uint8Array}
	 */
	data() {
		const ret = wasm.grid_data(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	 * @param {number} row
	 * @param {number} col
	 * @returns {number}
	 */
	get(row, col) {
		const ret = wasm.grid_get(this.__wbg_ptr, row, col);
		return ret;
	}
	/**
	 * @param {number} size
	 * @param {Uint8Array} data
	 * @returns {Grid | undefined}
	 */
	static new(size, data) {
		const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
		const len0 = WASM_VECTOR_LEN;
		const ret = wasm.grid_new(size, ptr0, len0);
		return ret === 0 ? undefined : Grid.__wrap(ret);
	}
	/**
	 * @param {number} row
	 * @returns {Uint8Array}
	 */
	row(row) {
		const ret = wasm.grid_row(this.__wbg_ptr, row);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
}
if (Symbol.dispose) { Grid.prototype[Symbol.dispose] = Grid.prototype.free; }

export class Params {
	static __wrap(ptr) {
		ptr = ptr >>> 0;
		const obj = Object.create(Params.prototype);
		obj.__wbg_ptr = ptr;
		ParamsFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		ParamsFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_params_free(ptr, 0);
	}
	/**
	 * Time Step Count
	 * @returns {bigint}
	 */
	get l() {
		const ret = wasm.__wbg_get_params_l(this.__wbg_ptr);
		return BigInt.asUintN(64, ret);
	}
	/**
	 * PoW Constraint
	 * @returns {number}
	 */
	get n() {
		const ret = wasm.__wbg_get_params_n(this.__wbg_ptr);
		return ret;
	}
	/**
	 * Similarity Threshold
	 * @returns {number}
	 */
	get s() {
		const ret = wasm.__wbg_get_params_s(this.__wbg_ptr);
		return ret;
	}
	/**
	 * Time Step Width
	 * @returns {bigint}
	 */
	get x() {
		const ret = wasm.__wbg_get_params_x(this.__wbg_ptr);
		return BigInt.asUintN(64, ret);
	}
	/**
	 * @param {number} n
	 * @param {number} s
	 * @param {bigint} x
	 * @param {bigint} l
	 */
	constructor(n, s, x, l) {
		const ret = wasm.params_new(n, s, x, l);
		this.__wbg_ptr = ret >>> 0;
		ParamsFinalization.register(this, this.__wbg_ptr, this);
		return this;
	}
	/**
	 * Time Step Count
	 * @param {bigint} arg0
	 */
	set l(arg0) {
		wasm.__wbg_set_params_l(this.__wbg_ptr, arg0);
	}
	/**
	 * PoW Constraint
	 * @param {number} arg0
	 */
	set n(arg0) {
		wasm.__wbg_set_params_n(this.__wbg_ptr, arg0);
	}
	/**
	 * Similarity Threshold
	 * @param {number} arg0
	 */
	set s(arg0) {
		wasm.__wbg_set_params_s(this.__wbg_ptr, arg0);
	}
	/**
	 * Time Step Width
	 * @param {bigint} arg0
	 */
	set x(arg0) {
		wasm.__wbg_set_params_x(this.__wbg_ptr, arg0);
	}
}
if (Symbol.dispose) { Params.prototype[Symbol.dispose] =
		Params.prototype.free; }

export class Proof {
	static __wrap(ptr) {
		ptr = ptr >>> 0;
		const obj = Object.create(Proof.prototype);
		obj.__wbg_ptr = ptr;
		ProofFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		ProofFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_proof_free(ptr, 0);
	}
	/**
	 * @returns {Grid}
	 */
	answer() {
		const ret = wasm.proof_answer(this.__wbg_ptr);
		return Grid.__wrap(ret);
	}
	/**
	 * @param {Uint8Array} value
	 * @returns {Proof}
	 */
	static decode(value) {
		const ptr0 = passArray8ToWasm0(value, wasm.__wbindgen_malloc);
		const len0 = WASM_VECTOR_LEN;
		const ret = wasm.proof_decode(ptr0, len0);
		if (ret[2]) {
			throw takeFromExternrefTable0(ret[1]);
		}
		return Proof.__wrap(ret[0]);
	}
	/**
	 * @returns {Uint8Array}
	 */
	encode() {
		const ret = wasm.proof_encode(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	 * @param {Uint8Array} sid
	 * @param {Grid} answer
	 * @param {bigint} nonce
	 */
	constructor(sid, answer, nonce) {
		const ptr0 = passArray8ToWasm0(sid, wasm.__wbindgen_malloc);
		const len0 = WASM_VECTOR_LEN;
		_assertClass(answer, Grid);
		var ptr1 = answer.__destroy_into_raw();
		const ret = wasm.proof_new(
			ptr0,
			len0,
			ptr1,
			nonce,
			nonce >> BigInt(64)
		);
		this.__wbg_ptr = ret >>> 0;
		ProofFinalization.register(this, this.__wbg_ptr, this);
		return this;
	}
	/**
	 * @returns {bigint}
	 */
	nonce() {
		const ret = wasm.proof_nonce(this.__wbg_ptr);
		return (BigInt.asUintN(64, ret[0]) |
			(BigInt.asUintN(64, ret[1]) << BigInt(64)));
	}
	/**
	 * @returns {Uint8Array}
	 */
	sid() {
		const ret = wasm.proof_sid(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
}
if (Symbol.dispose) { Proof.prototype[Symbol.dispose] = Proof.prototype.free; }

export class Session {
	static __wrap(ptr) {
		ptr = ptr >>> 0;
		const obj = Object.create(Session.prototype);
		obj.__wbg_ptr = ptr;
		SessionFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		SessionFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_session_free(ptr, 0);
	}
	/**
	 * @returns {Uint8Array}
	 */
	cid() {
		const ret = wasm.session_cid(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	 * @param {Uint8Array} sid
	 * @param {Uint8Array} cid
	 * @param {Params} params
	 * @param {bigint} start_step
	 */
	constructor(sid, cid, params, start_step) {
		const ptr0 = passArray8ToWasm0(sid, wasm.__wbindgen_malloc);
		const len0 = WASM_VECTOR_LEN;
		const ptr1 = passArray8ToWasm0(cid, wasm.__wbindgen_malloc);
		const len1 = WASM_VECTOR_LEN;
		_assertClass(params, Params);
		var ptr2 = params.__destroy_into_raw();
		const ret = wasm.session_new(ptr0, len0, ptr1, len1, ptr2, start_step);
		this.__wbg_ptr = ret >>> 0;
		SessionFinalization.register(this, this.__wbg_ptr, this);
		return this;
	}
	/**
	 * @returns {Params}
	 */
	params() {
		const ret = wasm.session_params(this.__wbg_ptr);
		return Params.__wrap(ret);
	}
	/**
	 * @returns {Uint8Array}
	 */
	sid() {
		const ret = wasm.session_sid(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	 * @returns {bigint}
	 */
	start_step() {
		const ret = wasm.session_start_step(this.__wbg_ptr);
		return BigInt.asUintN(64, ret);
	}
}
if (Symbol.dispose) { Session.prototype[Symbol.dispose] =
		Session.prototype.free; }

/**
 * @param {Session} session
 * @param {Grid} answer
 * @returns {Proof}
 */
export function build_proof(session, answer) {
	_assertClass(session, Session);
	_assertClass(answer, Grid);
	var ptr0 = answer.__destroy_into_raw();
	const ret = wasm.build_proof(session.__wbg_ptr, ptr0);
	return Proof.__wrap(ret);
}

/**
 * @param {Uint8Array} sid
 * @param {number} n
 * @param {number} s
 * @param {bigint} x
 * @param {bigint} l
 * @param {Uint8Array} cid
 * @param {bigint} start_step
 * @returns {Session}
 */
export function load_session(sid, n, s, x, l, cid, start_step) {
	const ptr0 = passArray8ToWasm0(sid, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(cid, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ret = wasm.load_session(
		ptr0,
		len0,
		n,
		s,
		x,
		l,
		ptr1,
		len1,
		start_step
	);
	return Session.__wrap(ret);
}

/**
 * @param {Uint8Array} sid
 * @param {number} n
 * @param {number} s
 * @param {bigint} x
 * @param {bigint} l
 * @param {Uint8Array} cid
 * @returns {Session}
 */
export function start_session(sid, n, s, x, l, cid) {
	const ptr0 = passArray8ToWasm0(sid, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(cid, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ret = wasm.start_session(ptr0, len0, n, s, x, l, ptr1, len1);
	return Session.__wrap(ret);
}

/**
 * @param {Session} session
 * @returns {BigUint64Array}
 */
export function valid_step_range(session) {
	_assertClass(session, Session);
	const ret = wasm.valid_step_range(session.__wbg_ptr);
	var v1 = getArrayU64FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 8, 8);
	return v1;
}

/**
 * @param {Session} session
 * @param {Proof} proof
 * @returns {boolean}
 */
export function verify_proof(session, proof) {
	_assertClass(session, Session);
	_assertClass(proof, Proof);
	const ret = wasm.verify_proof(session.__wbg_ptr, proof.__wbg_ptr);
	return ret !== 0;
}
export function __wbg_Error_8c4e43fe74559d73(arg0, arg1) {
	const ret = Error(getStringFromWasm0(arg0, arg1));
	return ret;
}
export function __wbg___wbindgen_throw_be289d5034ed271b(arg0, arg1) {
	throw new Error(getStringFromWasm0(arg0, arg1));
}
export function __wbindgen_init_externref_table() {
	const table = wasm.__wbindgen_externrefs;
	const offset = table.grow(4);
	table.set(0, undefined);
	table.set(offset + 0, undefined);
	table.set(offset + 1, null);
	table.set(offset + 2, true);
	table.set(offset + 3, false);
}
const GridFinalization = (typeof FinalizationRegistry === "undefined")
	? { register: () => {}, unregister: () => {} }
	: new FinalizationRegistry((ptr) => wasm.__wbg_grid_free(ptr >>> 0, 1));
const ParamsFinalization = (typeof FinalizationRegistry === "undefined")
	? { register: () => {}, unregister: () => {} }
	: new FinalizationRegistry((ptr) => wasm.__wbg_params_free(ptr >>> 0, 1));
const ProofFinalization = (typeof FinalizationRegistry === "undefined")
	? { register: () => {}, unregister: () => {} }
	: new FinalizationRegistry((ptr) => wasm.__wbg_proof_free(ptr >>> 0, 1));
const SessionFinalization = (typeof FinalizationRegistry === "undefined")
	? { register: () => {}, unregister: () => {} }
	: new FinalizationRegistry((ptr) => wasm.__wbg_session_free(ptr >>> 0, 1));

function _assertClass(instance, klass) {
	if (!(instance instanceof klass)) {
		throw new Error(`expected instance of ${klass.name}`);
	}
}

function getArrayU64FromWasm0(ptr, len) {
	ptr = ptr >>> 0;
	return getBigUint64ArrayMemory0().subarray(ptr / 8, ptr / 8 + len);
}

function getArrayU8FromWasm0(ptr, len) {
	ptr = ptr >>> 0;
	return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedBigUint64ArrayMemory0 = null;
function getBigUint64ArrayMemory0() {
	if (
		cachedBigUint64ArrayMemory0 === null ||
		cachedBigUint64ArrayMemory0.byteLength === 0
	) {
		cachedBigUint64ArrayMemory0 = new BigUint64Array(wasm.memory.buffer);
	}
	return cachedBigUint64ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
	ptr = ptr >>> 0;
	return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
	if (
		cachedUint8ArrayMemory0 === null ||
		cachedUint8ArrayMemory0.byteLength === 0
	) {
		cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
	}
	return cachedUint8ArrayMemory0;
}

function passArray8ToWasm0(arg, malloc) {
	const ptr = malloc(arg.length * 1, 1) >>> 0;
	getUint8ArrayMemory0().set(arg, ptr / 1);
	WASM_VECTOR_LEN = arg.length;
	return ptr;
}

function takeFromExternrefTable0(idx) {
	const value = wasm.__wbindgen_externrefs.get(idx);
	wasm.__externref_table_dealloc(idx);
	return value;
}

let cachedTextDecoder = new TextDecoder("utf-8", {
	ignoreBOM: true,
	fatal: true
});
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
	numBytesDecoded += len;
	if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
		cachedTextDecoder = new TextDecoder("utf-8", {
			ignoreBOM: true,
			fatal: true
		});
		cachedTextDecoder.decode();
		numBytesDecoded = len;
	}
	return cachedTextDecoder.decode(
		getUint8ArrayMemory0().subarray(ptr, ptr + len)
	);
}

let WASM_VECTOR_LEN = 0;

let wasm;
export function __wbg_set_wasm(val) {
	wasm = val;
}
