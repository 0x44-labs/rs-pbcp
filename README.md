# Proof-Bound Claims Protocol (PBCP)

![Crates.io Version](https://img.shields.io/crates/v/pbcp)
![Crates.io License](https://img.shields.io/crates/l/pbcp)
![docs.rs](https://img.shields.io/docsrs/pbcp)

Pure Rust implementation of a protocol for producing claims whose assertion is backed by proof of resources spent.

[Documentation](https://docs.rs/pbcp/)

## About

Every PBCP exchange consists of two roles. A **Verifier** issues challenges, each with the difficulty level a proof must meet, and judges the responses received. It authenticates each challenge with its own key, so recognising a challenge requires no stored state. A challenge is single-use and expires, protecting against replay. A **Prover** responds to challenges by providing a claims set and searching for a nonce value over it that satisfies the challenge's difficulty. The proof is bound to both the challenge and the claims set, and demonstrates the memory and CPU work the challenge demands was performed.

Challenges, proofs, and outcomes can be serialised as `pbcp://` URIs. Byte representations of challenges and proofs are serialised as CBOR bytes, and claims sets as canonical JSON bytes.

A replay store records used challenges, either in memory or through an external backend.

## Minimum Supported Rust Version

Rust **1.85.1** or higher.

## License

Licensed under the [MIT License](https://opensource.org/license/MIT).
