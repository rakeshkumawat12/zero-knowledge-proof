# Zero-Knowledge Proof (ZKP) Demo

A simple implementation of **Zero-Knowledge Proofs** demonstrating how one party (the prover) can prove to another party (the verifier) that they know a value **without revealing the value itself**.  


## What is a Zero-Knowledge Proof?

A **Zero-Knowledge Proof** allows you to prove knowledge of a secret without revealing the secret itself.  
For example:  
> You can prove you know a password without ever showing the password.

This is a fundamental concept for **privacy-preserving cryptography**, blockchain scalability, and identity verification.

## Install & Setup

To run server first
```
cargo run --bin server
```

Than good to go with client
```
cargo run --bin client
```