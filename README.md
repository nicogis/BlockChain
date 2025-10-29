# BlockChain (PoA demo in C#/.NET 8)

A minimal Proof-of-Authority (PoA) blockchain prototype demonstrating:
- UTXO-based transactions with fee and fee-rate policy.
- Address derivation: legacy P2PKH (Base58Check) and native SegWit P2WPKH (Bech32).
- ECDSA signing/verification on secp256k1 using the Chilkat library.
- Merkle root computation and block header hashing.
- Round-robin leader selection and validator quorum for PoA.
- A tiny HTTP JSON RPC for inspecting the chain and submitting transactions.

This project is educational and not intended for production use.

## Features

- Crypto helpers for SHA-256, RIPEMD-160, HASH160, double-SHA256
- SEC1 compressed EC point extraction from public key PEM (SPKI)
- Base58Check and Bech32 encoders
- Minimal CBOR encoder used to measure realistic transaction size for fee-rate
- Mempool ordered by fee-rate (sat/byte), then fee, then tx hash
- PoA blockchain with:
  - Genesis block
  - Round-robin leader
  - Quorum K of N validator signatures over block hash
  - Merkle root verification
  - UTXO application with atomic state update
- HTTP JSON RPC endpoints

## Requirements

- .NET 8 SDK
- Chilkat .NET library available at runtime
- Chilkat unlock key provided via configuration or environment variable

## Configuration

Provide a Chilkat unlock key either via `appsettings.json` or an environment variable.

Example `appsettings.json` in the application directory: