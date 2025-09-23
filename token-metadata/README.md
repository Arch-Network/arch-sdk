# arch_token_metadata (on-chain program)

Arch Token Metadata program for Arch/Solana-like runtime.

Features:

- Deterministic PDAs for token metadata and attributes
- Create, update, and immutable flows
- Efficient attribute storage and replacement semantics

Related crates:

- `arch_token_metadata_elf`: packaged ELF for deployment or tooling
- `arch_token_metadata_sdk`: Rust client SDK with instruction builders and readers
- `arch-token-metadata-cli`: CLI for inspection and common flows

Documentation:

- See `docs/SECURITY.md` for invariants and constraints
- See SDK README for usage examples and transaction builders

License: MIT
