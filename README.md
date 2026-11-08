## Lazarus Contracts

Soroban smart contracts (`#![no_std]`, `soroban-sdk` v27, target `wasm32v1-none`) implementing the **Decoupled Voucher Pattern** escrow vault for the Lazarus Protocol.

---

### Testnet Deployment

| Parameter | Value |
| :--- | :--- |
| **Network** | Stellar Testnet |
| **Vault Contract ID** | `CCWAH7BVPGYOEBPRFWPZIONBYUCCQH7OARGZLOD6ZV66SOAFBVA2DHD5` |
| **WASM Hash** | `f269dcf6ad077039d468936511ad16be5a8867d61a0105a20b6615e13eb70459` |
| **Escrow Payment Token (SAC)** | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |
| **Oracle / FROST Group PubKey** | `197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61` |
| **Explorer** | [stellar.expert/explorer/testnet/contract/CCWAH7...](https://stellar.expert/explorer/testnet/contract/CCWAH7BVPGYOEBPRFWPZIONBYUCCQH7OARGZLOD6ZV66SOAFBVA2DHD5) |
| **Web Console** | [https://lazarusprotocol.online/](https://lazarusprotocol.online/) |

---

### Core Protocol Invariants

* **Native `i128` Precision:** CAP-0046 / SEP-41 compliant accounting for SAC escrow reserves, bounties, and fees.
* **Non-Custodial Escrow:** Client-funded escrow pools dedicated exclusively to verifiable state extension bounties.
* **Replay-Safe Keeper Nonces:** Out-of-order batch tolerance via per-voucher redemption tracking and keeper high-water marks.
* **Dual Outflow Circuit Breakers:** Enforces global and per-contract hourly outflow caps to prevent drain griefing.
* **Domain-Separated Verification:** Validates canonical XDR `LAZARUS_VOUCHER_V1` payloads signed by Ed25519 / 2-of-3 FROST group key.
* **Batched Redemption (`MAX_BATCH_SIZE = 10`):** Settles up to 10 keeper vouchers in a single transaction with a 5% protocol fee surcharge.
* **Self-Preserving Storage:** Automatically extends instance and persistent storage TTLs on every contract mutation.

---

### Build & Test

```bash
# Run unit test suite
cargo test

# Build optimized Wasm binary (wasm32v1-none)
stellar contract build
```
