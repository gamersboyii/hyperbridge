Commit aa2a7af0 (aa2a7af07fac664f2b1ef5f0e545504b93b7b8b3), tagged indexer-mainnet-v3.7.2, committed 2026-08-28 — subject: [indexer, sdk]:
Decode phantom bids of either fillOrder shape (#1186).

runtime/pallets/modules (`modules/`), EVM smart contracts (`evm/`), and parachain runtime wiring (`parachain/`). Only findings with an in-scope on-chain impact (fund loss, unauthorized state change, invariant violation, transaction/message manipulation, reentrancy, replay, accounting errors) are reported. Informational, gas, style and testnet-only-value issues are excluded.

---

## HIGH — Routed-fee double payout (shared fee pot)

**Location**
- `parachain/runtimes/nexus/src/ismp.rs:393-398` (`ProxyModule::on_accept`)
- `modules/pallets/relayer/src/accumulate.rs:48-170`
- `modules/ismp/core/src/handlers/timeout.rs:107-111`
- `evm/src/core/HandlerV2.sol:254-321`
- `evm/src/core/EvmHost.sol:856-906` (`dispatchTimeOut`)

**Summary**

On the routed path (EVM → Hyperbridge → EVM), the relayer fee is escrowed once on the source EVM under `_requestCommitments[C]`, but Hyperbridge independently settles that same fee through two uncoordinated mechanisms:

1. `pallet_ismp_relayer::accumulate` reads the fee from a **source-chain state proof** (`source_fee_commitment_keys` / `validate_results`, `accumulate.rs:238-302`) and credits `Fees[state_machine][address]`.
2. `EvmHost.dispatchTimeOut` refunds the same `fee` out of the source `_requestCommitments[C]` on timeout.

There is no cross-chain lock tying the two together.

**Root cause**

`ProxyModule::on_accept` re-dispatches the *identical* `Request` object with a zero fee (`ismp.rs:394-397`). Because `hash_request` (`modules/ismp/core/src/messaging.rs:253-256`) uses chain-independent ABI encoding, the routed commitment `C` is byte-for-byte identical on the source EVM and on Hyperbridge.

- The source EVM stores `_requestCommitments[C] = {sender, fee}` (the real user fee).
- Hyperbridge stores its own `RequestCommitments[C] = {fee = 0, claimed}` — a *separate* entry used only for `accumulate`'s claim tracking.

`accumulate` filters on `RequestCommitments::<T>::get(req).claimed` (`accumulate.rs:62-63`) and sets `claimed = true` after credit (`accumulate.rs:153-161`). This `claimed` flag lives only on Hyperbridge's copy.

**Failure of the timeout path**

`timeout.rs:107` calls `host.delete_request_commitment(&request)` **without checking the `claimed` flag**, and for routed requests `timeout.rs:110-111` also deletes the leg-1 receipt:

```rust
if host.host_state_machine() != post.source {
    signer = host.delete_request_receipt(&request).ok();
}
```

Deleting that receipt is exactly what makes the EVM-side timeout non-membership proof (`HandlerV2.sol:281` — `REQUEST_RECEIPTS_STORAGE_PREFIX || requestCommitment` must be empty) provable again.

**Attack path**

1. A user dispatches a routed request EVM → Hyperbridge → EVM, paying `fee` (escrowed in `_requestCommitments[C]` on the source EVM).
2. A relayer proves delivery (source fee proof + destination receipt proof) and calls `accumulate_fees`, collecting `fee` into `Fees[]` on Hyperbridge. Hyperbridge's `RequestCommitments[C].claimed` is set to `true`.
3. Independently — either before or after — the timeout for `C` is processed on the EVM side: `HandlerV2.handlePostRequestTimeouts` verifies non-membership of the leg-1 receipt (which `timeout.rs:111` deletes) and calls `EvmHost.dispatchTimeOut`, which refunds `fee` to `meta.sender`.
4. Both settle the same escrowed `fee`, so the protocol pays out 2× the escrowed amount from the shared fee pot.

The `claimed` flag does not prevent the EVM refund (it is in a different chain's storage), and the EVM refund does not check whether Hyperbridge already paid via `accumulate`. The process is fully permissionless and repeatable across routed commitments.

**Affected invariant**: a relayer fee must be settled exactly once.

**Impact**: loss of protocol funds — double payout of escrowed relayer fees.

---

## MEDIUM — Unauthenticated relayer attribution in receipts

**Location**
- `modules/utils/crypto/src/verification.rs:109-115` (`Signature::signer`)
- `modules/pallets/ismp/src/host.rs:351-359` (`extract_signer`)
- Consumers: `modules/pallets/ismp/src/host.rs:261-283` (`store_request_receipt` / `store_response_receipt`)

**Summary**

`Signature::signer()` returns the **embedded** `address` / `public_key` field verbatim without any cryptographic verification:

```rust
pub fn signer(&self) -> Vec<u8> {
    match self {
        Signature::Evm { address, .. } => address.clone(),
        Signature::Sr25519 { public_key, .. } => public_key.clone(),
        Signature::Ed25519 { public_key, .. } => public_key.clone(),
    }
}
```

`extract_signer` uses this for incoming message receipts (`signer.len() > 32`):

```rust
fn extract_signer(signer: &[u8]) -> Result<Vec<u8>, Error> {
    if signer.len() > 32 {
        Signature::decode(&mut signer.as_ref())
            .map(|sig| sig.signer())   // decode + extract, NO verify
            .map_err(|_| Error::SignatureDecodingFailed)
    } else {
        Ok(signer.to_vec())
    }
}
```

The receipt relayer is therefore whatever the signer field claims, not a cryptographically verified identity. Any party can attribute a delivery (and any downstream relayer-fee credit that keys off the receipt) to an arbitrary address.

**Affected invariant**: the relayer recorded in a receipt is the account that actually delivered the message.

**Impact**: untrusted relayer attribution — a prerequisite for fee-credit manipulation in any logic that trusts the receipt's recorded relayer.

---

## MEDIUM — HandlerV2 timeouts do not bind proof height to `request.dest`

**Location**
- `evm/src/core/HandlerV2.sol:254-321` (`handlePostRequestTimeouts`, `handleGetRequestTimeouts`)

**Summary**

Both timeout handlers fetch the state commitment purely from `message.height` and use it for the non-membership proof, but never verify that the state machine identified by `message.height.stateMachineId` corresponds to `request.dest`:

```solidity
StateCommitment memory state = host.stateMachineCommitment(message.height);
if (state.stateRoot == bytes32(0)) revert StateCommitmentNotFound();
// ...
if (request.timeout() > state.timestamp) revert MessageNotTimedOut();
// ...
bytes[] memory keys = new bytes[](1);
keys[0] = bytes.concat(REQUEST_RECEIPTS_STORAGE_PREFIX, requestCommitment);
PolkadotTrie.StorageValue memory entry = PolkadotTrie.VerifyProof(state.stateRoot, message.proof, keys)[0];
```

The Rust core performs the equivalent binding explicitly (`modules/ismp/core/src/handlers/timeout.rs:65`):

```rust
if dest_chain != timeout_proof.height.id.state_id && !allow_proxy {
    Err(Error::RequestProxyProhibited { meta: post.into() })?
}
```

**Affected invariant**: a timeout proof may only be used against the request's own destination state machine.

**Impact**: latent — only becomes exploitable once a second state machine is allowlisted, at which point a timeout proof for one chain could be steered against requests destined for another. Not exploitable with a single allowlisted state machine today.

---

## MEDIUM — `pallet_assets::CreateOrigin = EnsureSigned` (Gargantua)

**Location**
- `parachain/runtimes/gargantua/src/ismp.rs:356`

**Summary**

Gargantua configures `pallet_assets` so that **any signed account** can create a new asset:

```rust
type CreateOrigin = AsEnsureOriginWithArg<frame_system::EnsureSigned<AccountId32>>;
```

The reputation asset is keyed by a fixed, well-known identifier (`ReputationAssetId`, `gargantua/src/lib.rs:781`). If that asset is not already reserved/created at genesis, an attacker can race to call `pallet_assets::create` with the fixed id, becoming the asset's admin, and then use admin privileges (mint / force-transfer) over the reputation asset that underpins collator-set management.

**Affected invariant**: the reputation asset is created and owned only by governance.

**Impact**: latent — depends on whether the fixed reputation asset id is pre-created in the genesis configuration. If un-created, this is a collator-set capture vector via forged reputation.
