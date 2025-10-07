# Sequence audit details
- Total Prize Pool: $73,000 in USDC
  - HM awards: up to $67,200 in USDC 
    - If no valid Highs or Mediums are found, the HM pool is $0 
  - QA awards: $2,800 in USDC
  - Judge awards: $2,500 in USDC
  - Scout awards: $500 in USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts October 7, 2025 20:00 UTC 
- Ends October 22, 2025 20:00 UTC 

**❗ Important notes for wardens** 
1. A coded, runnable PoC is required for all High/Medium submissions to this audit. 
  - This repo includes several test suites each focusing on a dedicated file of the contracts in scope.
  - PoCs must either use the test suites within the repository or build a new one executable under the `test` subfolder.
  - Your submission will be marked as Insufficient if the POC is not runnable and working.
  - Exception: PoC is optional (though recommended) for wardens with signal ≥ 0.68.
2. Judging phase risk adjustments (upgrades/downgrades):
  - High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
  - Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
  - As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.


## Automated Findings / Publicly Known Issues

The 4naly3er report will be found [here](https://github.com/code-423n4/YYYY-MM-contest-candidate/blob/main/4naly3er-report.md) and will be added **within 24 hours of the contest's start**.

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

### Configurational Assumptions

* There are multiple ways for a user to brick the wallet (e.g., setting an invalid imageHash, using a set of signers that doesn't reach the threshold, losing the contents of the tree, etc.); these contracts are meant to be used with an SDK that guards against those scenarios, which are beyond the scope of the audit.
* Hooks are meant to have admin privileges; it is expected that once installed, they have full rein to affect the wallet. The SDK guards against installing non-whitelisted hooks.
* It is possible to define a configuration tree so large that attempting to use it may cause out-of-gas errors; this is a known issue and the SDK guards against that scenario.

### Off-Chain Assumptions

* Exploits that involve tricking a relayer into relaying a transaction that fails and never pays for gas are out of scope; the relayer has its own layer of protections that are independent from the contracts.
* It is possible to desync the wallet across chains if the signers sign configuration updates with `chainId != 0`, or if they perform a one-off configuration or implementation update on-chain. The signers are responsible for not doing this to keep the chains in sync; the SDK handles it automatically.

### Operational Assumptions

* Rule changes immediately reset usage limits for a permission; this is a known issue.
* Calls with value are not forwarded to the implementation; this is by design. The `payable` modifiers are a gas optimization to avoid checking `msg.value` twice.

### Signer Assumptions

* When sending a transaction, the signers have free rein to update the wallet configuration and implementation; this is by design. The calls can be restricted if needed using sapient signers.
* Intermediary configurations of the state channel (that haven't been invalidated by the checkpointer) are usable. To properly evict a removed signer, the configuration has to be updated on-chain or the checkpointer must reflect the change.
* Signature malleability is not a concern, as signatures are not expected to be unique.

# Overview

Sequence Ecosystem Wallet is a non-custodial smart wallet designed for chains and ecosystems. It combines passkeys, social auth, timed recovery keys, and sandboxed permissions to deliver higher security with less friction.

The codebase represents the V3 implementation of this infrastructure, utilizing a minimal proxy pattern and a novel Merkle-proof based configuration approach for smart wallets.

## Links

- **Previous audits:**  Audits can be found here: 
    - Consensys Diligence: https://github.com/0xsequence/wallet-contracts-v3/blob/master/audits/consensys-audit.pdf
    - Quantstamp Audit: https://github.com/0xsequence/wallet-contracts-v3/blob/master/audits/consensys-audit.pdf
    - Rotcivegaf Audit: https://github.com/0xsequence/wallet-contracts-v3/blob/master/audits/rotcivegaf-audit.md
- **Documentation:** https://github.com/0xsequence/wallet-contracts-v3/tree/master/docs
- **Website:** https://sequence.xyz/
- **X/Twitter:** https://x.com/0xsequence

---

# Scope

### Files in scope


| File   | 
|---|
| [src/Factory.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/Factory.sol) | 
| [src/Guest.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/Guest.sol) | 
| [src/Stage1Module.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/Stage1Module.sol) | 
| [src/Stage2Module.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/Stage2Module.sol) | 
| [src/Wallet.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/Wallet.sol) | 
| [src/extensions/passkeys/Passkeys.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/passkeys/Passkeys.sol) | 
| [src/extensions/recovery/Recovery.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/recovery/Recovery.sol) | 
| [src/extensions/sessions/SessionErrors.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/SessionErrors.sol) | 
| [src/extensions/sessions/SessionManager.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/SessionManager.sol) | 
| [src/extensions/sessions/SessionSig.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/SessionSig.sol) | 
| [src/extensions/sessions/explicit/ExplicitSessionManager.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/explicit/ExplicitSessionManager.sol) |
| [src/extensions/sessions/explicit/IExplicitSessionManager.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/explicit/IExplicitSessionManager.sol) |
| [src/extensions/sessions/explicit/Permission.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/explicit/Permission.sol) | 
| [src/extensions/sessions/explicit/PermissionValidator.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/explicit/PermissionValidator.sol) | 
| [src/extensions/sessions/implicit/Attestation.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/implicit/Attestation.sol) | 
| [src/extensions/sessions/implicit/ISignalsImplicitMode.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/implicit/ISignalsImplicitMode.sol) | 
| [src/extensions/sessions/implicit/ImplicitSessionManager.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/extensions/sessions/implicit/ImplicitSessionManager.sol) | 
| [src/modules/Calls.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/Calls.sol) | 
| [src/modules/ERC4337v07.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/ERC4337v07.sol) | 
| [src/modules/Hooks.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/Hooks.sol) | 
| [src/modules/Implementation.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/Implementation.sol) | 
| [src/modules/Nonce.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/Nonce.sol) | 
| [src/modules/Payload.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/Payload.sol) | 
| [src/modules/ReentrancyGuard.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/ReentrancyGuard.sol) | 
| [src/modules/Storage.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/Storage.sol) | 
| [src/modules/auth/BaseAuth.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/auth/BaseAuth.sol) | 
| [src/modules/auth/BaseSig.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/auth/BaseSig.sol) | 
| [src/modules/auth/SelfAuth.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/auth/SelfAuth.sol) |
| [src/modules/auth/Stage1Auth.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/auth/Stage1Auth.sol) |
| [src/modules/auth/Stage2Auth.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/auth/Stage2Auth.sol) | 
| [src/modules/interfaces/IAccount.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IAccount.sol) | 
| [src/modules/interfaces/IAuth.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IAuth.sol) | 
| [src/modules/interfaces/ICheckpointer.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/ICheckpointer.sol) | 
| [src/modules/interfaces/IDelegatedExtension.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IDelegatedExtension.sol) | 
| [src/modules/interfaces/IERC1155Receiver.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IERC1155Receiver.sol) | 
| [src/modules/interfaces/IERC1271.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IERC1271.sol) | 
| [src/modules/interfaces/IERC223Receiver.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IERC223Receiver.sol) | 
| [src/modules/interfaces/IERC721Receiver.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IERC721Receiver.sol) | 
| [src/modules/interfaces/IERC777Receiver.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IERC777Receiver.sol) | 
| [src/modules/interfaces/IEntryPoint.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IEntryPoint.sol) | 
| [src/modules/interfaces/IPartialAuth.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/IPartialAuth.sol) | 
| [src/modules/interfaces/ISapient.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/modules/interfaces/ISapient.sol) | 
| [src/utils/Base64.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/utils/Base64.sol) | 
| [src/utils/LibBytes.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/utils/LibBytes.sol) | 
| [src/utils/LibOptim.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/utils/LibOptim.sol) | 
| [src/utils/P256.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/utils/P256.sol) | 
| [src/utils/WebAuthn.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/utils/WebAuthn.sol) | 
| **Total Logic Contracts: 34** | 

*For a machine-readable version, see [scope.txt](https://github.com/code-423n4/2025-10-sequence/blob/main/scope.txt)*

### Files out of scope

| File         |
| ------------ |
| [script/\*\*.\*\*](https://github.com/code-423n4/2025-10-sequence/tree/main/script) |
| [src/Estimator.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/Estimator.sol) |
| [src/Simulator.sol](https://github.com/code-423n4/2025-10-sequence/blob/main/src/Simulator.sol) |
| [test/\*\*.\*\*](https://github.com/code-423n4/2025-10-sequence/tree/main/test) |
| Total Contracts: 45 |

*For a machine-readable version, see [out_of_scope.txt](https://github.com/code-423n4/2025-10-sequence/blob/main/out_of_scope.txt)*

# Additional context

## Areas of concern (where to focus for bugs)

1. Privilege escalation either from a signer that belongs to the configuration or from a non-signer, allowing it to sign transactions on behalf of the wallet bypassing the threshold.
2. Correctness of the checkpointer and the chained signatures.
3. Malleability of packed payloads.
4. Privilege escalation within smart sessions.
5. Timelock bypasses on the recovery module.

## Main invariants

### Authorized Signers Only

Only the wallet’s designated signers (meeting the required signing threshold) can execute transactions or make state changes. No external party can operate the wallet without a valid EIP-712 signature from the correct signer set. The contract enforces this by requiring a proper signature for every execute call – if the signature check fails, the transaction is rejected.

### Image Hash & Configuration Integrity

Each Sequence wallet is defined by an image hash that encodes its owner configuration (the set of signer addresses and their threshold scheme). This image hash is tied to the wallet’s deployment address. On deployment, the wallet contract checks that its own address was generated using the image hash (via CREATE2 with the factory) and stores this hash on-chain. Every future transaction recomputes the image hash from the current config and compares it to the stored value, ensuring the signer set or threshold cannot be tampered with undetected. In short, the wallet’s address and its authorized signer configuration are cryptographically bound – any unauthorized change breaks the hash check and invalidates signatures.

### Deterministic Wallet Address per Config

Given the above, a particular signer configuration always corresponds to a single unique wallet address. The factory uses the image hash as a salt to deploy the wallet, meaning the mapping between a wallet’s config and its address is one-to-one. This prevents an attacker from, say, front-running the deployment of a user’s wallet with a different contract – the address is predetermined by the intended signers. No two distinct configs will produce the same address, and the same config cannot be deployed twice on the same network. After deployment, two wallets could upgrade their image hash to the same configuration.

### Strict Nonce Sequencing

Sequence wallets implement a multi-space nonce system to prevent replay attacks. Each wallet has independent nonce “spaces” (to allow parallel sequence streams), and in each space the nonce must match exactly the next expected value. Nonces increment sequentially per space and cannot be reused. If a transaction’s provided nonce is out of sequence for that space, it will be rejected as an INVALID_NONCE. This invariant guarantees proper ordering of transactions and that each signed transaction is unique to a single execution.

### Domain-Separated Signatures

All signatures are domain-separated and network-specific. The wallet’s EIP-712 signing scheme includes the current chain ID and the wallet’s address in the hashed message. This means a signature intended for one particular Sequence wallet on one network cannot be replayed on a different wallet or chain. The contract explicitly pulls the chain ID in at hash time and prefixes the data with `0x19_01 || chainId || address(this)`, binding the signature to that wallet instance. This invariant protects against cross-chain or cross-contract replay of signed messages.

### Privileged Operations Require Self-Call

Sensitive operations on the wallet (such as upgrading the implementation, adding/removing module hooks, or deploying new contracts from the wallet) are guarded by a modifier onlySelf. This means the function can only be called by the wallet itself (i.e. via an internal delegatecall from the wallet’s own context) and never by an external EOA or unprivileged contract . For example, the updateImplementation function (used to upgrade the wallet’s logic) is onlySelf, so it can only execute if initiated from an authorized wallet transaction, and cannot be invoked by an attacker directly. This invariant ensures no admin or external contract can unilaterally change the wallet’s state – only the wallet’s owners, via a proper signed transaction, can trigger such changes.

### All External Actions Go Through execute

Users interact with their Sequence wallet exclusively via the execute function (or meta-transaction workflows that ultimately call execute). There is no alternative public method to trigger arbitrary calls from the wallet without signature verification. Even batched calls are executed internally by _execute after the signature and nonce have been validated. This invariant means there’s no “backdoor” to bypass authentication – every funds transfer or contract call from the wallet is explicitly authorized by the wallet’s signers.

### ERC-4337 Integration

Sequence wallets fully support ERC-4337 account abstraction by implementing the required validateUserOp interface. When a User Operation is submitted through an ERC-4337 entrypoint, the wallet validates that the sender is the configured entrypoint contract and processes the operation through the executeUserOp function. The validateUserOp function calls the wallet's own ERC-1271 isValidSignature function to validate signature correctness, where the signature is of the userOpHash rather than the Payload contents. This design protects against replay attacks by ensuring that signatures are bound to the specific User Operation hash, which includes critical fields like nonce, gas parameters, and operation data. The User Operation's data field contains a nested Sequence Payload, which gets forwarded to the wallet's selfExecute function. This selfExecute call follows the same execution flow as the standard _execute function described above. This invariant guarantees that ERC-4337 operations maintain the same security guarantees as direct wallet interactions – the account abstraction layer cannot bypass the wallet's core authentication mechanisms or authorization requirements.

### Batched Transactions & Atomicity

The wallet supports batching multiple actions in a single execute call for efficiency. By default, the batch is atomic – if any call in the batch fails and is marked as critical, the entire batch will revert. However, the wallet allows certain calls to be flagged as non-critical (revertOnError = false), in which case a failure of that call will not stop the batch: it will emit a TxFailed event for that specific sub-transaction and continue with the next one. This invariant ensures that optional or best-effort operations can be attempted without jeopardizing the main transaction, while still transparently logging any failures. Importantly, a sub-call failing without revertOnError cannot corrupt subsequent calls – the revert is trapped and the wallet moves on, maintaining overall state consistency for the rest of the batch.

### Contract Signers and ERC-1271

Sequence wallets can have other smart-contract wallets or contracts as signers (not just EOAs), and the wallet fully supports nested signatures via ERC-1271 and the new Sapient Signer interface. If a signer is a contract, the Sequence wallet will call that contract’s isValidSignature method to confirm that the payload was approved by that contract’s logic. A contract signer only counts as valid if its own internal approval check returns true, per ERC-1271. This means adding a contract (even another Sequence wallet) as a signer does not bypass the signature requirement – it simply shifts it to that contract’s own signature/approval mechanism. The system even supports multiple layers of nested Sequence wallets as signers, as covered in tests (e.g. wallets signing for wallets), all of which must resolve to true approvals. Invariantly, a signature from a contract signer is treated with the same rigor as a human signer: no contract signer can “auto-approve” transactions unless explicitly programmed to, and it cannot be used to circumvent the threshold or nonce rules.

### Sapient Signers

Sapient signers represent an advanced interface designed to support more complex Sequence wallet signer configurations. While ERC-1271 can only validate a hash and signature by returning the magic value, a Sapient Signer receives the complete transaction payload and signature and is expected to return its configuration or image hash. This returned image hash is then used by the Sequence wallet to reconstruct the wallet's image hash. Since the signer's image hash is derived for every payload and signature combination, a sapient signer can counterfactually determine its image hash without relying on on-chain state. This capability is achieved by encoding the intended sapient signer configuration directly within the signature being validated. As a result, a wallet can support a specific configuration of the sapient signer without requiring updates to that contract's state, enabling more flexible and gas-efficient signer management. The sapient signer may validate the contents of the payload or signature in whichever way it deems fit.

### Controlled Module Hooks

The wallet allows installing hook modules to handle specific function selectors (for example, to custom-handle incoming token transfers or to extend wallet functionality). These hooks are strictly controlled by the wallet’s owners. Only one hook implementation can be registered per function signature at any time, and adding or removing a hook can only be done via a valid wallet transaction (which, as noted, requires signer authorization and onlySelf). If a hook is set for a function, the wallet’s fallback will delegatecall into the hook’s contract when that function is invoked; if no hook is set, such calls are simply ignored by the wallet’s fallback (no action taken, aside from possibly receiving ETH). Hooks do not get to override the wallet’s security model – they execute within the wallet context under the same onlySelf restrictions for any state changes. In essence, a hook can extend functionality but cannot, for example, surreptitiously initiate an execute on its own. The invariant here is that hooks augment the wallet but cannot violate its core access controls.

### Non-Privileged Helper Modules

The Sequence system includes certain helper modules (e.g. Estimator, Simulator, and a Guest module for new wallets) which have no privileged rights in the protocol. These components are used for off-chain simulation, gas estimation or temporary guest session logic, and they cannot modify wallet state or perform sensitive actions. Invariants are not impacted by these modules – they operate with read-only or strictly limited scope. This means auditors and users can largely ignore these modules in terms of security critical paths, as they cannot bypass authorization or affect funds. All the critical invariants remain focused on the core wallet, its factory, and the authorized modules described above.


## All trusted roles in the protocol

N/A

## Running tests

### Prerequisites

The repository utilizes the `foundry` (`forge`) toolkit to compile its contracts, and contains several dependencies through `foundry` that will be automatically installed whenever a `forge` command is issued.

The compilation instructions were evaluated with the following toolkit versions:

- forge: `1.3.5-stable`

A significant portion of the test suite relies on a custom RPC node to be setup through the Sequence SDK. If one desires to employ this method to cause all tests to succeed, the `NodeJS` and `pnpm` dependencies are required.

The following versions have been tested with this approach:

- NodeJS: `20.9.0`
- pnpm: `10.14.0`

### Tests

This command can be issued to execute any tests within the repository:

```sh
forge test
```

While several tests may indicate failure, they are failing due to a lack of local infrastructure and can be safely ignored.

If desired, these tests can be successfully executed if a custom RPC server is setup as described in the next steps.

#### RPC Setup

The publicly-available [Sequence V3 SDK](https://github.com/0xsequence/sequence.js) must be cloned locally:

```bash
git clone https://github.com/0xsequence/sequence.js
```

Afterward, the repository's packages must be installed, built, and its server must be launched through the following sequence of commands:

```bash
cd sequence.js
pnpm build:packages
pnpm dev:server
```

While the server is running, the `.env.example` file in the `2025-10-sequence` GitHub repository can be renamed to `.env` to permit its values to be utilized by `forge`:

```bash
cp .env.sample .env
```

Executing tests should now properly succeed in all scenarios as follows:

```bash
forge test
```

### Submission PoCs

The scope of the audit contest involves a modular smart wallet configuration that can mix-and-match several configurations with each implementation containing its own complexity.

As such, producing a single PoC file that renders all combinations of functionality accessible is not possible.

Wardens are instructed to utilize any of the existing test suites to illustrate the vulnerabilities they identify should they be constrained to a single file (i.e. `BaseSig` vulnerabilities should utilize the `BaseSig.t.sol` file).

If a custom configuration is desired, wardens are advised to create their own PoC file that should be executable within the `test` subfolder of this contest.

All PoCs must adhere to the following guidelines:

- The PoC should execute successfully
- The PoC must not mock any contract-initiated calls
- The PoC must not utilize any mock contracts in place of actual in-scope implementations

## Miscellaneous

Employees of Sequence and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.


