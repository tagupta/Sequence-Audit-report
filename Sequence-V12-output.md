
## Critical Severity Findings


### Arbitrary Module Injection in Wallet Clone Factory

**Severity:** Critical  

**Affected Contract(s):**
- `Factory`

**Affected Function(s):**
- `deploy()`

**Description:**

The deploy function allows anyone to specify any address as the `_mainModule` without any validation or access control. This address is embedded directly into the creation bytecode of a new Wallet clone. If the Wallet contract trusts this module address for core logic (e.g., via delegatecalls), an attacker can deploy a wallet pointing to a malicious module implementation, effectively gaining arbitrary control over the wallet’s behavior.

**Root Cause:**

No whitelist or access-control checks on the `_mainModule` parameter in the Factory’s deploy function before embedding it into the creation code.

**Impact:**

An attacker can deploy wallets that delegate all logic to a malicious module. They can then execute any code in the context of the wallet, including draining funds and changing configuration. This undermines the security model of module-based wallet clones.

---

### Undefined behaviorOnError value slip leads to unhandled execution path

**Severity:** Critical    

**Affected Contract(s):**
- `Connext (core)`

**Affected Function(s):**
- `_execute()`

**Description:**

The `fromPackedCalls` function in the `Payload` library decodes a 2‐bit `behaviorOnError` value from the high bits of each call’s `flags` byte. Although only three behaviors (0–2) are defined (`IGNORE`, `REVERT`, `ABORT`), the raw 2‐bit slice can yield 3. The execution logic in Connext’s `_execute` function switches on `behaviorOnError` but only handles cases 0, 1, and 2. If `behaviorOnError == 3`, no branch matches, causing an unexpected fall‐through or silent skip with undefined or unsafe behavior.

**Root Cause:**

Extracting a 2‐bit field without bounding against the three defined behavior constants allows an undefined value (3) to pass through without validation.

**Impact:**

An attacker could craft a packed call with high bits set to produce `behaviorOnError == 3`. During execution in `_execute`, this undefined case may bypass expected error handling, potentially leading to skipped calls, unchecked failures, or reentrancy/memory-corruption vectors, undermining the wallet’s safety guarantees.

---

### Unverified Merkle Proof Allows Arbitrary Root Forging

**Severity:** Critical  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `_recoverBranch()`

**Description:**

The `_recoverBranch` function sets a `verified` flag if any single recovery leaf meets timing checks, then accumulates a Merkle‐style `root` by hashing in all subsequent `FLAG_NODE` and `FLAG_BRANCH` values straight from calldata. Because the contract never compares this computed `root` against an on-chain commitment, an attacker who controls one valid leaf can supply arbitrary node and branch data to forge any desired root.

**Root Cause:**

Using a simple boolean OR over leaf verifications and blindly mixing untrusted FLAG_NODE/FLAG_BRANCH data into the hash root without binding it to a known, on-chain Merkle root.

**Impact:**

An attacker can produce any Merkle root at will once they have one valid leaf, bypassing all integrity checks. Downstream systems that trust the returned root (e.g. for wallet recovery or authorization) can be tricked into accepting forged proofs, enabling unauthorized actions or fund theft.

---

### Incorrect Handling of Initial Branch in Merkle Proof Reconstruction

**Severity:** Critical  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `_recoverBranch()`

**Description:**

In the FLAG_BRANCH case, the code always computes root = fkeccak256(root, nroot) without checking if root is zero. When the first proof element is a branch, this produces keccak256(0‖subtreeRoot) instead of subtreeRoot, corrupting the reconstructed Merkle root.

**Root Cause:**

Unconditional hashing of an uninitialized (zero) root with the first subtree root in the FLAG_BRANCH path, instead of using the subtree root directly when root is zero.

**Impact:**

Any valid Merkle proof starting with a branch element will yield an incorrect root and thus fail verification. This can prevent legitimate recoveries and allow attackers to craft proofs that never validate.

---

### Cumulative Usage Updates Not Persisted

**Severity:** Critical  

**Affected Contract(s):**
- `PermissionValidator`

**Affected Function(s):**
- `validatePermission()`

**Description:**

The validatePermission function constructs a newUsageLimits array and inserts or locates UsageLimit structs for cumulative rules. However, after updating usageLimit.usageAmount in memory, it never writes this modified struct back into newUsageLimits[j]. As a result, the returned newUsageLimits always contains stale usage amounts (defaulting to zero or the previous on-chain value), breaking cumulative limit tracking.

**Root Cause:**

A missing assignment: the code updates the local UsageLimit struct’s usageAmount but never reassigns it to the newUsageLimits array, so the array retains outdated data.

**Impact:**

Attackers can bypass or reset cumulative usage limits, allowing repeated or excessive use of permissions beyond the intended caps, leading to unauthorized actions.

---

### Missing Persistence of Updated UsageAmount in Cumulative Rules

**Severity:** Critical  

**Affected Contract(s):**
- `PermissionValidator`

**Affected Function(s):**
- `validatePermission()`

**Description:**

Within the cumulative‐rule branch, the function reads or creates a UsageLimit entry into a local `usageLimit` variable, updates `usageLimit.usageAmount`, but never writes this updated struct back to the `newUsageLimits` array for existing entries. As a result, the returned `newUsageLimits` always contains stale or zero `usageAmount` values rather than the intended cumulative totals.

**Root Cause:**

After modifying `usageLimit.usageAmount` in the cumulative branch, the code omits the assignment `newUsageLimits[j] = usageLimit` for existing entries, so updates to the struct are never persisted in the output array.

**Impact:**

Incorrect limit tracking leads to security gaps: cumulative usage may be under‐reported, allowing callers to exceed intended limits, or legitimate usage may be blocked if stale values undercount prior usage.

---

### Lost Updates on Cumulative Usage Limits

**Severity:** Critical  

**Affected Contract(s):**
- `PermissionValidator`

**Affected Function(s):**
- `validatePermission()`

**Description:**

When handling cumulative rules, the function copies an existing UsageLimit from the in-memory newUsageLimits array into a local struct, updates its usageAmount, but never writes it back into newUsageLimits. As a result, any previous usage is retrieved correctly, but the updated value is lost and the returned newUsageLimits array contains stale usage values. This allows callers to repeatedly satisfy cumulative limits and bypass intended caps.

**Root Cause:**

Reading an array element into a memory struct creates a copy; updating the copy does not update the original array entry, and no assignment writes the modified struct back into the array for existing entries.

**Impact:**

Cumulative usage rules no longer enforce limits correctly. Malicious actors can repeatedly invoke actions gated by cumulative limits to exceed intended usage caps without detection.

---

### Threshold Overwritten in recoverChained

**Severity:** Critical  

**Affected Contract(s):**
- `BaseSig`

**Affected Function(s):**
- `recoverChained()`

**Description:**

In the loop over chained signature segments, the named return variable `threshold` is reassigned each iteration by calls to `recover(...)`. No variable preserves the initial (root) segment’s threshold. As a result, recoverChained returns the threshold of the last segment while `opHash` remains that of the first segment, causing callers to apply the wrong (lower) threshold to the original operation hash.

**Root Cause:**

Using a single named return variable for `threshold` inside a loop without storing the root segment’s threshold separately, leading to it being overwritten.

**Impact:**

An attacker can construct a chained signature where the final segment has a low threshold. recoverChained will return that low threshold alongside the original opHash, allowing signatures that meet only the last segment’s requirement to be accepted for the root operation, bypassing the intended higher security threshold.

---

### Incorrect Flags Offset in WebAuthn Authenticator Data

**Severity:** Critical  

**Affected Contract(s):**
- `WebAuthn`

**Affected Function(s):**
- `verify()`

**Description:**

The inline assembly in the `verify` function reads the user presence (UP) and user verification (UV) flags from the wrong memory offset in `authenticatorData`. It uses `mload(add(mload(auth), 0x21))`, which points into the `rpIDHash` region rather than the single-byte flags field immediately after the 32-byte `rpIDHash`. As a result, the code never actually masks and checks the real UP and UV bits.

**Root Cause:**

Erroneous pointer arithmetic in inline assembly: using an offset of 0x21 instead of the correct 0x20 from the start of `authenticatorData` to locate the flags byte.

**Impact:**

User presence and verification are not enforced. An attacker can bypass these checks and submit authenticator data without the genuine user interaction or verification, potentially allowing replay or unauthorized attestations.

---

### Unchecked Clearing of Snapshot.imageHash Allows Replay of Stale Segments

**Severity:** Critical  

**Affected Contract(s):**
- `BaseSig`

**Affected Function(s):**
- `recoverChained()`

**Description:**

Within recoverChained, the code zeroes out the passed-in Snapshot.imageHash immediately upon matching any segment’s imageHash—even if it’s not the final segment. Because the final UnusedSnapshot guard only reverts when Snapshot.imageHash is still non-zero, an attacker can first match an intermediate segment to clear imageHash, then supply a last segment with a stale checkpoint (≤ original snapshot.checkpoint) and bypass the guard entirely, resulting in replay of old segments.

**Root Cause:**

The function unconditionally clears snapshot.imageHash on the first matching segment and relies on snapshot.imageHash remaining non-zero to trigger the final revert, creating a logic gap when the match occurs early in the chain.

**Impact:**

An attacker can replay previously used (stale) signature segments by chaining a matching intermediate segment to nullify the snapshot guard, potentially bypassing checkpoint-based replay protection and compromising protocol integrity.

---


## Medium Severity Findings


### Factory Allows Deploying Proxies Pointing to Zero Implementation

**Severity:** Medium  

**Affected Contract(s):**
- `Factory`

**Affected Function(s):**
- `deploy()`

**Description:**

The Factory.deploy function lacks validation of the _mainModule address. It simply packs the provided address into the Wallet.creationCode and uses CREATE2 to deploy a proxy. If _mainModule is zero, the resulting proxy stores a zero implementation and will revert on every call, rendering the proxy unusable.

**Root Cause:**

Missing require(_mainModule != address(0)) or equivalent check in Factory.deploy (and no validation in Wallet.creationCode) allows a zero address to be set as the proxy’s implementation.

**Impact:**

Attackers can deploy ‘dead’ proxy contracts that revert on any call, cluttering the blockchain with unusable contracts. While the attacker pays gas, it can be used to spam or fill state, potentially increasing node storage and lookup costs.

---

### Unaligned Memory Write Corrupts JSON Region

**Severity:** Medium  

**Affected Contract(s):**
- `WebAuthn`

**Affected Function(s):**
- `tryEncodeAuthCompact()`

**Description:**

After copying clientDataJSON of arbitrary non-32-aligned length into memory, the code uses mstore at the end pointer without padding. Because mstore always writes a full 32 bytes, if clientDataJSON.length % 32 ≠ 0 it will overwrite bytes immediately following the JSON data, corrupting the freshly copied JSON region.

**Root Cause:**

Assuming the end of clientDataJSON falls on a 32-byte boundary without enforcing alignment, then using mstore at that unaligned address.

**Impact:**

Corruption of clientDataJSON in the encoded output can break data integrity, resulting in invalid JSON payloads, authentication failures, or downstream errors in relying contracts or off-chain consumers.

---

### Missing clientDataJSON Length Prefix in Compact Encoding

**Severity:** Medium  

**Affected Contract(s):**
- `WebAuthn`

**Affected Function(s):**
- `tryEncodeAuthCompact()`

**Description:**

In tryEncodeAuthCompact, the helper copyBytes writes a 2-byte length prefix before each dynamic field, then advances the write pointer by c_ bytes so the prefix remains visible. However, when encoding clientDataJSON, copyBytes is invoked with c_ = 0, causing o_ not to advance and the subsequent data copy to overwrite the just-stored length prefix. Consequently, the length header for clientDataJSON is entirely lost in the final byte array.

**Root Cause:**

Passing c_ = 0 to copyBytes prevents advancing past the length prefix, so the first mstore of actual data overwrites the prefix word.

**Impact:**

Downstream consumers expecting a length-prefixed clientDataJSON will read invalid or misaligned data, potentially leading to parsing failures or protocol desynchronization. Attackers might exploit this to craft malformed inputs that bypass validation or cause unexpected behavior.

---

### Inconsistent Error Handling in Signature Validation Breaking ERC-1271 Semantics

**Severity:** Medium  

**Affected Contract(s):**
- `BaseAuth`

**Affected Function(s):**
- `signatureValidation / isValidSignature()`

**Description:**

The BaseAuth contract’s signatureValidation function reverts on certain invalid signature conditions (expired static signature, wrong static signer, insufficient weight) but returns `false` on others (invalid image). The isValidSignature function then returns `bytes4(0)` only when it sees `false`, but lets reverts bubble up for the other failure paths. This inconsistent handling leads to a mix of reverts and return codes, violating ERC-1271 expectations for uniform failure semantics.

**Root Cause:**

Mixed error handling in signatureValidation: some failure branches use `revert` with custom errors, while the final validation branch simply returns `false`, causing inconsistency when propagated by isValidSignature.

**Impact:**

Callers of isValidSignature may encounter unexpected reverts for some invalid signatures and a `bytes4(0)` return for others. Integrations relying on consistent revert-on-failure or consistent error codes can break, potentially causing denial-of-service in signature flows or incorrect downstream logic.

---

### Inconsistent Error Handling in isValidSignature

**Severity:** Medium  

**Affected Contract(s):**
- `BaseAuth`

**Affected Function(s):**
- `isValidSignature()`

**Description:**

The `isValidSignature` function in BaseAuth inconsistently handles invalid signatures: static-signature failures revert, while dynamic-signature failures return false (mapped to a zero return). This behavior violates the ERC-1271 spec, which expects invalid signatures to return `0x00000000` without reverting.

**Root Cause:**

Static signature validation uses `revert` for expired or wrong-caller errors, whereas dynamic signature validation returns `false` for invalid images, causing different error pathways (revert vs. return).

**Impact:**

Clients expecting ERC-1271-compliant behavior may encounter unexpected transaction reverts for static signature failures. This inconsistency can break smart contract wallets or other client code relying on `isValidSignature` to never revert but return a magic value or zero.

---

### Unchecked external signature validation reverts in validateUserOp causes denial of service

**Severity:** Medium   

**Affected Contract(s):**
- `ERC4337v07`

**Affected Function(s):**
- `validateUserOp()`

**Description:**

The function validateUserOp makes an external call to this.isValidSignature(userOpHash, userOp.signature) without any try/catch or error handling. The underlying implementation in BaseAuth.signatureValidation can revert for expired static signatures, wrong caller addresses, or insufficient signature weight. Those reverts bubble up and abort validateUserOp instead of returning the intended SIG_VALIDATION_FAILED error code, allowing an attacker to craft a signature that intentionally triggers a revert and block all user operations for that account.

**Root Cause:**

Absence of error handling around the external call to isValidSignature, allowing all internal reverts in signatureValidation to propagate and revert the calling function.

**Impact:**

An attacker can intentionally supply a malformed or expired signature that triggers a revert in BaseAuth.signatureValidation, causing validateUserOp to revert and preventing any further account operations—resulting in a denial-of-service on the account.

---

### SignatureValidation Reverts Instead of Returning Failure

**Severity:** Medium   

**Affected Contract(s):**
- `ERC4337v07/BaseAuth`

**Affected Function(s):**
- `validateUserOp()`

**Description:**

The internal signatureValidation function in BaseAuth reverts on failure conditions (expired static signature, wrong caller, insufficient weight) instead of returning false. Because isValidSignature does not catch these reverts, they bubble up through validateUserOp as custom errors rather than causing validateUserOp to return SIG_VALIDATION_FAILED as intended.

**Root Cause:**

signatureValidation uses revert statements for all failure cases instead of returning isValid=false, and isValidSignature lacks try/catch to convert reverts into a failure return value.

**Impact:**

Any invalid signature scenario triggers an unexpected revert with custom errors (e.g., InvalidStaticSignatureExpired, InvalidSignatureWeight) instead of returning SIG_VALIDATION_FAILED. This breaks the ERC-4337 invariant and can lead to denial of service or inconsistent handling of user operations.

---

### Static Signature Validation Reverts Cause DoS

**Severity:** Medium  

**Affected Contract(s):**
- `BaseAuth`

**Affected Function(s):**
- `signatureValidation()`

**Description:**

The static‐signature branch in signatureValidation uses revert for expired signatures (InvalidStaticSignatureExpired) or wrong caller (InvalidStaticSignatureWrongCaller) instead of returning a failure code. Since isValidSignature does not catch these reverts, they propagate through the ERC-1271 interface, causing the entire transaction to revert rather than returning the expected 0x00000000 on failure.

**Root Cause:**

Using revert on static signature validation failures instead of returning a non-zero failure code.

**Impact:**

Any user operation with an expired or mis‐targeted static signature will fully revert the entry point, resulting in denial-of-service for legitimate users.

---

### Unhandled behaviorOnError Value Leads to False Success

**Severity:** Medium  

**Affected Contract(s):**
- `Calls`

**Affected Function(s):**
- `_execute()`

**Description:**

The `_execute` function reads `behaviorOnError` from user-supplied packed calldata as `(flags & 0xC0) >> 6`, yielding integer values 0 through 3. It explicitly handles values 0 (IGNORE_ERROR), 1 (REVERT_ON_ERROR), and 2 (ABORT_ON_ERROR). However, if `behaviorOnError` equals 3 (due to maliciously crafted flags), the function’s `if` blocks for error handling are all skipped and execution falls through to `emit CallSucceeded`, incorrectly treating a failed external call as successful.

**Root Cause:**

Missing validation or default handling for out-of-range `behaviorOnError` values when decoding user input; only cases 0–2 are handled explicitly.

**Impact:**

An attacker can set `behaviorOnError` to 3, causing failed calls to be marked as succeeded. This breaks error semantics, potentially bypassing expected reverts or aborts, leading to inconsistent contract state and unauthorized execution flows.

---

### Unbounded Growth of queuedPayloadHashes

**Severity:** Medium  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `queuePayload()`

**Description:**

The queuePayload function unconditionally appends each new payloadHash to the queuedPayloadHashes mapping without ever removing, expiring, or limiting entries. Since no other function in the Recovery contract prunes or caps this array, it can grow indefinitely as more payloads are queued.

**Root Cause:**

Missing cleanup or size-limit logic on the queuedPayloadHashes array—there is no mechanism to remove consumed or expired payload hashes.

**Impact:**

An attacker or misbehaving signer can spam queuePayload to bloat on‐chain storage indefinitely, leading to state bloat, increased node sync and archival costs, and potential future denial‐of‐service if any array iteration is implemented.

---

### Missing Root Initialization Check in Branch Case

**Severity:** Medium  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `_recoverBranch()`

**Description:**

The function mistakenly hashes a zero root with a nested branch root when the first or a nested flag is FLAG_BRANCH. Unlike FLAG_RECOVERY_LEAF and FLAG_NODE, which use the child node directly when the accumulated root is zero, FLAG_BRANCH always computes root = fkeccak256(root, nroot). An attacker can therefore craft or break proofs by beginning with FLAG_BRANCH, causing valid proofs to fail or malicious proofs to collide.

**Root Cause:**

Omission of a root == bytes32(0) guard in the FLAG_BRANCH case, leading to an unconditional hash of zero with the child root.

**Impact:**

Valid recovery proofs can be broken, and crafted proofs may collide under keccak256(0,·), undermining the signature recovery process and allowing bypass or denial-of-service.

---

### Incorrect Root Calculation for Initial Nested Branch Proof

**Severity:** Medium  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `_recoverBranch()`

**Description:**

Within the FLAG_BRANCH case, the code always computes `root = keccak256(root, subRoot)` without checking whether `root` is still its zero value. When a signature’s very first element is a nested branch proof, this causes the calculated root to become `keccak256(0x00…, subRoot)` instead of simply `subRoot`, resulting in an incorrect aggregated Merkle root.

**Root Cause:**

A missing zero‐value check in the FLAG_BRANCH branch causes hashing of an uninitialized (zero) root with the sub‐proof root, rather than initializing `root` directly to `subRoot` when `root` is zero.

**Impact:**

An attacker can supply a signature beginning with a nested branch flag to force an incorrect Merkle root to be returned by `recoverSapientSignatureCompact`. This corrupts proof verification, potentially causing valid proofs to be rejected or invalid aggregation, leading to denial of service or proof bypass in downstream logic.

---

### LibBytes Out-of-Bounds Calldata Read

**Severity:** Medium  

**Affected Contract(s):**
- `LibBytes`

**Affected Function(s):**
- `readUintX (and related helpers)()`

**Description:**

The LibBytes library’s low-level parsing helpers—readUintX, readUint24, readAddress, and readFirstUint8—use EVM calldataload with an index and length derived directly from untrusted input. They do not perform any explicit bounds checks against the calldata length. When a malicious caller supplies an out-of-range offset or length, calldataload pads the result with zeros rather than reverting. As a result, these functions can silently return zeroes or arbitrary data, misleading downstream logic that expects valid values.

**Root Cause:**

Missing explicit checks comparing the read offset plus length against the calldata length before performing calldataload and updating the pointer.

**Impact:**

An attacker can craft calldata with out-of-bounds offsets to force parsed values—such as addresses or integers—to zeros or arbitrary values. This may subvert protocol logic relying on these parsed values (e.g., authorization checks, value transfers, or data verification), potentially leading to unauthorized actions or asset loss.

---

### Missing Support for 65-Byte Signatures in isValidSignature

**Severity:** Medium  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `isValidSignature()`

**Description:**

The function only handles 64-byte “compact” (EIP-2098) signatures and never processes the 65-byte (r, s, v) format. As a result, any valid 65-byte signature from an EOA (_signer.code.length == 0) will fall through and return false, causing legitimate signatures to be rejected.

**Root Cause:**

The code contains an if branch for `_signature.length == 64` but lacks any branch to accept the standard 65-byte (r, s, v) signature format for EOAs.

**Impact:**

Breaks compatibility with most wallets that produce 65-byte signatures, leading to failed signature verifications and denial of service for users relying on standard signature formats.

---

### Mutating payload causes static signature verification to always fail

**Severity:** Medium   

**Affected Contract(s):**
- `BaseAuth`

**Affected Function(s):**
- `recoverSapientSignature()`

**Description:**

recoverSapientSignature unconditionally appends msg.sender to the payload.parentWallets array before calling signatureValidation. The static-signature branch in signatureValidation computes an EIP-712 hash (opHash) over the mutated payload, but the on-chain static signature was generated over the original payload. This hash mismatch causes _getStaticSignature(opHash) to never find the stored signature, triggering a revert in all static-signature cases.

**Root Cause:**

Modifying the payload.parentWallets array prior to computing the EIP-712 hash used for static signature lookup.

**Impact:**

Static signatures can never be validated via recoverSapientSignature, leading to a denial-of-service for any operation relying on static signatures through this function.

---


## Low Severity Findings


### Unrecognized behaviorOnError values cause failed calls to be marked as succeeded

**Severity:** Low  

**Affected Contract(s):**
- `Calls`

**Affected Function(s):**
- `_execute()`

**Description:**

Within the _execute loop, failed calls trigger special error branches only when behaviorOnError equals 0 (ignore), 1 (revert), or 2 (abort). If behaviorOnError is set to 3—possible because it’s extracted from two bits of a flags byte without validation—a failing call does not match any branch and falls through to emit CallSucceeded despite the call having failed.

**Root Cause:**

The behaviorOnError field is derived unchecked from the top two bits of a flags byte, allowing an out-of-range value (3). The _execute function has no default or else clause to handle unexpected behaviorOnError values, so it silently treats failures as successes.

**Impact:**

An attacker or malformed payload can craft a call with behaviorOnError=3, causing failing sub-calls to be reported as successful. This misreporting can break protocol logic, leave the system in an unexpected state, and potentially allow bypass of intended fallback or abort mechanisms.

---

### Unbounded Growth of queuedPayloadHashes Leading to DoS

**Severity:** Low  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `queuePayload()`

**Description:**

The mapping queuedPayloadHashes stores an ever-growing dynamic array of payload hashes for each wallet-signer pair. The queuePayload function pushes new hashes onto this array but there is no mechanism anywhere in the contract to remove, consume, or clear these hashes. Over time the stored arrays will grow without bound.

**Root Cause:**

Absence of any removal, consumption, or pruning logic for entries in queuedPayloadHashes, causing unbounded state growth.

**Impact:**

An attacker or high-usage scenario can push a large number of payloads to bloat storage. This will increase gas costs for subsequent queuePayload calls and may eventually exceed block gas limits or storage constraints, effectively causing a denial-of-service.

---

### ERC-1271 Compliance Violation in isValidSignature

**Severity:** Low  

**Affected Contract(s):**
- `BaseAuth`

**Affected Function(s):**
- `isValidSignature()`

**Description:**

The isValidSignature function delegates signature checks to signatureValidation, which reverts on static signature errors (expired or wrong-caller) and on insufficient signature weight. Under ERC-1271, invalid signatures should never cause a revert but return the zero magic value (0x00000000). This implementation instead bubbles up errors, violating the spec.

**Root Cause:**

signatureValidation uses unhandled revert statements for invalid signature conditions, and isValidSignature does not catch these reverts, causing exceptions rather than returning the prescribed invalid magic value.

**Impact:**

Consumers expecting ERC-1271 compliance will see unexpected reverts for invalid signatures, breaking integrations, enabling denial-of-service, and potentially locking contract functionality when invalid signatures are submitted.

---

### Stale Queue Entries in Recovery.totalQueuedPayloads

**Severity:** Low  

**Affected Contract(s):**
- `Recovery`

**Affected Function(s):**
- `totalQueuedPayloads()`

**Description:**

The function totalQueuedPayloads returns the length of queuedPayloadHashes for a given wallet and signer. However, since entries are never removed or cleared after payloads are processed or expire, this count reflects the total number of payloads ever queued rather than the number of active pending payloads.

**Root Cause:**

Missing removal logic: queuedPayloadHashes entries are only pushed and never popped or deleted when payloads are handled or expired.

**Impact:**

Persistent growth of the queue count leads to misreported metrics, can break conditional logic dependent on pending counts, and may cause resource exhaustion or gas inefficiencies when iterating over or displaying queues.

---

### Out-of-Range behaviorOnError Allows Masking of Failed Calls

**Severity:** Low  

**Affected Contract(s):**
- `Guest`
- `Calls`

**Affected Function(s):**
- `_dispatchGuest()`
- `_execute()`

**Description:**

Both the Guest and Calls contracts decode a 2-bit behaviorOnError flag without validating that its value falls within the supported range (0: IGNORE_ERROR, 1: REVERT_ON_ERROR, 2: ABORT_ON_ERROR). If an attacker crafts a flags byte yielding behaviorOnError == 3, none of the error-handling branches match on call failure. The code then falls through to emit a CallSucceeded event, falsely indicating success despite the failure.

**Root Cause:**

The implementation extracts behaviorOnError from encoded flags as a raw uint256 without bounds checking or a default/else branch. Only values 0–2 are handled explicitly, so an unsupported value (3) bypasses all error-processing logic.

**Impact:**

An attacker can fabricate payloads with behaviorOnError=3 to suppress failure handling and emit success events on failed external calls. This misleads off-chain monitoring, hides critical failures, corrupts event logs, and may allow unauthorized state transitions or skipped safety checks, leading to inconsistent contract state or financial loss.

---

### Off-by-One Static Signature Expiration Check

**Severity:** Low  

**Affected Contract(s):**
- `BaseAuth`

**Affected Function(s):**
- `signatureValidation()`

**Description:**

In signatureValidation, static signatures are deemed expired if their stored timestamp is less than or equal to block.timestamp. When a user registers a static signature with an expiration equal to the current block timestamp, it is immediately treated as expired, preventing its use until the next block.

**Root Cause:**

The expiration check uses “timestamp <= block.timestamp” instead of requiring strictly less-than for expiration, causing equality with the current block timestamp to be treated as expired rather than valid.

**Impact:**

Freshly set static signatures cannot be used in the same block they are created, breaking expected approval flows and potentially blocking legitimate operations.

---
