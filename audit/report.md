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