// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Storage } from "./Storage.sol";
import { SelfAuth } from "./auth/SelfAuth.sol";
import { IERC1155Receiver } from "./interfaces/IERC1155Receiver.sol";
import { IERC223Receiver } from "./interfaces/IERC223Receiver.sol";
import { IERC721Receiver } from "./interfaces/IERC721Receiver.sol";
import { IERC777Receiver } from "./interfaces/IERC777Receiver.sol";

/// @title Hooks
/// @author Agustin Aguilar, Michael Standen
/// @notice Enables extension of the wallet by adding hooks
contract Hooks is SelfAuth, IERC1155Receiver, IERC777Receiver, IERC721Receiver, IERC223Receiver {

  /// @dev keccak256("org.arcadeum.module.hooks.hooks")
  bytes32 private constant HOOKS_KEY = bytes32(0xbe27a319efc8734e89e26ba4bc95f5c788584163b959f03fa04e2d7ab4b9a120);

  /// @notice Emitted when a hook is defined
  event DefinedHook(bytes4 selector, address implementation);

  /// @notice Error thrown when a hook already exists
  error HookAlreadyExists(bytes4 selector);
  /// @notice Error thrown when a hook does not exist
  error HookDoesNotExist(bytes4 selector);

  /// @notice Read a hook
  /// @param selector The selector of the hook
  /// @return implementation The implementation address of the hook
  function readHook(
    bytes4 selector
  ) external view returns (address) {
    return _readHook(selector);
  }

  /// @notice Add a hook
  /// @param selector The selector of the hook
  /// @param implementation The implementation address of the hook
  /// @dev Callable only by the contract itself
  function addHook(bytes4 selector, address implementation) external payable onlySelf {
    if (_readHook(selector) != address(0)) {
      revert HookAlreadyExists(selector);
    }
    //@audit-q @audit-lowrequire(implementation.code.length > 0, "implementation not a contract"); and validate non-zero address.
    //@audit-low adding hook with address 0
    _writeHook(selector, implementation);
  }

  /// @notice Remove a hook
  /// @param selector The selector of the hook
  /// @dev Callable only by the contract itself
  function removeHook(
    bytes4 selector
  ) external payable onlySelf {
    if (_readHook(selector) == address(0)) {
      revert HookDoesNotExist(selector);
    }
    _writeHook(selector, address(0));
  }

  function _readHook(
    bytes4 selector
  ) private view returns (address) {
    return address(uint160(uint256(Storage.readBytes32Map(HOOKS_KEY, bytes32(selector)))));
  }

  function _writeHook(bytes4 selector, address implementation) private {
    //@audit-low no check on the viability of implementation address
    //@note _writeHook does not check that implementation is a contract. Storing an EOA or zero address may confuse callers.
    Storage.writeBytes32Map(HOOKS_KEY, bytes32(selector), bytes32(uint256(uint160(implementation))));
    emit DefinedHook(selector, implementation);
  }

  /// @inheritdoc IERC1155Receiver
  function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
    return Hooks.onERC1155Received.selector;
  }

  /// @inheritdoc IERC1155Receiver
  function onERC1155BatchReceived(
    address,
    address,
    uint256[] calldata,
    uint256[] calldata,
    bytes calldata
  ) external pure returns (bytes4) {
    return Hooks.onERC1155BatchReceived.selector;
  }

  /// @inheritdoc IERC777Receiver
  function tokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes calldata data,
    bytes calldata operatorData
  ) external { }

  /// @inheritdoc IERC721Receiver
  function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
    return Hooks.onERC721Received.selector;
  }

  /// @inheritdoc IERC223Receiver
  function tokenReceived(address, uint256, bytes calldata) external pure returns (bytes4) {
    return Hooks.tokenReceived.selector;
  }

  /// @notice Fallback function
  /// @dev Handles delegate calls to hooks
  //@audit-q is it possible to store malicious target and using that target we can make any delegate call
  //@note There's no authentication - anyone can trigger these delegatecalls to the mapped addresses.
  //@note @audit-med
  //Problem: Anyone can call the fallback with msg.data matching a selector, and trigger delegatecall to the stored hook address. There is no authentication on who may invoke a hook; onlySelf only protects adding/removing hooks (but not invoking them).
  // Exploit scenario: Even if hooks are added by a trusted process, an attacker can repeatedly call hooks and trigger behavior that abuses gas, causes reentrancy, or manipulates external state from Hooks’ storage context.
  fallback() external payable {
    if (msg.data.length >= 4) {
      address target = _readHook(bytes4(msg.data));
      if (target != address(0)) {
        //@audit-q Malicious contracts can consume all gas and cause DoS.
        (bool success, bytes memory result) = target.delegatecall(msg.data);
        assembly {
          if iszero(success) { revert(add(result, 32), mload(result)) }
          return(add(result, 32), mload(result))
        }
      }
    }
  }

  /// @notice Receive native tokens
  receive() external payable { }

}

//@audit-info You implement receiver functions (ERC1155, ERC721, ERC223, ERC777) but don’t declare ERC165 support. Some registries/clients check ERC165.