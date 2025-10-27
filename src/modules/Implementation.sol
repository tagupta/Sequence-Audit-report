// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SelfAuth } from "./auth/SelfAuth.sol";

/// @title Implementation
/// @author Agustin Aguilar
/// @notice Manages the implementation address of the proxy contract
contract Implementation is SelfAuth {

  /// @notice Emitted when the implementation is updated
  event ImplementationUpdated(address newImplementation);

  /// @notice Update the implementation
  /// @param _implementation The new implementation
  /// @dev Callable only by the contract itself
  function updateImplementation(
    address _implementation
  ) external payable virtual onlySelf {
    //@note no check towards the _implementation address, can be address 0 or EOA
    _updateImplementation(_implementation);
  }

  /// @notice Get the implementation
  /// @return implementation The implementation
  function getImplementation() external view virtual returns (address) {
    return _getImplementation();
  }

  function _updateImplementation(
    address _implementation
  ) internal virtual {
    _setImplementation(_implementation);
    emit ImplementationUpdated(_implementation);
  }

  function _setImplementation(
    address _imp
  ) internal {
    //@note stores the implementation address at the slot value defined by the address of this contract
    assembly {
      sstore(address(), _imp) 
    }
  }

  function _getImplementation() internal view returns (address _imp) {
    assembly {
      _imp := sload(address())
    }
  }

}
