// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/Payload.sol";
import { LibBytes } from "../../../utils/LibBytes.sol";
import { ParameterOperation, ParameterRule, Permission, UsageLimit } from "./Permission.sol";

/// @title PermissionValidator
/// @author Michael Standen, Agustin Aguilar
/// @notice Validates permissions for a given call
abstract contract PermissionValidator {

  using LibBytes for bytes;

  /// @notice Emitted when the usage amount for a given wallet and usage hash is updated
  event LimitUsageUpdated(address wallet, bytes32 usageHash, uint256 usageAmount);

  /// @notice Mapping of usage limit hashes to their usage amounts
  mapping(address => mapping(bytes32 => uint256)) private limitUsage; //@note wallet => usageHash => limit amount

  /// @notice Get the usage amount for a given usage hash and wallet
  /// @param wallet The wallet address
  /// @param usageHash The usage hash
  /// @return The usage amount
  function getLimitUsage(address wallet, bytes32 usageHash) public view returns (uint256) {
    return limitUsage[wallet][usageHash];
  }

  /// @notice Set the usage amount for a given usage hash and wallet
  /// @param wallet The wallet address
  /// @param usageHash The usage hash
  /// @param usageAmount The usage amount
  //@audit-q there are no validations over the value of any of the parameters
  function setLimitUsage(address wallet, bytes32 usageHash, uint256 usageAmount) internal {
    limitUsage[wallet][usageHash] = usageAmount;
    emit LimitUsageUpdated(wallet, usageHash, usageAmount);
  }

  /// @notice Validates a rules permission
  /// @param permission The rules permission to validate
  /// @param call The call to validate against
  /// @param wallet The wallet address
  /// @param signer The signer address
  /// @param usageLimits Array of current usage limits
  /// @return True if the permission is valid, false otherwise
  /// @return newUsageLimits New array of usage limits
  function validatePermission(
    Permission memory permission,
    Payload.Call calldata call,
    address wallet,
    address signer,
    UsageLimit[] memory usageLimits
  ) public view returns (bool, UsageLimit[] memory newUsageLimits) {
    if (permission.target != call.to) {
      return (false, usageLimits);
    }

    // Copy usage limits into array with space for new rules
    newUsageLimits = new UsageLimit[](usageLimits.length + permission.rules.length);
    for (uint256 i = 0; i < usageLimits.length; i++) {
      newUsageLimits[i] = usageLimits[i];
    }
    uint256 actualLimitsCount = usageLimits.length;

    // Check each rule
    for (uint256 i = 0; i < permission.rules.length; i++) {
      ParameterRule memory rule = permission.rules[i];

      // Extract value from calldata at offset
      (bytes32 value,) = call.data.readBytes32(rule.offset);

      // Apply mask
      value = value & rule.mask;

      if (rule.cumulative) {
        // Calculate cumulative usage
        //@note bool foundInCurrentPayload = false;
        uint256 value256 = uint256(value);
        // Find the usage limit for the current rule
        bytes32 usageHash = keccak256(abi.encode(signer, permission, i));
        uint256 previousUsage;
        UsageLimit memory usageLimit;
        //@audit-low The nested loops create O(n²) complexity: gas inefficiency
        for (uint256 j = 0; j < newUsageLimits.length; j++) {
          //@audit-low We might find an empty slot at position 2, but the usageHash might actually exist at position 5. We'd create a duplicate!
          if (newUsageLimits[j].usageHash == bytes32(0)) {
            // Initialize new usage limit
            usageLimit = UsageLimit({ usageHash: usageHash, usageAmount: 0 });
            newUsageLimits[j] = usageLimit;
            //@note is this even right?
            //@audit-high not sure about this
            actualLimitsCount = j + 1;
            break;
          }
          if (newUsageLimits[j].usageHash == usageHash) {
            // Value exists, use it
            usageLimit = newUsageLimits[j];
            //foundInCurrentPayload = true;
            previousUsage = usageLimit.usageAmount;
            break;
          }
        }
        if (previousUsage == 0) {
          //if (!foundInCurrentPayload) {
          // Not in current payload, use storage
          //@note This assumes previousUsage == 0 means "not found in current payload", but:
          //@audit-low
          //A usage limit could legitimately be 0 (no usage yet)
          //The variable might not be properly initialized
          previousUsage = getLimitUsage(wallet, usageHash);
        }
        // Cumulative usage
        value256 += previousUsage;
        //@report-written after updating this value here, it is never to the newUsageLimits
        usageLimit.usageAmount = value256;
        // Use the cumulative value for comparison
        value = bytes32(value256);
      }

      // Compare based on operation
      if (rule.operation == ParameterOperation.EQUAL) {
        if (value != rule.value) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.LESS_THAN_OR_EQUAL) {
        if (uint256(value) > uint256(rule.value)) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.NOT_EQUAL) {
        if (value == rule.value) {
          return (false, usageLimits);
        }
      } else if (rule.operation == ParameterOperation.GREATER_THAN_OR_EQUAL) {
        if (uint256(value) < uint256(rule.value)) {
          return (false, usageLimits);
        }
      }
    }

    // Fix array length
    //@audit-low Memory Corruption via Array Length Manipulation
    //@note The contract uses unsafe assembly to directly modify array length fields in memory without proper bounds checking. This occurs in both recoverConfiguration and validatePermission functions.
    //@note recommendation

    //  /**
    //       * SessionPermissions[] memory actualPermissions = new SessionPermissions[](permissionsCount);
    //   for (uint256 i = 0; i < permissionsCount; i++) {
    //       actualPermissions[i] = sig.sessionPermissions[i];
    //   }
    //   sig.sessionPermissions = actualPermissions;
    //   */

    assembly {
      mstore(newUsageLimits, actualLimitsCount)
    }

    return (true, newUsageLimits);
  }

}
