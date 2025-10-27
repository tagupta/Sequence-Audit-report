```solidity
// Process each cumulative rule
for (uint256 i = 0; i < permission.rules.length; i++) {
    ParameterRule memory rule = permission.rules[i];
    
    // Extract value from calldata
    (bytes32 value,) = call.data.readBytes32(rule.offset);
    value = value & rule.mask;

    if (rule.cumulative) {
        bytes32 usageHash = keccak256(abi.encode(signer, permission, i));
        
        // STEP 1: Search for existing usage limit
        bool foundInCurrentPayload = false;
        uint256 foundIndex = 0;
        uint256 previousUsage = 0;
        
        for (uint256 j = 0; j < nextAvailableSlot; j++) {
            if (newUsageLimits[j].usageHash == usageHash) {
                previousUsage = newUsageLimits[j].usageAmount;
                foundInCurrentPayload = true;
                foundIndex = j;
                break;
            }
        }
        
        // STEP 2: If not found in current payload, check storage
        if (!foundInCurrentPayload) {
            previousUsage = getLimitUsage(wallet, usageHash);
        }
        
        // STEP 3: Calculate cumulative value
        uint256 cumulativeValue = uint256(value) + previousUsage;
        value = bytes32(cumulativeValue);
        
        // STEP 4: Update or create usage limit entry
        if (foundInCurrentPayload) {
            // Update existing entry
            newUsageLimits[foundIndex].usageAmount = cumulativeValue;
        } else {
            // Create new entry - THIS IS OUTSIDE THE SEARCH LOOP
            if (nextAvailableSlot >= newUsageLimits.length) {
                revert("Usage limits overflow");
            }
            newUsageLimits[nextAvailableSlot] = UsageLimit({
                usageHash: usageHash,
                usageAmount: cumulativeValue
            });
            nextAvailableSlot++;
        }
    }
    
    // Apply operation check (EQUAL, LESS_THAN, etc.)
    if (!_checkOperation(value, rule)) {
        return (false, _resizeArray(newUsageLimits, nextAvailableSlot));
    }
}
```

--------------------------------------------

```text
If the goal is to prevent usage limits from being skipped, the dangerous behavior is actually:

BEHAVIOR_IGNORE_ERROR (0x00) - This is the real risk!
Call executes but fails

System ignores the error and continues

Usage limits might not be updated for the failed call

But subsequent calls still execute

BEHAVIOR_ABORT_ON_ERROR (0x02) is actually SAFER:
Call fails → execution stops

No subsequent calls execute

Clear failure state - easier to track
```

```solidity
// Check if this call could cause usage limits to be skipped
if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
    revert SessionErrors.InvalidBehavior();
}
```