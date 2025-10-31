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
