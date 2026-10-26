// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../contracts/ArohaRegistry.sol";
import "../contracts/ArohaEscrow.sol";
import "../contracts/ArohaReputation.sol";

/**
 * Deploy.s.sol — Aroha local Anvil deployment
 *
 * Usage (from project root, WSL/bash):
 *   anvil &
 *   forge build
 *   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
 *     --private-key <Anvil account #0 key> --broadcast
 *
 * Without --broadcast, forge only simulates the deployment.
 *
 * Or use the Node.js helper which handles this automatically:
 *   node scripts/setup-chain.mjs
 */
contract Deploy {
    // Foundry cheatcode and console addresses (no forge-std dependency)
    address constant VM = address(uint160(uint256(keccak256("hevm cheat code"))));
    address constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;

    // Foundry Script interface
    function run() external {
        // With a single --private-key, forge uses that account as msg.sender here
        address deployer = msg.sender;

        // Every call between start/stopBroadcast is sent as a transaction from the deployer
        (bool ok, ) = VM.call(abi.encodeWithSignature("startBroadcast()"));
        require(ok, "startBroadcast failed");

        // 1. Registry (no oracle yet — set after Reputation is deployed)
        ArohaRegistry registry = new ArohaRegistry(address(0), address(0));

        // 2. Escrow — deployer is the authorized orchestrator
        ArohaEscrow escrow = new ArohaEscrow(deployer);

        // 3. Reputation oracle
        ArohaReputation reputation = new ArohaReputation(address(registry));

        // 4. Wire oracle into registry
        registry.setReputationOracle(address(reputation));

        (ok, ) = VM.call(abi.encodeWithSignature("stopBroadcast()"));
        require(ok, "stopBroadcast failed");

        // Log addresses (forge script --broadcast also records them in the broadcast JSON)
        _log(string(abi.encodePacked(
            "Aroha_REGISTRY=", toHexString(address(registry)),
            " Aroha_ESCROW=", toHexString(address(escrow)),
            " Aroha_REPUTATION=", toHexString(address(reputation))
        )));
    }

    function _log(string memory message) internal view {
        (bool ok, ) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", message));
        ok;
    }

    function toHexString(address a) internal pure returns (string memory) {
        bytes memory b = abi.encodePacked(a);
        bytes memory hex_ = new bytes(42);
        hex_[0] = "0"; hex_[1] = "x";
        bytes memory alphabet = "0123456789abcdef";
        for (uint i = 0; i < 20; i++) {
            hex_[2 + i * 2]     = alphabet[uint8(b[i] >> 4)];
            hex_[2 + i * 2 + 1] = alphabet[uint8(b[i] & 0x0f)];
        }
        return string(hex_);
    }
}
