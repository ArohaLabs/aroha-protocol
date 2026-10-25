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
 *   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
 *
 * Or use the Node.js helper which handles this automatically:
 *   node scripts/setup-chain.mjs
 */
contract Deploy {
    // Foundry Script interface
    function run() external {
        // vm.startBroadcast uses the --private-key flag or the first Anvil account
        address deployer = msg.sender;

        // 1. Registry (no oracle yet — set after Reputation is deployed)
        ArohaRegistry registry = new ArohaRegistry(address(0), address(0));

        // 2. Escrow — deployer is the authorized orchestrator
        ArohaEscrow escrow = new ArohaEscrow(deployer);

        // 3. Reputation oracle
        ArohaReputation reputation = new ArohaReputation(address(registry));

        // 4. Wire oracle into registry
        registry.setReputationOracle(address(reputation));

        // Log addresses for setup-chain.mjs to parse
        // (forge script --broadcast logs them in the broadcast JSON)
        // Direct logging via revert trick:
        require(
            false,
            string(abi.encodePacked(
                "Aroha_REGISTRY=", toHexString(address(registry)),
                " Aroha_ESCROW=", toHexString(address(escrow)),
                " Aroha_REPUTATION=", toHexString(address(reputation))
            ))
        );
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
