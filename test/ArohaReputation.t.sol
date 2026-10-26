// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../contracts/ArohaRegistry.sol";
import "../contracts/ArohaReputation.sol";

/**
 * Self-contained Foundry test (no forge-std): run with `forge test`.
 * The test contract deploys both contracts, so it is the reputation owner.
 */
contract OtherCaller {
    function tryRecord(ArohaReputation reputation, bytes32 sagaId, bytes32 agentDID)
        external
        returns (bool ok, bytes memory revertData)
    {
        try reputation.recordOutcome(sagaId, agentDID, ArohaReputation.SagaOutcome.SUCCESS, 0) {
            return (true, "");
        } catch (bytes memory data) {
            return (false, data);
        }
    }
}

contract ArohaReputationTest {
    ArohaRegistry registry;
    ArohaReputation reputation;
    OtherCaller other;

    bytes32 constant AGENT = keccak256("did:aroha:test-agent");

    function setUp() public {
        registry = new ArohaRegistry(address(0), address(0));
        reputation = new ArohaReputation(address(registry));
        registry.setReputationOracle(address(reputation));
        other = new OtherCaller();
    }

    function testRecordOutcomeRevertsForNonOwner() public {
        (bool ok, bytes memory data) = other.tryRecord(reputation, keccak256("saga-1"), AGENT);
        require(!ok, "non-owner call succeeded");
        require(
            keccak256(data) == keccak256(abi.encodeWithSelector(ArohaReputation.Unauthorized.selector)),
            "expected Unauthorized()"
        );
        require(reputation.getScore(AGENT) == 5000, "score changed");
        require(reputation.getOutcomes(AGENT).length == 0, "outcome stored");
    }

    function testRecordOutcomeSucceedsForOwner() public {
        require(reputation.owner() == address(this), "test contract is not owner");
        reputation.recordOutcome(keccak256("saga-1"), AGENT, ArohaReputation.SagaOutcome.SUCCESS, 0);
        // 5000 * 85/100 + 10000 * 15/100 = 5750
        require(reputation.getScore(AGENT) == 5750, "unexpected score");
        require(reputation.getOutcomes(AGENT).length == 1, "outcome not stored");
    }
}
