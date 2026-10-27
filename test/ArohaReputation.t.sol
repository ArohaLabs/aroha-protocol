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

    function tryTransferOwnership(ArohaReputation reputation, address newOwner)
        external
        returns (bool ok, bytes memory revertData)
    {
        try reputation.transferOwnership(newOwner) {
            return (true, "");
        } catch (bytes memory data) {
            return (false, data);
        }
    }

    function tryAcceptOwnership(ArohaReputation reputation)
        external
        returns (bool ok, bytes memory revertData)
    {
        try reputation.acceptOwnership() {
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

    function _unauthorized() internal pure returns (bytes32) {
        return keccak256(abi.encodeWithSelector(ArohaReputation.Unauthorized.selector));
    }

    function testTransferOwnershipRevertsForNonOwner() public {
        (bool ok, bytes memory data) = other.tryTransferOwnership(reputation, address(other));
        require(!ok, "non-owner transfer succeeded");
        require(keccak256(data) == _unauthorized(), "expected Unauthorized()");
        require(reputation.pendingOwner() == address(0), "pending owner set");
        require(reputation.owner() == address(this), "owner changed");
    }

    function testTransferOwnershipRejectsZeroAddress() public {
        (bool ok, bytes memory data) = address(reputation).call(
            abi.encodeWithSelector(ArohaReputation.transferOwnership.selector, address(0))
        );
        require(!ok, "zero-address transfer succeeded");
        require(
            keccak256(data) == keccak256(abi.encodeWithSelector(ArohaReputation.ZeroAddress.selector)),
            "expected ZeroAddress()"
        );
        require(reputation.pendingOwner() == address(0), "pending owner set");
    }

    function testAcceptOwnershipRevertsForNonPendingCaller() public {
        OtherCaller pending = new OtherCaller();
        reputation.transferOwnership(address(pending));
        (bool ok, bytes memory data) = other.tryAcceptOwnership(reputation);
        require(!ok, "non-pending accept succeeded");
        require(keccak256(data) == _unauthorized(), "expected Unauthorized()");
        require(reputation.owner() == address(this), "owner changed");
        require(reputation.pendingOwner() == address(pending), "pending owner cleared");
    }

    function testPendingOwnerAcceptsAndTakesOverRecording() public {
        reputation.transferOwnership(address(other));
        require(reputation.pendingOwner() == address(other), "pending owner not set");
        require(reputation.owner() == address(this), "owner changed before accept");

        (bool ok, ) = other.tryAcceptOwnership(reputation);
        require(ok, "pending owner accept failed");
        require(reputation.owner() == address(other), "owner not transferred");
        require(reputation.pendingOwner() == address(0), "pending owner not cleared");

        (ok, ) = other.tryRecord(reputation, keccak256("saga-1"), AGENT);
        require(ok, "new owner could not record");
        require(reputation.getOutcomes(AGENT).length == 1, "outcome not stored");

        (bool oldOk, bytes memory data) = address(reputation).call(
            abi.encodeWithSelector(
                ArohaReputation.recordOutcome.selector,
                keccak256("saga-2"), AGENT, ArohaReputation.SagaOutcome.SUCCESS, uint8(0)
            )
        );
        require(!oldOk, "old owner could still record");
        require(keccak256(data) == _unauthorized(), "expected Unauthorized()");
    }
}
