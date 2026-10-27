// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./ArohaRegistry.sol";

/**
 * ArohaReputation — Aroha Protocol Layer 2 (Reputation Oracle)
 *
 * Records saga outcomes and maintains on-chain reputation scores.
 * Score range: 0–10000 (5000 = neutral starting score).
 *
 * Composite scoring (SUCCESS outcomes only):
 *   compositeSignal = executionSignal × 60% + qualitySignal × 40%
 *
 *   qualitySignal = qualityStars × 2000  (1★=2000 … 5★=10000)
 *   qualityStars = 0 means "unrated" — falls back to execution signal only.
 *
 * Non-success outcomes (FAILURE, COMPENSATED, DISPUTE_LOST) always use the
 * execution signal only — a subjective rating cannot override a real failure.
 *
 * Quality stars are stored per-record and emitted in events so off-chain
 * indexers can compute per-capability average ratings without extra storage.
 */
contract ArohaReputation {

    // ── Types ─────────────────────────────────────────────────────────────────

    enum SagaOutcome { SUCCESS, FAILURE, COMPENSATED, DISPUTE_LOST }

    struct OutcomeRecord {
        bytes32 sagaId;
        bytes32 agentDID;
        SagaOutcome outcome;
        uint8 qualityStars;  // 0 = unrated, 1–5 = orchestrator subjective rating
        uint256 recordedAt;
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    uint32 constant DECAY_NUM = 85;
    uint32 constant DECAY_DEN = 100;

    uint32 constant SIGNAL_SUCCESS      = 10000;
    uint32 constant SIGNAL_COMPENSATED  =  3000;
    uint32 constant SIGNAL_FAILURE      =  1000;
    uint32 constant SIGNAL_DISPUTE_LOST =     0;

    // Composite weights (must sum to 100)
    uint32 constant WEIGHT_EXECUTION = 60;
    uint32 constant WEIGHT_QUALITY   = 40;

    // ── Storage ───────────────────────────────────────────────────────────────

    ArohaRegistry public registry;
    address public owner;
    address public pendingOwner;

    mapping(bytes32 => OutcomeRecord[]) private _outcomes;
    mapping(bytes32 => uint32)          private _scores;

    // ── Events ────────────────────────────────────────────────────────────────

    event OutcomeRecorded(
        bytes32 indexed agentDID,
        bytes32 indexed sagaId,
        SagaOutcome outcome,
        uint8 qualityStars,
        uint32 newScore
    );
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ── Errors ────────────────────────────────────────────────────────────────

    error Unauthorized();
    error ZeroAddress();
    error DuplicateSaga(bytes32 sagaId, bytes32 agentDID);
    error InvalidQualityStars(uint8 stars);

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _registry) {
        registry = ArohaRegistry(_registry);
        owner = msg.sender;
    }

    // ── Record outcome ────────────────────────────────────────────────────────

    /**
     * Record the outcome of a saga step for one participant agent.
     * Only callable by the contract owner (the deployer, unless ownership
     * has been transferred via transferOwnership/acceptOwnership).
     *
     * @param sagaId      The saga correlation ID (bytes32)
     * @param agentDID     The participant agent's DID hash
     * @param outcome      SUCCESS | FAILURE | COMPENSATED | DISPUTE_LOST
     * @param qualityStars 0 = unrated; 1–5 = subjective quality rating.
     *                     Only applied when outcome == SUCCESS.
     */
    function recordOutcome(
        bytes32 sagaId,
        bytes32 agentDID,
        SagaOutcome outcome,
        uint8 qualityStars
    ) external {
        if (msg.sender != owner) revert Unauthorized();
        if (qualityStars > 5) revert InvalidQualityStars(qualityStars);

        OutcomeRecord[] storage records = _outcomes[agentDID];
        for (uint256 i = 0; i < records.length; i++) {
            if (records[i].sagaId == sagaId) revert DuplicateSaga(sagaId, agentDID);
        }

        uint32 currentScore = _scores[agentDID] == 0 ? 5000 : _scores[agentDID];
        uint32 signal = _computeSignal(outcome, qualityStars);

        uint32 newScore = uint32(
            (uint256(currentScore) * DECAY_NUM / DECAY_DEN) +
            (uint256(signal) * (DECAY_DEN - DECAY_NUM) / DECAY_DEN)
        );

        _scores[agentDID] = newScore;

        if (records.length >= 1000) {
            for (uint256 i = 0; i < records.length - 1; i++) {
                records[i] = records[i + 1];
            }
            records.pop();
        }
        records.push(OutcomeRecord({
            sagaId:       sagaId,
            agentDID:     agentDID,
            outcome:      outcome,
            qualityStars: qualityStars,
            recordedAt:   block.timestamp
        }));

        registry.updateReputation(agentDID, newScore);

        emit OutcomeRecorded(agentDID, sagaId, outcome, qualityStars, newScore);
    }

    // ── Ownership (two-step) ──────────────────────────────────────────────────

    /**
     * Start transferring ownership. Takes effect only when `newOwner` calls
     * acceptOwnership(); calling again replaces the pending owner.
     */
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert Unauthorized();
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function getScore(bytes32 agentDID) external view returns (uint32) {
        return _scores[agentDID] == 0 ? 5000 : _scores[agentDID];
    }

    function getOutcomes(bytes32 agentDID) external view returns (OutcomeRecord[] memory) {
        return _outcomes[agentDID];
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _computeSignal(SagaOutcome outcome, uint8 qualityStars) internal pure returns (uint32) {
        uint32 executionSignal = _outcomeSignal(outcome);

        // Non-success: execution signal only — a real failure cannot be rated away
        if (outcome != SagaOutcome.SUCCESS) return executionSignal;

        // Success with no rating: execution signal only
        if (qualityStars == 0) return executionSignal;

        // Success with rating: 60% execution + 40% quality
        uint32 qualitySignal = uint32(qualityStars) * 2000; // 1→2000 … 5→10000
        return (executionSignal * WEIGHT_EXECUTION + qualitySignal * WEIGHT_QUALITY) / 100;
    }

    function _outcomeSignal(SagaOutcome outcome) internal pure returns (uint32) {
        if (outcome == SagaOutcome.SUCCESS)      return SIGNAL_SUCCESS;
        if (outcome == SagaOutcome.COMPENSATED)  return SIGNAL_COMPENSATED;
        if (outcome == SagaOutcome.FAILURE)      return SIGNAL_FAILURE;
        if (outcome == SagaOutcome.DISPUTE_LOST) return SIGNAL_DISPUTE_LOST;
        return SIGNAL_FAILURE;
    }
}
