// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * ArohaEscrow — Aroha Protocol Layer 2 (Payment Infrastructure)
 *
 * Holds payment funds during multi-agent saga transactions.
 * Funds are locked when a saga starts and released only after
 * all saga steps are confirmed (ArohaCommitAck).
 *
 * If the saga fails or is compensated, funds are refunded to the payer.
 *
 * This creates trustless payment — providers are guaranteed to get paid
 * if they fulfill their commitment, and users are guaranteed a refund
 * if any step fails.
 */
contract ArohaEscrow {

    // ── Types ─────────────────────────────────────────────────────────────────

    enum EscrowState { OPEN, RELEASED, REFUNDED }

    struct EscrowRecord {
        bytes32 sagaId;
        address payer;
        uint256 totalAmount;
        uint256 releasedAmount;
        EscrowState state;
        uint256 createdAt;
        uint256 expiresAt;
    }

    struct PaymentSplit {
        address payable recipient;
        uint256 amount;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    mapping(bytes32 => EscrowRecord) private _escrows;
    /// sagaId → list of payment splits approved for release
    mapping(bytes32 => PaymentSplit[]) private _splits;

    address public orchestratorAuthorized;

    // ── Events ────────────────────────────────────────────────────────────────

    event EscrowOpened(bytes32 indexed sagaId, address indexed payer, uint256 amount, uint256 expiresAt);
    event PaymentReleased(bytes32 indexed sagaId, address indexed recipient, uint256 amount);
    event EscrowRefunded(bytes32 indexed sagaId, address indexed payer, uint256 amount);

    // ── Errors ────────────────────────────────────────────────────────────────

    error EscrowNotFound(bytes32 sagaId);
    error EscrowAlreadyExists(bytes32 sagaId);
    error EscrowExpired(bytes32 sagaId);
    error InsufficientFunds(uint256 available, uint256 required);
    error AlreadyFinalized(bytes32 sagaId);
    error Unauthorized();

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _orchestratorAuthorized) {
        orchestratorAuthorized = _orchestratorAuthorized;
    }

    // ── Payer actions ─────────────────────────────────────────────────────────

    /**
     * Open an escrow for a saga.
     * Called by the Personal Agent before the COMMIT phase begins.
     *
     * @param sagaId       Unique saga identifier (correlationId from the protocol)
     * @param ttlSeconds   How long the escrow is valid (e.g. 3600 = 1 hour)
     */
    function open(bytes32 sagaId, uint256 ttlSeconds) external payable {
        if (_escrows[sagaId].createdAt != 0) revert EscrowAlreadyExists(sagaId);
        if (msg.value == 0) revert InsufficientFunds(0, 1);

        _escrows[sagaId] = EscrowRecord({
            sagaId:         sagaId,
            payer:          msg.sender,
            totalAmount:    msg.value,
            releasedAmount: 0,
            state:          EscrowState.OPEN,
            createdAt:      block.timestamp,
            expiresAt:      block.timestamp + ttlSeconds
        });

        emit EscrowOpened(sagaId, msg.sender, msg.value, block.timestamp + ttlSeconds);
    }

    /**
     * Approve a payment split for a saga step.
     * Accumulates splits — actual transfer happens in release().
     * Only callable by the authorized orchestrator contract/address.
     */
    function approveSplit(
        bytes32 sagaId,
        address payable recipient,
        uint256 amount
    ) external {
        if (msg.sender != orchestratorAuthorized) revert Unauthorized();
        EscrowRecord storage escrow = _requireEscrow(sagaId);
        if (escrow.state != EscrowState.OPEN) revert AlreadyFinalized(sagaId);
        if (block.timestamp > escrow.expiresAt) revert EscrowExpired(sagaId);

        uint256 alreadyAllocated = 0;
        for (uint256 i = 0; i < _splits[sagaId].length; i++) {
            alreadyAllocated += _splits[sagaId][i].amount;
        }
        if (alreadyAllocated + amount > escrow.totalAmount) {
            revert InsufficientFunds(escrow.totalAmount - alreadyAllocated, amount);
        }

        _splits[sagaId].push(PaymentSplit({ recipient: recipient, amount: amount }));
    }

    /**
     * Release all approved payment splits to their recipients.
     * Called by the orchestrator after all saga steps are committed.
     */
    function release(bytes32 sagaId) external {
        if (msg.sender != orchestratorAuthorized) revert Unauthorized();
        EscrowRecord storage escrow = _requireEscrow(sagaId);
        if (escrow.state != EscrowState.OPEN) revert AlreadyFinalized(sagaId);

        escrow.state = EscrowState.RELEASED;

        PaymentSplit[] storage splits = _splits[sagaId];
        uint256 totalReleased = 0;

        for (uint256 i = 0; i < splits.length; i++) {
            splits[i].recipient.transfer(splits[i].amount);
            totalReleased += splits[i].amount;
            emit PaymentReleased(sagaId, splits[i].recipient, splits[i].amount);
        }

        escrow.releasedAmount = totalReleased;

        // Refund any unallocated remainder to payer
        uint256 remainder = escrow.totalAmount - totalReleased;
        if (remainder > 0) {
            payable(escrow.payer).transfer(remainder);
        }
    }

    /**
     * Refund the full escrow to the payer.
     * Called by the orchestrator if the saga fails / is compensated.
     */
    function refund(bytes32 sagaId) external {
        if (msg.sender != orchestratorAuthorized) revert Unauthorized();
        EscrowRecord storage escrow = _requireEscrow(sagaId);
        if (escrow.state != EscrowState.OPEN) revert AlreadyFinalized(sagaId);

        escrow.state = EscrowState.REFUNDED;
        uint256 amount = escrow.totalAmount;
        payable(escrow.payer).transfer(amount);

        emit EscrowRefunded(sagaId, escrow.payer, amount);
    }

    /**
     * Auto-refund an expired escrow to the payer.
     * Anyone can call this after the TTL has passed.
     */
    function expireRefund(bytes32 sagaId) external {
        EscrowRecord storage escrow = _requireEscrow(sagaId);
        if (escrow.state != EscrowState.OPEN) revert AlreadyFinalized(sagaId);
        if (block.timestamp <= escrow.expiresAt) revert EscrowExpired(sagaId);

        escrow.state = EscrowState.REFUNDED;
        payable(escrow.payer).transfer(escrow.totalAmount);

        emit EscrowRefunded(sagaId, escrow.payer, escrow.totalAmount);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function getEscrow(bytes32 sagaId) external view returns (EscrowRecord memory) {
        return _escrows[sagaId];
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _requireEscrow(bytes32 sagaId) internal view returns (EscrowRecord storage) {
        if (_escrows[sagaId].createdAt == 0) revert EscrowNotFound(sagaId);
        return _escrows[sagaId];
    }
}
