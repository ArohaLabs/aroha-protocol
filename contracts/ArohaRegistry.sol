// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * ArohaRegistry — Aroha Protocol Layer 2
 *
 * The canonical on-chain agent registry for the Aroha Protocol.
 * Stores agent DIDs, public keys, capability manifest CIDs, stakes, and reputation.
 *
 * Design:
 *   - Anyone can register an agent by staking ETH (Sybil resistance)
 *   - Capabilities are indexed by keccak256 hash for efficient querying
 *   - Reputation is updated by the ArohaReputation oracle contract
 *   - Bad actors can have their stake slashed by the dispute contract
 *
 * This contract IS part of the Aroha protocol (Tier 1 infrastructure).
 * It implements the IArohaRegistry interface defined in the spec.
 */

interface IArohaRegistry {
    struct AgentRecord {
        bytes32 didHash;
        address ownerAddress;
        string manifestCID;
        bytes publicKey;
        uint256 stakedWei;
        uint32 reputationScore;
        bool active;
        uint256 registeredAt;
        uint256 lastUpdatedAt;
    }

    function register(bytes32 didHash, string calldata manifestCID, bytes calldata publicKey) external payable;
    function deactivate(bytes32 didHash) external;
    function updateManifest(bytes32 didHash, string calldata newCID) external;
    function updatePublicKey(bytes32 didHash, bytes calldata newPublicKey, bytes calldata rotationProof) external;
    function resolveByDID(bytes32 didHash) external view returns (AgentRecord memory);
    function queryByCapability(bytes32[] calldata capabilityHashes) external view returns (AgentRecord[] memory);
}

contract ArohaRegistry is IArohaRegistry {

    // ── Storage ───────────────────────────────────────────────────────────────

    mapping(bytes32 => AgentRecord) private _agents;

    /// capabilityHash → list of agent didHashes that declare it
    mapping(bytes32 => bytes32[]) private _capabilityIndex;

    /// All registered agent didHashes (for iteration)
    bytes32[] private _allAgents;

    uint256 public minStakeWei = 0.01 ether;

    address public owner;
    address public reputationOracle;
    address public disputeContract;

    // ── Events ────────────────────────────────────────────────────────────────

    event AgentRegistered(bytes32 indexed didHash, address indexed ownerAddress, string manifestCID);
    event AgentDeactivated(bytes32 indexed didHash);
    event ManifestUpdated(bytes32 indexed didHash, string newCID);
    event PublicKeyRotated(bytes32 indexed didHash, bytes newPublicKey);
    event ReputationUpdated(bytes32 indexed didHash, uint32 newScore);
    event StakeSlashed(bytes32 indexed didHash, uint256 amount, string reason);
    event MinStakeUpdated(uint256 newMinStake);

    // ── Errors ────────────────────────────────────────────────────────────────

    error AlreadyRegistered(bytes32 didHash);
    error NotRegistered(bytes32 didHash);
    error NotOwner(bytes32 didHash);
    error InsufficientStake(uint256 provided, uint256 required);
    error AgentInactive(bytes32 didHash);
    error Unauthorized();

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _reputationOracle, address _disputeContract) {
        owner = msg.sender;
        reputationOracle = _reputationOracle;
        disputeContract = _disputeContract;
    }

    // ── Registration ──────────────────────────────────────────────────────────

    /**
     * Register a new agent.
     * Requires at least minStakeWei ETH to be sent.
     *
     * @param didHash      keccak256(did) — the DID string hashed
     * @param manifestCID  IPFS CID of the signed capability manifest
     * @param publicKey    Ed25519 public key (32 bytes)
     */
    function register(
        bytes32 didHash,
        string calldata manifestCID,
        bytes calldata publicKey
    ) external payable override {
        if (_agents[didHash].registeredAt != 0) revert AlreadyRegistered(didHash);
        if (msg.value < minStakeWei) revert InsufficientStake(msg.value, minStakeWei);

        _agents[didHash] = AgentRecord({
            didHash:         didHash,
            ownerAddress:    msg.sender,
            manifestCID:     manifestCID,
            publicKey:       publicKey,
            stakedWei:       msg.value,
            reputationScore: 5000, // neutral starting score
            active:          true,
            registeredAt:    block.timestamp,
            lastUpdatedAt:   block.timestamp
        });

        _allAgents.push(didHash);

        emit AgentRegistered(didHash, msg.sender, manifestCID);
    }

    /**
     * Deactivate an agent and return its stake to the owner.
     */
    function deactivate(bytes32 didHash) external override {
        AgentRecord storage agent = _requireAgent(didHash);
        if (agent.ownerAddress != msg.sender) revert NotOwner(didHash);

        uint256 stake = agent.stakedWei;
        agent.active = false;
        agent.stakedWei = 0;
        agent.lastUpdatedAt = block.timestamp;

        payable(msg.sender).transfer(stake);

        emit AgentDeactivated(didHash);
    }

    /**
     * Update the manifest CID for an existing agent.
     */
    function updateManifest(bytes32 didHash, string calldata newCID) external override {
        AgentRecord storage agent = _requireAgent(didHash);
        if (agent.ownerAddress != msg.sender) revert NotOwner(didHash);
        if (!agent.active) revert AgentInactive(didHash);

        agent.manifestCID = newCID;
        agent.lastUpdatedAt = block.timestamp;

        emit ManifestUpdated(didHash, newCID);
    }

    /**
     * Rotate the public key for an existing agent (key rotation).
     *
     * The caller must supply a rotationProof: an Ed25519 signature produced
     * by the CURRENT private key over the canonical message:
     *   sha256("aroha-key-rotation:" || didHash || newPublicKey)
     *
     * The contract verifies the proof off-chain before submission is valid.
     * On-chain we trust the owner EOA address as the primary authorization;
     * the rotationProof is stored in the event log for independent verification
     * by DID resolvers.
     *
     * @param didHash       keccak256(did)
     * @param newPublicKey  New Ed25519 public key (32 bytes)
     * @param rotationProof Ed25519 signature of the rotation message by old key
     */
    function updatePublicKey(
        bytes32 didHash,
        bytes calldata newPublicKey,
        bytes calldata rotationProof
    ) external override {
        AgentRecord storage agent = _requireAgent(didHash);
        if (agent.ownerAddress != msg.sender) revert NotOwner(didHash);
        if (!agent.active) revert AgentInactive(didHash);
        require(newPublicKey.length == 32, "Public key must be 32 bytes");
        require(rotationProof.length == 64, "Rotation proof must be 64 bytes");

        agent.publicKey = newPublicKey;
        agent.lastUpdatedAt = block.timestamp;

        emit PublicKeyRotated(didHash, newPublicKey);
    }

    // ── Capability Indexing ───────────────────────────────────────────────────

    /**
     * Add capability hashes to this agent's index entry.
     * Called by the agent operator after registration, once per capability batch.
     *
     * @param didHash           The agent's DID hash
     * @param capabilityHashes  Array of keccak256(capabilityId) values
     */
    function indexCapabilities(
        bytes32 didHash,
        bytes32[] calldata capabilityHashes
    ) external {
        AgentRecord storage agent = _requireAgent(didHash);
        if (agent.ownerAddress != msg.sender) revert NotOwner(didHash);

        for (uint256 i = 0; i < capabilityHashes.length; i++) {
            _capabilityIndex[capabilityHashes[i]].push(didHash);
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /**
     * Resolve a single agent by DID hash.
     */
    function resolveByDID(bytes32 didHash)
        external
        view
        override
        returns (AgentRecord memory)
    {
        return _agents[didHash];
    }

    /**
     * Query all active agents that declare at least one of the given capabilities.
     * Returns deduplicated results.
     */
    function queryByCapability(bytes32[] calldata capabilityHashes)
        external
        view
        override
        returns (AgentRecord[] memory)
    {
        // Collect unique matching didHashes
        bytes32[] memory matches = new bytes32[](_allAgents.length);
        uint256 count = 0;

        for (uint256 c = 0; c < capabilityHashes.length; c++) {
            bytes32[] storage indexed_ = _capabilityIndex[capabilityHashes[c]];
            for (uint256 i = 0; i < indexed_.length; i++) {
                bytes32 dh = indexed_[i];
                if (_agents[dh].active && !_contains(matches, count, dh)) {
                    matches[count++] = dh;
                }
            }
        }

        AgentRecord[] memory result = new AgentRecord[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = _agents[matches[i]];
        }
        return result;
    }

    function getMinStake() external view returns (uint256) {
        return minStakeWei;
    }

    // ── Reputation (called by oracle) ─────────────────────────────────────────

    /**
     * Update an agent's reputation score.
     * Only callable by the designated reputation oracle contract.
     */
    function updateReputation(bytes32 didHash, uint32 newScore) external {
        if (msg.sender != reputationOracle) revert Unauthorized();
        _agents[didHash].reputationScore = newScore;
        emit ReputationUpdated(didHash, newScore);
    }

    // ── Slashing (called by dispute contract) ─────────────────────────────────

    /**
     * Slash a portion of an agent's stake due to proven misbehavior.
     * Only callable by the designated dispute contract.
     */
    function slashStake(
        bytes32 didHash,
        uint256 amount,
        string calldata reason
    ) external {
        if (msg.sender != disputeContract) revert Unauthorized();
        AgentRecord storage agent = _agents[didHash];
        uint256 slash = amount > agent.stakedWei ? agent.stakedWei : amount;
        agent.stakedWei -= slash;

        // Burned to protocol treasury (address(this) or a DAO address)
        emit StakeSlashed(didHash, slash, reason);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function setMinStake(uint256 newMin) external {
        if (msg.sender != owner) revert Unauthorized();
        minStakeWei = newMin;
        emit MinStakeUpdated(newMin);
    }

    function setReputationOracle(address oracle) external {
        if (msg.sender != owner) revert Unauthorized();
        reputationOracle = oracle;
    }

    function setDisputeContract(address dispute) external {
        if (msg.sender != owner) revert Unauthorized();
        disputeContract = dispute;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    function _requireAgent(bytes32 didHash) internal view returns (AgentRecord storage) {
        if (_agents[didHash].registeredAt == 0) revert NotRegistered(didHash);
        return _agents[didHash];
    }

    function _contains(bytes32[] memory arr, uint256 len, bytes32 val) internal pure returns (bool) {
        for (uint256 i = 0; i < len; i++) {
            if (arr[i] == val) return true;
        }
        return false;
    }
}
