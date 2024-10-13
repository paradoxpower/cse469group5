// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ChainOfCustody {
    // Structure representing a single block in the blockchain
    struct Block {
        bytes32 previousHash; // Hash of the previous block for linking the blockchain
        uint64 timestamp; // Timestamp of when the block was created
        uint128 caseId; // Unique case identifier (should be encrypted using AES ECB mode)
        uint32 evidenceItemId; // Unique evidence identifier (should be encrypted using AES ECB mode)
        bytes12 state; // State of the evidence (CHECKEDIN, CHECKEDOUT, etc.)
        bytes20 handlerName; // Name of the handler performing the action
        bytes20 organizationName; // Name of the organization
        uint32 dataLength; // Length of additional data (optional field)
        bytes data; // Additional data
    }

    Block[] public blockchain;
    mapping(uint32 => bool) public evidenceExists;

    // Event declaration for adding new evidence
    event EvidenceItemAdded(uint128 caseId, uint32 evidenceItemId, uint64 timestamp, bytes12 state);

    /**
     * @dev Function to add new evidence items to a case.
     * @param _caseId The ID of the case to which evidence is being added.
     * @param _itemIds Array of evidence item IDs being added.
     */
    function addEvidenceItems(uint128 _caseId, uint32[] memory _itemIds) public {
        for (uint i = 0; i < _itemIds.length; i++) {
            require(!evidenceExists[_itemIds[i]], "Evidence item ID must be unique");
            addBlock(_caseId, _itemIds[i], "CHECKEDIN", "", "", ""); // Initial state is CHECKEDIN
        }
    }

    /**
     * @dev Function to add a new block to the blockchain.
     * @param _caseId The ID of the case related to the block.
     * @param _evidenceItemId The ID of the evidence item being added.
     * @param _state The state of the evidence item.
     * @param _handlerName The name of the handler performing the action.
     * @param _organizationName The name of the organization.
     * @param _data Additional data related to the evidence.
     */
    function addBlock(
        uint128 _caseId,
        uint32 _evidenceItemId,
        bytes12 _state,
        bytes20 _handlerName,
        bytes20 _organizationName,
        bytes memory _data
    ) private {
        bytes32 previousHash = blockchain.length > 0 ? getLatestBlockHash() : bytes32(0);
        uint64 timestamp = uint64(block.timestamp);
        uint32 dataLength = uint32(_data.length);

        Block memory newBlock = Block(
            previousHash,
            timestamp,
            _caseId,
            _evidenceItemId,
            _state,
            _handlerName,
            _organizationName,
            dataLength,
            _data
        );

        blockchain.push(newBlock);
        evidenceExists[_evidenceItemId] = true;

        // Emitting the event
        emit EvidenceItemAdded(_caseId, _evidenceItemId, timestamp, _state);
    }

    /**
     * @dev Function to retrieve the latest block hash for linking purposes.
     * @return The hash of the latest block in the blockchain.
     */
    function getLatestBlockHash() private view returns (bytes32) {
        Block storage lastBlock = blockchain[blockchain.length - 1];
        return keccak256(
            abi.encodePacked(
                lastBlock.previousHash,
                lastBlock.timestamp,
                lastBlock.caseId,
                lastBlock.evidenceItemId,
                lastBlock.state,
                lastBlock.handlerName,
                lastBlock.organizationName,
                lastBlock.dataLength,
                lastBlock.data
            )
        );
    }

    // TODO: Implement checkout, checkin, remove, show cases, and show history functions
}
