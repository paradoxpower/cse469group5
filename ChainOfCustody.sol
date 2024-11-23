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

    // Mappings to track evidence items
    mapping(uint32 => bool) public evidenceExists;
    mapping(uint32 => bool) public evidenceRemoved;
    mapping(uint32 => bytes12) public itemCurrentState;
    mapping(uint32 => bytes16) public itemCaseId;

    // Event declarations for logging actions
    event EvidenceItemAdded(bytes16 indexed caseId, uint32 indexed evidenceItemId, uint64 timestamp, bytes12 state);
    event EvidenceItemCheckedOut(bytes16 indexed caseId, uint32 indexed evidenceItemId, uint64 timestamp, bytes12 state);
    event EvidenceItemCheckedIn(bytes16 indexed caseId, uint32 indexed evidenceItemId, uint64 timestamp, bytes12 state);
    event EvidenceItemRemoved(
        bytes16 indexed caseId,
        uint32 indexed evidenceItemId,
        uint64 timestamp,
        bytes12 state,
        string reason,
        string owner
    );

    // Constructor to initialize the blockchain with the initial block
    constructor() {
        uint64 timestamp = uint64(block.timestamp);
        Block memory initialBlock = Block(
            bytes32(0),
            timestamp,
            bytes16(0),
            0,
            "INITIAL",
            bytes20(0),
            bytes20(0),
            14,
            bytes("Initial block")
        );
        blockchain.push(initialBlock);
    }

    // Function to add new evidence items to a case
    function addEvidenceItems(
        bytes16 _caseId,
        uint32[] memory _itemIds,
        bytes20 _handlerName,
        bytes20 _organizationName
    ) public {
        require(_itemIds.length > 0, "Error: No item IDs provided.");
        for (uint256 i = 0; i < _itemIds.length; i++) {
            uint32 itemId = _itemIds[i];
            require(!evidenceExists[itemId], "Error: Evidence item ID must be unique and not already used.");
            addBlock(
                _caseId,
                itemId,
                "CHECKEDIN",
                _handlerName,
                _organizationName,
                "",
                ""
            );
            evidenceExists[itemId] = true;
            itemCurrentState[itemId] = "CHECKEDIN";
            itemCaseId[itemId] = _caseId;

            emit EvidenceItemAdded(_caseId, itemId, uint64(block.timestamp), "CHECKEDIN");
        }
    }

    // Function to check out an evidence item
    function checkoutEvidenceItem(
        uint32 _evidenceItemId,
        bytes20 _handlerName,
        bytes20 _organizationName
    ) public {
        require(evidenceExists[_evidenceItemId], "Error: Evidence item does not exist.");
        require(!evidenceRemoved[_evidenceItemId], "Error: Item has been removed.");
        require(
            keccak256(abi.encodePacked(itemCurrentState[_evidenceItemId])) ==
                keccak256(abi.encodePacked("CHECKEDIN")),
            "Error: Item must be checked in to be checked out."
        );

        bytes16 caseId = itemCaseId[_evidenceItemId];
        addBlock(
            caseId,
            _evidenceItemId,
            "CHECKEDOUT",
            _handlerName,
            _organizationName,
            "",
            ""
        );
        itemCurrentState[_evidenceItemId] = "CHECKEDOUT";

        emit EvidenceItemCheckedOut(caseId, _evidenceItemId, uint64(block.timestamp), "CHECKEDOUT");
    }

    // Function to check in an evidence item
    function checkinEvidenceItem(
        uint32 _evidenceItemId,
        bytes20 _handlerName,
        bytes20 _organizationName
    ) public {
        require(evidenceExists[_evidenceItemId], "Error: Evidence item does not exist.");
        require(!evidenceRemoved[_evidenceItemId], "Error: Item has been removed.");
        require(
            keccak256(abi.encodePacked(itemCurrentState[_evidenceItemId])) ==
                keccak256(abi.encodePacked("CHECKEDOUT")),
            "Error: Item must be checked out to be checked in."
        );

        bytes16 caseId = itemCaseId[_evidenceItemId];
        addBlock(
            caseId,
            _evidenceItemId,
            "CHECKEDIN",
            _handlerName,
            _organizationName,
            "",
            ""
        );
        itemCurrentState[_evidenceItemId] = "CHECKEDIN";

        emit EvidenceItemCheckedIn(caseId, _evidenceItemId, uint64(block.timestamp), "CHECKEDIN");
    }

    // Function to remove an evidence item
    function removeEvidenceItem(
        uint32 _evidenceItemId,
        string memory _reason,
        string memory _owner
    ) public {
        require(evidenceExists[_evidenceItemId], "Error: Evidence item does not exist.");
        require(!evidenceRemoved[_evidenceItemId], "Error: Item has already been removed.");
        require(
            keccak256(abi.encodePacked(itemCurrentState[_evidenceItemId])) ==
                keccak256(abi.encodePacked("CHECKEDIN")),
            "Error: Item must be checked in to be removed."
        );

        require(
            keccak256(abi.encodePacked(_reason)) == keccak256(abi.encodePacked("DISPOSED")) ||
                keccak256(abi.encodePacked(_reason)) == keccak256(abi.encodePacked("DESTROYED")) ||
                keccak256(abi.encodePacked(_reason)) == keccak256(abi.encodePacked("RELEASED")),
            "Error: Invalid removal reason."
        );

        if (keccak256(abi.encodePacked(_reason)) == keccak256(abi.encodePacked("RELEASED"))) {
            require(bytes(_owner).length > 0, "Error: Owner info must be provided when reason is RELEASED.");
        }

        bytes16 caseId = itemCaseId[_evidenceItemId];
        addBlock(
            caseId,
            _evidenceItemId,
            bytes12(bytes(_reason)),
            bytes20(0),
            bytes20(0),
            _reason,
            bytes(_owner)
        );

        itemCurrentState[_evidenceItemId] = bytes12(bytes(_reason));
        evidenceRemoved[_evidenceItemId] = true;

        emit EvidenceItemRemoved(caseId, _evidenceItemId, uint64(block.timestamp), bytes12(bytes(_reason)), _reason, _owner);
    }

    // Private function to add a new block to the blockchain
    function addBlock(
        bytes16 _caseId,
        uint32 _evidenceItemId,
        bytes12 _state,
        bytes20 _handlerName,
        bytes20 _organizationName,
        string memory _reason,
        bytes memory _data
    ) private {
        bytes32 previousHash = getLatestBlockHash();
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
    }

    // Function to get the latest block hash
    function getLatestBlockHash() private view returns (bytes32) {
        Block storage lastBlock = blockchain[blockchain.length - 1];
        return calculateBlockHash(lastBlock);
    }

    // Helper function to calculate block hash
    function calculateBlockHash(Block storage _block) private view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    _block.previousHash,
                    _block.timestamp,
                    _block.caseId,
                    _block.evidenceItemId,
                    _block.state,
                    _block.handlerName,
                    _block.organizationName,
                    _block.dataLength,
                    _block.data
                )
            );
    }

    // Corrected verifyBlockchain function
    function verifyBlockchain() public view returns (string memory) {
        if (blockchain.length == 0) {
            return "ERROR: Blockchain is empty.";
        }

        // Arrays to simulate mappings for item states and removal status
        uint32[] memory itemIds = new uint32[](blockchain.length);
        bytes12[] memory itemStates = new bytes12[](blockchain.length);
        bool[] memory evidenceRemovedArray = new bool[](blockchain.length);
        uint256 itemCount = 0;

        for (uint256 i = 1; i < blockchain.length; i++) {
            Block storage currentBlock = blockchain[i];
            Block storage previousBlock = blockchain[i - 1];

            // Verify the previous hash
            if (currentBlock.previousHash != calculateBlockHash(previousBlock)) {
                return "ERROR: Blockchain integrity compromised at block ";
            }

            uint32 itemId = currentBlock.evidenceItemId;
            bytes12 state = currentBlock.state;

            // Find the index of the itemId in the itemIds array
            uint256 index = 0;
            bool itemExists = false;
            for (uint256 j = 0; j < itemCount; j++) {
                if (itemIds[j] == itemId) {
                    index = j;
                    itemExists = true;
                    break;
                }
            }

            if (!itemExists) {
                // New itemId, add it to the arrays
                itemIds[itemCount] = itemId;
                itemStates[itemCount] = ""; // Initialize with empty state
                evidenceRemovedArray[itemCount] = false;
                index = itemCount;
                itemCount++;
            }

            // State transition validation
            if (keccak256(abi.encodePacked(state)) == keccak256(abi.encodePacked("CHECKEDIN"))) {
                if (
                    itemStates[index] != bytes12(0) &&
 
                    keccak256(abi.encodePacked(itemStates[index])) != keccak256(abi.encodePacked("CHECKEDOUT"))
                ) {
                    return "ERROR: Invalid CHECKEDIN state transition.";
                }
                itemStates[index] = "CHECKEDIN";
            } else if (keccak256(abi.encodePacked(state)) == keccak256(abi.encodePacked("CHECKEDOUT"))) {
                if (
                    evidenceRemovedArray[index] ||
                    keccak256(abi.encodePacked(itemStates[index])) != keccak256(abi.encodePacked("CHECKEDIN"))
                ) {
                    return "ERROR: Invalid CHECKEDOUT state transition.";
                }
                itemStates[index] = "CHECKEDOUT";
            } else if (
                keccak256(abi.encodePacked(state)) == keccak256(abi.encodePacked("DISPOSED")) ||
                keccak256(abi.encodePacked(state)) == keccak256(abi.encodePacked("DESTROYED")) ||
                keccak256(abi.encodePacked(state)) == keccak256(abi.encodePacked("RELEASED"))
            ) {
                if (
                    evidenceRemovedArray[index] ||
                    keccak256(abi.encodePacked(itemStates[index])) != keccak256(abi.encodePacked("CHECKEDIN"))
                ) {
                    return "ERROR: Invalid removal state transition.";
                }
                itemStates[index] = state;
                evidenceRemovedArray[index] = true;
            } else if (keccak256(abi.encodePacked(state)) == keccak256(abi.encodePacked("INITIAL"))) {
                // Skip validation for the initial block
                continue;
            } else {
                return "ERROR: Invalid state detected.";
            }
        }
        return "CLEAN: Blockchain is valid.";
    }

    // Function to get all cases in the blockchain
    function getCases() public view returns (bytes16[] memory) {
        bytes16[] memory casesTemp = new bytes16[](blockchain.length);
        uint256 count = 0;

        for (uint256 i = 0; i < blockchain.length; i++) {
            bytes16 caseId = blockchain[i].caseId;
            bool exists = false;
            for (uint256 j = 0; j < count; j++) {
                if (casesTemp[j] == caseId) {
                    exists = true;
                    break;
                }
            }
            if (!exists && caseId != bytes16(0)) {
                casesTemp[count] = caseId;
                count++;
            }
        }

        bytes16[] memory uniqueCases = new bytes16[](count);
        for (uint256 i = 0; i < count; i++) {
            uniqueCases[i] = casesTemp[i];
        }

        return uniqueCases;
    }

    // Function to get items for a specific case
    function getItemsForCase(bytes16 _caseId) public view returns (uint32[] memory) {
        uint32[] memory itemsTemp = new uint32[](blockchain.length);
        uint256 count = 0;

        for (uint256 i = 0; i < blockchain.length; i++) {
            if (blockchain[i].caseId == _caseId) {
                uint32 itemId = blockchain[i].evidenceItemId;
                bool exists = false;
                for (uint256 j = 0; j < count; j++) {
                    if (itemsTemp[j] == itemId) {
                        exists = true;
                        break;
                    }
                }
                if (!exists && itemId != 0) {
                    itemsTemp[count] = itemId;
                    count++;
                }
            }
        }

        uint32[] memory uniqueItems = new uint32[](count);
        for (uint256 i = 0; i < count; i++) {
            uniqueItems[i] = itemsTemp[i];
        }

        return uniqueItems;
    }

    // Function to get history of an evidence item
    function getItemHistory(
        uint32 _itemId,
        uint256 _n,
        bool _reverse
    ) public view returns (Block[] memory) {
        uint256 totalEntries = 0;
        for (uint256 i = 0; i < blockchain.length; i++) {
            if (blockchain[i].evidenceItemId == _itemId) {
                totalEntries++;
            }
        }

        uint256 limit = (_n > 0 && _n < totalEntries) ? _n : totalEntries;
        Block[] memory history = new Block[](limit);
        uint256 index = 0;

        if (_reverse) {
            // Most recent entries first
            for (uint256 i = blockchain.length; i > 0 && index < limit; i--) {
                if (blockchain[i - 1].evidenceItemId == _itemId) {
                    history[index] = blockchain[i - 1];
                    index++;
                }
            }
        } else {
            // Oldest entries first
            for (uint256 i = 0; i < blockchain.length && index < limit; i++) {
                if (blockchain[i].evidenceItemId == _itemId) {
                    history[index] = blockchain[i];
                    index++;
                }
            }
        }

        return history;
    }
}
