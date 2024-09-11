// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./IBaseDepositContract.sol";

/// @title BaseDepositContract
/// Based on https://github.com/ethereum/consensus-specs/blob/dev/solidity_deposit_contract/deposit_contract.sol
abstract contract BaseDepositContract is IBaseDepositContract {
    // Merkle tree levels
    uint256 internal constant DEPOSIT_CONTRACT_TREE_DEPTH = 32;
    // This ensures `depositCount` will fit into 32-bits
    uint256 internal constant MAX_DEPOSIT_COUNT =
        2 ** DEPOSIT_CONTRACT_TREE_DEPTH - 1;

    // Contains the necessary sibilings to compute the next root when a new leaf is inserted
    bytes32[DEPOSIT_CONTRACT_TREE_DEPTH] internal branch;
    // Counter of current deposits
    uint256 public depositCount;

    uint256[10] private _gap;

    error MerkleTreeFull();

    /// @notice Returns the roof of the merkle tree.
    function getRoot() public view virtual returns (bytes32) {
        bytes32 node;
        uint256 size = depositCount;
        bytes32 currentZeroHashHeight = 0;

        for (
            uint256 height = 0;
            height < DEPOSIT_CONTRACT_TREE_DEPTH;
            height++
        ) {
            if (((size >> height) & 1) == 1)
                node = keccak256(abi.encodePacked(branch[height], node));
            else
                node = keccak256(abi.encodePacked(node, currentZeroHashHeight));

            currentZeroHashHeight = keccak256(
                abi.encodePacked(currentZeroHashHeight, currentZeroHashHeight)
            );
        }
        return node;
    }


    /// @notice Adds a new leaf to the merkle tree.
    function _addLeaf(bytes32 leaf) internal {
        bytes32 node = leaf;

        // Avoid overflowing the Merkle tree (and prevent edge case in computing `branch`)
        if (depositCount >= MAX_DEPOSIT_COUNT) {
            revert MerkleTreeFull();
        }

        // Add deposit data root to Merkle tree (update a single `branch` node)
        uint256 size = ++depositCount;
        for (
            uint256 height = 0;
            height < DEPOSIT_CONTRACT_TREE_DEPTH;
            height++
        ) {
            if (((size >> height) & 1) == 1) {
                branch[height] = node;
                return;
            }
            node = keccak256(abi.encodePacked(branch[height], node));
        }
        // As the loop should always end prematurely with the `return` statement,
        // this code should be unreachable. We assert `false` just to be safe.
        assert(false);
    }

    /// @notice Verifies the merkle proof against a given root.
    function verifyMerkleProof(
        bytes32 leafHash,
        bytes32[DEPOSIT_CONTRACT_TREE_DEPTH] memory smtProof,
        uint32 index,
        bytes32 root
    ) public pure returns (bool) {
        return calculateRoot(leafHash, smtProof, index) == root;
    }

    /// @notice Calculates the merkle root from a given proof.
    function calculateRoot(
        bytes32 leafHash,
        bytes32[DEPOSIT_CONTRACT_TREE_DEPTH] memory smtProof,
        uint32 index
    ) public pure returns (bytes32) {
        bytes32 node = leafHash;

        // Compute root
        for (
            uint256 height = 0;
            height < DEPOSIT_CONTRACT_TREE_DEPTH;
            height++
        ) {
            if (((index >> height) & 1) == 1)
                node = keccak256(abi.encodePacked(smtProof[height], node));
            else node = keccak256(abi.encodePacked(node, smtProof[height]));
        }

        return node;
    }
}
