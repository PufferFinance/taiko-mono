// SPDX-License-Identifier: MIT
//
// ╭━━━━╮╱╱╭╮╱╱╱╱╱╭╮╱╱╱╱╱╭╮
// ┃╭╮╭╮┃╱╱┃┃╱╱╱╱╱┃┃╱╱╱╱╱┃┃
// ╰╯┃┃┣┻━┳┫┃╭┳━━╮┃┃╱╱╭━━┫╰━┳━━╮
// ╱╱┃┃┃╭╮┣┫╰╯┫╭╮┃┃┃╱╭┫╭╮┃╭╮┃━━┫
// ╱╱┃┃┃╭╮┃┃╭╮┫╰╯┃┃╰━╯┃╭╮┃╰╯┣━━┃
// ╱╱╰╯╰╯╰┻┻╯╰┻━━╯╰━━━┻╯╰┻━━┻━━╯
pragma solidity ^0.8.9;

import "../thirdparty/LibRLPReader.sol";
import "../thirdparty/LibRLPWriter.sol";
import "../thirdparty/LibSecureMerkleTrie.sol";

/**
 * @title LibTrieProof
 * @author dantaik <dan@taiko.xyz>
 */
library LibTrieProof {
    /*********************
     * Constants         *
     *********************/

    // The consensus format representing account is RLP encoded in the
    // following order: nonce, balance, storageHash, codeHash.
    uint256 private constant ACCOUNT_FIELD_INDEX_STORAGE_HASH = 2;

    /*********************
     * Public Functions  *
     *********************/

    /**
     * Verifies that the value of a slot `key` in the storage tree of `addr`
     * is `value`.
     *
     * @param stateRoot The merkle root of state tree.
     * @param addr The contract address.
     * @param key The slot in the contract.
     * @param value The value to be verified.
     * @param mkproof The proof obtained by encoding state proof and storage
     *        proof.
     */
    function verify(
        bytes32 stateRoot,
        address addr,
        bytes32 key,
        bytes32 value,
        bytes calldata mkproof
    ) public pure {
        (bytes memory accountProof, bytes memory storageProof) = abi.decode(
            mkproof,
            (bytes, bytes)
        );

        (bool exists, bytes memory rlpAccount) = LibSecureMerkleTrie.get(
            abi.encodePacked(addr),
            accountProof,
            stateRoot
        );

        require(exists, "LTP:invalid account proof");

        LibRLPReader.RLPItem[] memory accountState = LibRLPReader.readList(
            rlpAccount
        );
        bytes32 storageRoot = LibRLPReader.readBytes32(
            accountState[ACCOUNT_FIELD_INDEX_STORAGE_HASH]
        );

        bool verified = LibSecureMerkleTrie.verifyInclusionProof(
            abi.encodePacked(key),
            LibRLPWriter.writeBytes32(value),
            storageProof,
            storageRoot
        );

        require(verified, "LTP:invalid storage proof");
    }
}
